package rbac

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// BackingObjectPermissions are the sign-in-relevant changes to a directory object that TM-D19 rule 5
// and DM-30.I7 guard: a password reset, an unlock, enabling the object, a change of its UPN or
// sAMAccountName, and a move. An Action that performs one of these changes MUST declare one of these
// permissions in its Descriptor; the guard keys on the permission. Disabling is not listed: it removes
// sign-in rather than granting it.
var BackingObjectPermissions = []authz.Permission{
	"objects.user.reset_password",
	"objects.user.unlock",
	"objects.user.enable",
	"objects.user.rename_logon", // UPN or sAMAccountName
	"objects.user.move",
}

// Reasons of the backing-object guard (TM-D19 rule 5).
const (
	ReasonBackingObject     authz.Reason = "backing_object_escalation"
	ReasonBackingIncomplete authz.Reason = "backing_facts_incomplete"
	ReasonBackingNoResolver authz.Reason = "backing_resolver_missing"
)

// BackedAccounts is the set of console accounts an object backs.
type BackedAccounts struct {
	// Accounts are the IDs of the console accounts backed by the object: the account whose
	// directory object it is, the account an sso account is bound to it by oid or onprem_sid, and the
	// accounts backed by any object with a DM-20 correlation to it, in any state but removed.
	Accounts []string
	// Complete is true only when every source was read in full. An incomplete answer refuses.
	Complete bool
}

// Backing answers which console accounts an object backs (DM-30.I7). Implementations read
// committed state for the tenant and expand correlations in both directions.
type Backing interface {
	BackedBy(ctx context.Context, t tenant.ID, target authority.TargetRef) (BackedAccounts, error)
}

// RootResolver reads, live, the ancestor chain of a scope root so containment can be decided
// (authz.ScopeRoot). It never trusts stored or request-supplied ancestors.
type RootResolver interface {
	Resolve(ctx context.Context, t tenant.ID, r Root) (authz.ScopeRoot, error)
}

// Option configures an Authorizer.
type Option func(*Authorizer)

// WithBackingGuard enables rule 5. Without it, every permission in BackingObjectPermissions is
// refused (fail closed): the guard cannot be skipped by leaving it unwired.
func WithBackingGuard(b Backing, r RootResolver) Option {
	return func(a *Authorizer) { a.backing, a.roots = b, r }
}

func isBackingPermission(p authz.Permission) bool {
	return slices.Contains(BackingObjectPermissions, p)
}

// checkBacking refuses a sign-in-relevant change to a console-backing object unless the actor holds
// every privilege each backed account holds, over every scope it holds it (the DM-36.I1 test).
func (a *Authorizer) checkBacking(ctx context.Context, tn tenant.ID, actor []Assignment, who string, t authority.TargetRef) error {
	if a.backing == nil {
		return denied(ReasonBackingNoResolver)
	}
	b, err := a.backing.BackedBy(ctx, tn, t)
	if err != nil {
		return fmt.Errorf("rbac: resolving backed accounts: %w", err)
	}
	if !b.Complete {
		return denied(ReasonBackingIncomplete)
	}
	for _, acct := range b.Accounts {
		if acct == who {
			continue // holds exactly its own privileges
		}
		theirs, err := a.effective(ctx, tn, acct, true)
		if err != nil {
			return fmt.Errorf("rbac: loading backed account assignments: %w", err)
		}
		for _, as := range theirs {
			if len(as.Permissions) == 0 {
				continue
			}
			if len(as.Roots) == 0 {
				// Permissions with no roots: what it reaches is undefined (a tenant- or
				// platform-wide grant could be represented this way). Fail closed.
				return denied(ReasonBackingIncomplete)
			}
			switch err := a.holdsOver(ctx, tn, actor, who, as.Permissions, as.Roots); {
			case err == nil:
			case errors.Is(err, authz.ErrEscalation):
				return denied(ReasonBackingObject)
			default:
				return denied(ReasonBackingIncomplete) // invalid, incomplete or dead owner: fail closed
			}
		}
	}
	return nil
}

// holdsOver is the DM-36.I1 test: the actor, whose effective assignments are actor, holds every
// permission in perms over every scope in roots (one scope per connection and root family). nil
// means yes, authz.ErrEscalation means no, any other error means the proof could not be made and the
// caller fails closed. Roots are resolved live. Correlation-derived assignments never count.
func (a *Authorizer) holdsOver(ctx context.Context, tn tenant.ID, actor []Assignment, who string, perms []authz.Permission, roots []Root) error {
	scopes, err := a.scopesOf(ctx, tn, Assignment{Roots: roots})
	if err != nil {
		return fmt.Errorf("rbac: resolving scope: %w", err)
	}
	// An exclude-only scope reaches nothing, so there is nothing to hold. A grant refuses it earlier.
	for _, sc := range scopes {
		// Only the actor's roots of the same connection and family can contain this scope: an
		// entra_tenant root whose GUID equals a connection never covers its Tier-0 scope.
		grantor, err := a.principalFor(ctx, tn, who, actor, sc.conn, sc.class)
		if err != nil {
			return fmt.Errorf("rbac: resolving grantor scope: %w", err)
		}
		if len(grantor.Assignments) == 0 {
			return authz.ErrEscalation // holds nothing there
		}
		if err := a.eval.CheckGrant(grantor, nil, authz.Role{Permissions: perms}, sc.Scope); err != nil {
			return err
		}
	}
	return nil
}

// principalFor builds the actor's evaluator view for one connection and root kind.
func (a *Authorizer) principalFor(ctx context.Context, tn tenant.ID, who string, as []Assignment, conn, class string) (*authz.Principal, error) {
	p := &authz.Principal{ID: who}
	for _, x := range as {
		if x.Via != nil {
			continue // a correlation-derived grant never backs a grant (TM-D17 rule 5)
		}
		var s authz.Scope
		for _, r := range x.Roots {
			if r.Connection != conn || rootClass(r) != class {
				continue
			}
			// Resolved live like the backed side: an exclusion is compared by ancestry, so a
			// root without its chain would let an exclusion inside the console's scope go unseen.
			sr, err := a.resolve(ctx, tn, r)
			if err != nil {
				return nil, err
			}
			if r.Exclude {
				s.Exclude = append(s.Exclude, sr)
			} else {
				s.Include = append(s.Include, sr)
			}
		}
		if len(s.Include)+len(s.Exclude) > 0 {
			p.Assignments = append(p.Assignments, authz.Assignment{Role: authz.Role{Permissions: x.Permissions}, Scope: s})
		}
	}
	return p, nil
}

// splitScopes groups roots by (connection, tier0-or-not) so each group is one scope: an assignment
// spanning two connections is held per connection, and a Tier-0 scope root is never mixed with object
// roots.
func splitScopes(roots []Root) [][]Root {
	type key struct{ conn, class string }
	idx := map[key]int{}
	var out [][]Root
	for _, r := range roots {
		k := key{r.Connection, rootClass(r)}
		i, ok := idx[k]
		if !ok {
			i = len(out)
			idx[k] = i
			out = append(out, nil)
		}
		out[i] = append(out[i], r)
	}
	return out
}

type keyedScope struct {
	authz.Scope
	conn, class string
}

// rootClass separates the root families that never cover each other: a connection's Tier-0 scope,
// the tenant's own store, and directory objects.
func rootClass(r Root) string {
	switch r.Kind {
	case Tier0Scope:
		return "tier0_scope"
	case TenantStore:
		return "tenant_store"
	default:
		return "directory"
	}
}

// scopesOf returns the backed account's assignment as live-resolved scopes, one per connection.
func (a *Authorizer) scopesOf(ctx context.Context, tn tenant.ID, as Assignment) ([]keyedScope, error) {
	var out []keyedScope
	for _, rs := range splitScopes(as.Roots) {
		var s authz.Scope
		for _, r := range rs {
			sr, err := a.resolve(ctx, tn, r)
			if err != nil {
				return nil, err
			}
			if r.Exclude {
				s.Exclude = append(s.Exclude, sr)
			} else {
				s.Include = append(s.Include, sr)
			}
		}
		if len(s.Include) == 0 {
			continue // an exclude-only scope reaches nothing
		}
		out = append(out, keyedScope{Scope: s, conn: rs[0].Connection, class: rootClass(rs[0])})
	}
	return out, nil
}

func (a *Authorizer) resolve(ctx context.Context, tn tenant.ID, r Root) (authz.ScopeRoot, error) {
	id, err := authz.ParseObjectID(r.GUID)
	if err != nil {
		return authz.ScopeRoot{}, err
	}
	if r.Kind == Tier0Scope || r.Kind == TenantStore {
		return authz.ScopeRoot{ID: id, Complete: true}, nil // a connection or the tenant: no ancestors
	}
	if a.roots == nil {
		return authz.ScopeRoot{}, errors.New("rbac: no root resolver")
	}
	if r.Kind == OUOneLevel && r.Exclude {
		return authz.ScopeRoot{}, errors.New("rbac: ou_one_level is an include root only")
	}
	sr, err := a.roots.Resolve(ctx, tn, r)
	if err != nil {
		return authz.ScopeRoot{}, err
	}
	if sr.ID != id {
		return authz.ScopeRoot{}, errors.New("rbac: resolver returned another root")
	}
	// Set here, not by the resolver, so no resolver can return a one-level root as a subtree.
	sr.OneLevel = r.Kind == OUOneLevel
	return sr, nil
}

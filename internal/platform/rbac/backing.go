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
		theirs, err := a.src.PendingOrActive(ctx, tn, acct, a.now())
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
			scopes, err := a.scopesOf(ctx, tn, as)
			if err != nil {
				return denied(ReasonBackingIncomplete)
			}
			for _, sc := range scopes {
				// Only the actor's roots of the same connection and kind can contain this scope: an
				// entra_tenant root whose GUID equals a connection never covers its Tier-0 scope.
				grantor, err := a.principalFor(ctx, tn, who, actor, sc.conn, sc.t0)
				if err != nil {
					return denied(ReasonBackingIncomplete)
				}
				if len(grantor.Assignments) == 0 {
					return denied(ReasonBackingObject) // holds nothing there
				}
				err = a.eval.CheckGrant(grantor, nil, authz.Role{Permissions: as.Permissions}, sc.Scope)
				if err == nil {
					continue
				}
				if errors.Is(err, authz.ErrEscalation) {
					return denied(ReasonBackingObject)
				}
				return denied(ReasonBackingIncomplete) // invalid, incomplete or dead owner: fail closed
			}
		}
	}
	return nil
}

// principalFor builds the actor's evaluator view for one connection and root kind.
func (a *Authorizer) principalFor(ctx context.Context, tn tenant.ID, who string, as []Assignment, conn string, t0 bool) (*authz.Principal, error) {
	p := &authz.Principal{ID: who}
	for _, x := range as {
		var s authz.Scope
		for _, r := range x.Roots {
			if r.Connection != conn || (r.Kind == Tier0Scope) != t0 {
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
	type key struct {
		conn string
		t0   bool
	}
	idx := map[key]int{}
	var out [][]Root
	for _, r := range roots {
		k := key{r.Connection, r.Kind == Tier0Scope}
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
	conn string
	t0   bool
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
		out = append(out, keyedScope{Scope: s, conn: rs[0].Connection, t0: rs[0].Kind == Tier0Scope})
	}
	return out, nil
}

func (a *Authorizer) resolve(ctx context.Context, tn tenant.ID, r Root) (authz.ScopeRoot, error) {
	id, err := authz.ParseObjectID(r.GUID)
	if err != nil {
		return authz.ScopeRoot{}, err
	}
	if r.Kind == Tier0Scope {
		return authz.ScopeRoot{ID: id, Complete: true}, nil // a connection: no ancestors
	}
	if a.roots == nil {
		return authz.ScopeRoot{}, errors.New("rbac: no root resolver")
	}
	sr, err := a.roots.Resolve(ctx, tn, r)
	if err != nil {
		return authz.ScopeRoot{}, err
	}
	if sr.ID != id {
		return authz.ScopeRoot{}, errors.New("rbac: resolver returned another root")
	}
	return sr, nil
}

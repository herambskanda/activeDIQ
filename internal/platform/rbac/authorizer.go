package rbac

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// TargetClassTier0Scope is the class of a target that names a connection's Tier-0 scope. Its GUID is
// the connection ID. It matches the inventory module's TargetClassScope (asserted in compose/server).
const TargetClassTier0Scope = "tier0_scope"

// Classes of activeDIQ's own store rows that rbac authorises (Connection is empty). Only these are
// store targets: a directory-class target with no connection is malformed and denied.
const (
	TargetClassRole       = "role"
	TargetClassAssignment = "assignment"
	// TargetClassTenant is the tenant store root itself (GUID is the tenant ID). Only a tenant-wide
	// root covers it: it is the target of an operation scoped to the whole tenant.
	TargetClassTenant = "tenant"
)

// storeClasses are the target classes authorised as rows of activeDIQ's own store.
var storeClasses = []string{TargetClassRole, TargetClassAssignment, TargetClassTenant, "settings"}

func isStoreClass(c string) bool { return slices.Contains(storeClasses, c) }

// ErrDenied is wrapped by every refusal. The reason is a stable authz.Reason or an rbac reason; it
// carries no grant detail.
var ErrDenied = errors.New("rbac: denied")

// Reasons rbac adds to authz's.
const (
	ReasonUnsupportedChain authz.Reason = "chain_not_a_direct_human"
	ReasonNoTenant         authz.Reason = "no_tenant"
	ReasonScopeOnly        authz.Reason = "tier0_scope_permission_off_scope"
	ReasonBadTarget        authz.Reason = "target_not_a_guid"
	ReasonTokenUnusable    authz.Reason = "token_unusable"
	ReasonNoTokenSource    authz.Reason = "token_source_missing"
	ReasonAutomationDenied authz.Reason = "automation_policy_not_granted"
)

func denied(r authz.Reason) error { return fmt.Errorf("%w: %s", ErrDenied, r) }

// Authorizer implements operation.Authorizer over authz.Evaluator.
type Authorizer struct {
	src     Source
	eval    authz.Evaluator
	now     func() time.Time
	backing Backing          // TM-D19 rule 5; nil refuses every backing-object permission
	roots   RootResolver     // live scope-root ancestry for the rule 5 containment test
	members authz.Membership // DM-36.I2; nil: group subjects grant nothing
	tokens  TokenSource      // DM-32; nil: a chain through an API token is refused
	reach   GroupReach       // TM-D18 membership guard; nil refuses every group-membership permission
}

// TokenSource reads an API token's constraint (DM-32): its permission subset, mandatory expiry and
// scope narrowing. It returns an error unless the token is active and owned by owner; a disabled or
// lost owner is the evaluator's to refuse. authn implements it over its token store.
type TokenSource interface {
	Constraint(ctx context.Context, t tenant.ID, tokenID, owner string) (authz.Token, error)
}

// WithMembership enables group subjects (DM-36.I2). Without it a group assignment grants nothing.
func WithMembership(m authz.Membership) Option { return func(a *Authorizer) { a.members = m } }

// WithTokens enables API tokens in the initiator chain. Without it such a chain is refused.
func WithTokens(ts TokenSource) Option { return func(a *Authorizer) { a.tokens = ts } }

// New returns an Authorizer reading assignments from src.
func New(src Source, opts ...Option) (*Authorizer, error) {
	if src == nil {
		return nil, errors.New("rbac: no assignment source")
	}
	a := &Authorizer{src: src, now: time.Now}
	for _, o := range opts {
		o(a)
	}
	return a, nil
}

// FactsQuery asks for the Tier-0 fact and the live parent chain of a directory target. A tier0_scope
// target is a scope, not a directory object: nothing is read about it.
func (a *Authorizer) FactsQuery(_ authority.Chain, _ authz.Permission, t authority.TargetRef) authority.FactsQuery {
	if t.Class == TargetClassTier0Scope || isStoreClass(t.Class) { // a scope or a store row: nothing to read
		return authority.FactsQuery{Target: t}
	}
	return authority.FactsQuery{Target: t, Tier0: true, Ancestry: true}
}

// Authorize decides whether the chain's requester may exercise perm on t, given the facts read live.
func (a *Authorizer) Authorize(ctx context.Context, chain authority.Chain, perm authz.Permission, t authority.TargetRef, f authority.Facts) error {
	tid, ok := authority.TenantFrom(ctx)
	if !ok {
		return denied(ReasonNoTenant)
	}
	tn, err := tenant.Parse(tid)
	if err != nil {
		return denied(ReasonNoTenant)
	}
	// The requester is a person. Whatever acted for them narrows their authority and never widens it
	// (ADR-0005 rule 7): an API token intersects it, an automation policy must be granted the same
	// permission as its own subject (DM-60.I2).
	if chain.Validate() != nil || chain.Requester.Kind != authority.Human {
		return denied(ReasonUnsupportedChain)
	}
	var tokenID, policy string
	for _, v := range chain.Via {
		switch {
		case v.Kind == authority.APIToken && tokenID == "":
			tokenID = string(v.ID)
		case v.Kind == authority.Automation && policy == "":
			policy = string(v.ID)
		default:
			return denied(ReasonUnsupportedChain)
		}
	}
	var tok *authz.Token
	if tokenID != "" {
		if a.tokens == nil {
			return denied(ReasonNoTokenSource)
		}
		c, err := a.tokens.Constraint(ctx, tn, tokenID, string(chain.Requester.ID))
		if err != nil {
			return denied(ReasonTokenUnusable)
		}
		tok = &c
	}
	scope := t.Class == TargetClassTier0Scope
	if !scope && isTier0Scope(perm) {
		return denied(ReasonScopeOnly)
	}
	as, err := a.effective(ctx, tn, string(chain.Requester.ID), false)
	if err != nil {
		return err
	}
	tgt, ev, err := a.view(tn, as, t, f)
	if err != nil {
		return err
	}
	p := &authz.Principal{ID: string(chain.Requester.ID), Assignments: ev, AuthorityFactor: authority.AuthorityFactorFrom(ctx)}
	if d := a.eval.Authorize(p, tok, perm, tgt); !d.Allowed {
		return denied(d.Reason)
	}
	if policy != "" {
		pas, err := a.automation(ctx, tn, policy)
		if err != nil {
			return err
		}
		_, pev, err := a.view(tn, pas, t, f)
		if err != nil {
			return err
		}
		if d := a.eval.Authorize(&authz.Principal{ID: policy, Assignments: pev}, nil, perm, tgt); !d.Allowed {
			return denied(ReasonAutomationDenied)
		}
	}
	if !scope && isBackingPermission(perm) {
		// TM-D19 rule 5: a console-backing object is an escalation object.
		return a.checkBacking(ctx, tn, as, string(chain.Requester.ID), t)
	}
	if !scope && isGroupMembershipPermission(perm) {
		// DM-36.I1 / TM-D18: changing who a role-granting group reaches is an indirect grant.
		return a.checkGroupMembership(ctx, tn, as, string(chain.Requester.ID), t)
	}
	return nil
}

// view builds the evaluator's view of target t from assignments as: a Tier-0 scope, a store target
// (no connection), or a directory object.
func (a *Authorizer) view(tn tenant.ID, as []Assignment, t authority.TargetRef, f authority.Facts) (authz.Target, []authz.Assignment, error) {
	switch {
	case t.Class == TargetClassTier0Scope:
		return tier0ScopeView(as, t)
	case isStoreClass(t.Class):
		if t.Connection != "" {
			return authz.Target{}, nil, denied(ReasonBadTarget)
		}
		return storeView(as, t, tn)
	case t.Connection == "":
		// A directory target must name its connection: failing here keeps a malformed target from
		// being read as a store row (which skips the Tier-0 and ancestry facts).
		return authz.Target{}, nil, denied(ReasonBadTarget)
	default:
		return objectView(as, t, f)
	}
}

// storeView builds the view of a target in activeDIQ's own store: the row, with the tenant as the
// top of its chain. Only a tenant-wide root covers it. The runner reads no live facts for a store
// target, so completeness is by construction. Every directory root is dropped here.
func storeView(as []Assignment, t authority.TargetRef, tn tenant.ID) (authz.Target, []authz.Assignment, error) {
	id, err := authz.ParseObjectID(t.GUID)
	if err != nil {
		return authz.Target{}, nil, denied(ReasonBadTarget)
	}
	var tenantRoot authz.ObjectID
	var out []authz.Assignment
	for _, a := range as {
		var inc []authz.ScopeRoot
		for _, r := range a.Roots {
			if r.Kind != TenantStore || r.Exclude {
				continue
			}
			rid, err := authz.ParseObjectID(r.GUID)
			if err != nil || r.Connection != r.GUID || r.GUID != tn.String() { // only this tenant's root
				continue
			}
			tenantRoot = rid
			inc = append(inc, authz.ScopeRoot{ID: rid, Complete: true})
		}
		if len(inc) > 0 {
			out = append(out, authz.Assignment{Role: authz.Role{Permissions: a.Permissions, TenantOwner: a.TenantOwner}, Scope: authz.Scope{Include: inc}, Via: a.Via})
		}
	}
	tgt := authz.Target{ID: id, Complete: true}
	if !tenantRoot.IsZero() {
		tgt.Ancestors = []authz.ObjectID{tenantRoot}
	}
	return tgt, out, nil
}

// effective returns every assignment that reaches account: its own, and those of the directory
// groups it is a member of (DM-36.I2). A group assignment never carries tenant-owner or a
// control-plane permission (DM-36.I4); such a row is dropped here as well as refused by the schema,
// for a permission that became control-plane after the grant. Membership that is incomplete grants
// nothing through groups. includeFuture adds assignments that have not started (backing guard).
func (a *Authorizer) effective(ctx context.Context, tn tenant.ID, account string, includeFuture bool) ([]Assignment, error) {
	var as []Assignment
	var err error
	if includeFuture {
		as, err = a.src.PendingOrActive(ctx, tn, account, a.now())
	} else {
		as, err = a.src.Assignments(ctx, tn, account, a.now())
	}
	if err != nil {
		return nil, fmt.Errorf("rbac: loading assignments: %w", err)
	}
	if a.members == nil {
		return as, nil
	}
	g, err := a.members.GroupsOf(ctx, tn.String(), account)
	if err != nil {
		return nil, fmt.Errorf("rbac: resolving group membership: %w", err)
	}
	if !g.Complete || len(g.Groups) == 0 {
		return as, nil
	}
	gas, err := a.src.SubjectAssignments(ctx, tn, Subjects{Groups: g.Groups}, a.now(), includeFuture)
	if err != nil {
		return nil, fmt.Errorf("rbac: loading group assignments: %w", err)
	}
	for _, ga := range gas {
		if ga.Subject != SubjectGroup {
			continue
		}
		for _, grp := range g.Groups {
			if grp.Connection != ga.GroupConn || grp.GUID != ga.GroupGUID {
				continue
			}
			if x, ok := personalOnly(ga); ok {
				x.Via = grp.Via
				as = append(as, x)
			}
			break // the first matching membership decides provenance; a direct one is listed first
		}
	}
	return as, nil
}

// automation returns the assignments of an automation policy as its own subject (DM-60.I2), without
// control-plane authority.
func (a *Authorizer) automation(ctx context.Context, tn tenant.ID, policy string) ([]Assignment, error) {
	pas, err := a.src.SubjectAssignments(ctx, tn, Subjects{Automation: policy}, a.now(), false)
	if err != nil {
		return nil, fmt.Errorf("rbac: loading automation assignments: %w", err)
	}
	var out []Assignment
	for _, x := range pas {
		if x.Subject == SubjectAutomation {
			if y, ok := personalOnly(x); ok {
				out = append(out, y)
			}
		}
	}
	return out, nil
}

// personalOnly strips what a non-account subject may never hold (DM-36.I4): a tenant-owner assignment
// is dropped whole, and control-plane permissions are removed from the rest.
func personalOnly(x Assignment) (Assignment, bool) {
	if x.TenantOwner {
		return x, false
	}
	var keep []authz.Permission
	for _, p := range x.Permissions {
		if !authz.NeverCrosses(p) {
			keep = append(keep, p)
		}
	}
	x.Permissions = keep
	return x, len(keep) > 0
}

func isTier0Scope(p authz.Permission) bool {
	for _, x := range Tier0ScopePermissions {
		if x == p {
			return true
		}
	}
	return false
}

// tier0ScopeView builds the evaluator's view of a Tier-0 scope target: the target is the connection,
// and only assignments holding a tier0_scope root for exactly that connection are candidates. Every
// other kind of root is dropped here, so no OU, naming-context or connection-wide grant can cover it.
func tier0ScopeView(as []Assignment, t authority.TargetRef) (authz.Target, []authz.Assignment, error) {
	conn, err := authz.ParseObjectID(t.GUID)
	if err != nil || t.Connection != "" && t.Connection != t.GUID {
		return authz.Target{}, nil, denied(ReasonBadTarget)
	}
	var out []authz.Assignment
	for _, a := range as {
		var inc []authz.ScopeRoot
		for _, r := range a.Roots {
			if r.Kind != Tier0Scope || r.Exclude {
				continue
			}
			id, err := authz.ParseObjectID(r.GUID)
			if err != nil || r.Connection != t.GUID {
				continue
			}
			inc = append(inc, authz.ScopeRoot{ID: id, Complete: true})
		}
		if len(inc) > 0 {
			out = append(out, authz.Assignment{Role: authz.Role{Permissions: a.Permissions, TenantOwner: a.TenantOwner}, Scope: authz.Scope{Include: inc}, Via: a.Via})
		}
	}
	return authz.Target{ID: conn, Complete: true}, out, nil
}

// objectView builds the view of a directory object: the object, its live parent chain and the
// connection as the top of the chain. A tier0_scope root never applies here. Roots of other
// connections are dropped. An unreadable chain, or an object that does not exist, is incomplete.
func objectView(as []Assignment, t authority.TargetRef, f authority.Facts) (authz.Target, []authz.Assignment, error) {
	id, err := authz.ParseObjectID(t.GUID)
	if err != nil {
		return authz.Target{}, nil, denied(ReasonBadTarget)
	}
	tgt := authz.Target{ID: id, Tier0: f.Tier0, Complete: f.Exists && f.AncestorsComplete}
	for _, s := range f.Ancestors {
		aid, err := authz.ParseObjectID(s)
		if err != nil {
			tgt.Complete = false // a chain element that is not a GUID makes the chain unprovable
			break
		}
		tgt.Ancestors = append(tgt.Ancestors, aid)
	}
	if conn, err := authz.ParseObjectID(t.Connection); err == nil {
		tgt.Ancestors = append(tgt.Ancestors, conn) // connection-wide (entra_tenant) roots match the connection
	}
	var out []authz.Assignment
	for _, a := range as {
		var sc authz.Scope
		for _, r := range a.Roots {
			if r.Kind == Tier0Scope || r.Kind == TenantStore || r.Connection != t.Connection {
				continue
			}
			rid, err := authz.ParseObjectID(r.GUID)
			if err != nil {
				// An unparsable exclude must narrow: a zero root makes the whole scope cover nothing.
				rid = authz.ObjectID{}
			}
			switch r.Kind {
			case NamingContext, OUSubtree, EntraTenant:
			case OUOneLevel:
				if r.Exclude {
					rid = authz.ObjectID{} // never written (schema and grant refuse it); fail closed
				} else if r.GUID == t.Connection {
					// The target's chain ends in the connection, so for a parentless object the
					// nearest "parent" would be the connection: such a root grants nothing.
					continue
				}
			default:
				rid = authz.ObjectID{} // a kind this view does not know is never read as a subtree
			}
			root := authz.ScopeRoot{ID: rid, Complete: true, OneLevel: r.Kind == OUOneLevel}
			if r.Exclude {
				sc.Exclude = append(sc.Exclude, root)
			} else {
				sc.Include = append(sc.Include, root)
			}
		}
		out = append(out, authz.Assignment{Role: authz.Role{Permissions: a.Permissions, TenantOwner: a.TenantOwner}, Scope: sc, Via: a.Via})
	}
	return tgt, out, nil
}

package rbac

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// TargetClassTier0Scope is the class of a target that names a connection's Tier-0 scope. Its GUID is
// the connection ID. It matches the inventory module's TargetClassScope (asserted in compose/server).
const TargetClassTier0Scope = "tier0_scope"

// ErrDenied is wrapped by every refusal. The reason is a stable authz.Reason or an rbac reason; it
// carries no grant detail.
var ErrDenied = errors.New("rbac: denied")

// Reasons rbac adds to authz's.
const (
	ReasonUnsupportedChain authz.Reason = "chain_not_a_direct_human"
	ReasonNoTenant         authz.Reason = "no_tenant"
	ReasonScopeOnly        authz.Reason = "tier0_scope_permission_off_scope"
	ReasonBadTarget        authz.Reason = "target_not_a_guid"
)

func denied(r authz.Reason) error { return fmt.Errorf("%w: %s", ErrDenied, r) }

// Authorizer implements operation.Authorizer over authz.Evaluator.
type Authorizer struct {
	src  Source
	eval authz.Evaluator
	now  func() time.Time
}

// New returns an Authorizer reading assignments from src.
func New(src Source) (*Authorizer, error) {
	if src == nil {
		return nil, errors.New("rbac: no assignment source")
	}
	return &Authorizer{src: src, now: time.Now}, nil
}

// FactsQuery asks for the Tier-0 fact and the live parent chain of a directory target. A tier0_scope
// target is a scope, not a directory object: nothing is read about it.
func (a *Authorizer) FactsQuery(_ authority.Chain, _ authz.Permission, t authority.TargetRef) authority.FactsQuery {
	if t.Class == TargetClassTier0Scope {
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
	// Only a person acting directly holds assignments today; a token or automation in the chain would
	// need its own constraint, which has no persistence yet.
	if chain.Validate() != nil || chain.Requester.Kind != authority.Human || len(chain.Via) > 0 {
		return denied(ReasonUnsupportedChain)
	}
	scope := t.Class == TargetClassTier0Scope
	if !scope && isTier0Scope(perm) {
		return denied(ReasonScopeOnly)
	}
	as, err := a.src.Assignments(ctx, tn, string(chain.Requester.ID), a.now())
	if err != nil {
		return fmt.Errorf("rbac: loading assignments: %w", err)
	}
	var tgt authz.Target
	var ev []authz.Assignment
	if scope {
		tgt, ev, err = tier0ScopeView(as, t)
	} else {
		tgt, ev, err = objectView(as, t, f)
	}
	if err != nil {
		return err
	}
	p := &authz.Principal{ID: string(chain.Requester.ID), Assignments: ev}
	if d := a.eval.Authorize(p, nil, perm, tgt); !d.Allowed {
		return denied(d.Reason)
	}
	return nil
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
			out = append(out, authz.Assignment{Role: authz.Role{Permissions: a.Permissions}, Scope: authz.Scope{Include: inc}})
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
			if r.Kind == Tier0Scope || r.Connection != t.Connection {
				continue
			}
			rid, err := authz.ParseObjectID(r.GUID)
			if err != nil {
				// An unparsable exclude must narrow: a zero root makes the whole scope cover nothing.
				rid = authz.ObjectID{}
			}
			root := authz.ScopeRoot{ID: rid, Complete: true}
			if r.Exclude {
				sc.Exclude = append(sc.Exclude, root)
			} else {
				sc.Include = append(sc.Include, root)
			}
		}
		out = append(out, authz.Assignment{Role: authz.Role{Permissions: a.Permissions}, Scope: sc})
	}
	return tgt, out, nil
}

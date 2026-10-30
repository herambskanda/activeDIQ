package rbac

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// ErrUnsupportedChain is returned by ReadScopes.For for a chain it cannot turn into one read scope:
// a requester who is not a human, an automation policy in the chain (its grants would have to be
// intersected with the requester's, and a ReadScope has one token layer, not two), or more than one
// token. The caller refuses the read; nothing is widened.
var ErrUnsupportedChain = errors.New("rbac: initiator chain cannot be turned into a read scope")

// Reasons recorded on a ReadScope (authz.ScopeReason). They are stable and log-safe.
const (
	// ReasonScopeKindUnsupportedPrefix is followed by the root kind that has no ScopeEvaluator.
	ReasonScopeKindUnsupportedPrefix = "scope_kind_unsupported:"
	// ReasonScopeTermInvalid marks an assignment dropped whole because a root could not be turned
	// into a valid term: a malformed GUID, an evaluator error, or an evaluator that returned a term
	// for a different connection, root or kind than it was given.
	ReasonScopeTermInvalid authz.ScopeReason = "scope_term_invalid"
	// ReasonScopeViaNotApplied marks a correlation-derived assignment, which grants no read scope in 2a.
	ReasonScopeViaNotApplied authz.ScopeReason = "scope_correlated_grant_not_applied"
	// ReasonScopeTokenUnresolved marks a token whose scope narrowing has a root that is zero or not
	// found in inventory: the token layer then grants nothing.
	ReasonScopeTokenUnresolved authz.ScopeReason = "scope_token_root_unresolved"
)

// ScopeEvaluators finds the EP-6 evaluator that owns an assignment root kind. module.Contributions
// implements it; rbac does not import the module host.
type ScopeEvaluators interface {
	ScopeEvaluator(kind string) (authz.ScopeEvaluator, bool)
}

// OwnerStatus says whether the account a read acts for can still act: it exists and is active. A
// disabled, deleted or unknown account is not (TM-TB15-T2: its schedules stop). Implemented over the
// account store by compose/server, so rbac never reads another module's tables.
type OwnerStatus interface {
	Active(ctx context.Context, tx store.Tx, t tenant.ID, account string) (bool, error)
}

// ObjectConnections resolves the connection a directory object belongs to, from inventory. It is how
// a token's scope roots (GUIDs with no connection) become terms. ok is false when the object is not
// found, or when its GUID exists in more than one connection: the caller then grants nothing for it.
type ObjectConnections interface {
	ConnectionOf(ctx context.Context, tx store.Tx, t tenant.ID, object authz.ObjectID) (connection authz.ObjectID, ok bool, err error)
}

// ReadScopes is the one producer of directory read-scope predicates (EP-6, reports spec §8.1,
// modules/reports.md §4). Reports and search consume what it returns; nothing else renders scope.
// It decides from the same assignments, group membership, token source and clock as the Authorizer
// it is built from, so a read scope and a per-target Authorize cannot drift apart: the property
// test holds it to authz.Evaluator.AuthorizeRead.
type ReadScopes struct {
	a     *Authorizer
	evals ScopeEvaluators
	owner OwnerStatus
	conns ObjectConnections // nil: a token's scope roots cannot be resolved, so a scoped token reads nothing
}

// NewReadScopes returns the producer. a supplies assignments, group membership, tokens and the clock.
// conns may be nil when no token carries a scope narrowing.
func NewReadScopes(a *Authorizer, evals ScopeEvaluators, owner OwnerStatus, conns ObjectConnections) (*ReadScopes, error) {
	switch {
	case a == nil:
		return nil, errors.New("rbac: read scopes need an authorizer")
	case evals == nil:
		return nil, errors.New("rbac: read scopes need the scope evaluators")
	case owner == nil:
		return nil, errors.New("rbac: read scopes need the owner status")
	}
	return &ReadScopes{a: a, evals: evals, owner: owner, conns: conns}, nil
}

// For returns the read scope of chain's requester for perm in tenant t.
//
//   - Grants come from the account's own assignments and its groups' that hold perm: one grant per
//     assignment, its include terms minus its exclude terms.
//   - A root kind with no registered evaluator contributes nothing and records
//     scope_kind_unsupported:<kind>. An assignment with an exclude of such a kind, or any root that
//     does not turn into a valid term, is dropped whole: an exclude that cannot be bound never widens.
//   - Correlation-derived (Via) assignments contribute nothing, and neither does the tenant root.
//     Tier-0 does not narrow reads (DM-35.I5), so nothing here looks at it.
//   - An API token in the chain adds a separate layer that is AND-ed with the grants. An expired
//     token, or one that does not list perm, is authz.ErrTokenRefused.
//   - A disabled owner, or one with no assignments left, is authz.ErrOwnerDead.
//
// A ReadScope that grants nothing is returned as such (Empty), with the reasons, not as an error.
func (r *ReadScopes) For(ctx context.Context, tx store.Tx, t tenant.ID, chain authority.Chain, perm authz.Permission) (authz.ReadScope, error) {
	if t.IsZero() {
		return authz.ReadScope{}, denied(ReasonNoTenant)
	}
	if chain.Validate() != nil || chain.Requester.Kind != authority.Human {
		return authz.ReadScope{}, ErrUnsupportedChain
	}
	var tokenID string
	for _, v := range chain.Via {
		if v.Kind != authority.APIToken || tokenID != "" {
			return authz.ReadScope{}, ErrUnsupportedChain
		}
		tokenID = string(v.ID)
	}
	account := string(chain.Requester.ID)

	active, err := r.owner.Active(ctx, tx, t, account)
	if err != nil {
		return authz.ReadScope{}, fmt.Errorf("rbac: reading owner status: %w", err)
	}
	if !active {
		return authz.ReadScope{}, authz.ErrOwnerDead
	}
	as, err := r.a.effective(ctx, t, account, false)
	if err != nil {
		return authz.ReadScope{}, err
	}
	if len(as) == 0 {
		return authz.ReadScope{}, authz.ErrOwnerDead // lost every assignment: the schedule stops
	}

	var tok *authz.Token
	if tokenID != "" {
		if tok, err = r.token(ctx, t, tokenID, account, perm); err != nil {
			return authz.ReadScope{}, err
		}
	}

	reasons := reasonSet{}
	var grants []authz.ScopeGrant
	for _, a := range as {
		if !(authz.Role{Permissions: a.Permissions, TenantOwner: a.TenantOwner}).Holds(perm) {
			continue
		}
		if a.Via != nil {
			reasons.add(ReasonScopeViaNotApplied)
			continue
		}
		if g, ok := r.grantOf(a, reasons); ok {
			grants = append(grants, g)
		}
	}

	var layer *authz.TokenLayer
	if tok != nil && tok.Scope != nil {
		if layer, err = r.tokenLayer(ctx, tx, t, *tok.Scope, reasons); err != nil {
			return authz.ReadScope{}, err
		}
	}
	return authz.NewReadScope(grants, layer, reasons.sorted(), summary(len(grants), layer != nil)), nil
}

// token reads the chain's token constraint and refuses it unless it can exercise perm now.
func (r *ReadScopes) token(ctx context.Context, t tenant.ID, tokenID, owner string, perm authz.Permission) (*authz.Token, error) {
	if r.a.tokens == nil {
		return nil, fmt.Errorf("%w: %s", authz.ErrTokenRefused, ReasonNoTokenSource)
	}
	c, err := r.a.tokens.Constraint(ctx, t, tokenID, owner)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", authz.ErrTokenRefused, ReasonTokenUnusable)
	}
	if err := (authz.Evaluator{Now: r.a.now}).CheckTokenFor(&c, perm); err != nil {
		return nil, err
	}
	return &c, nil
}

// grantOf turns one assignment into a grant. It reports false when the assignment contributes nothing
// or must be dropped whole; the reason is recorded either way.
func (r *ReadScopes) grantOf(a Assignment, reasons reasonSet) (authz.ScopeGrant, bool) {
	var g authz.ScopeGrant
	for _, root := range a.Roots {
		if root.Kind == TenantStore {
			if root.Exclude { // never written (schema refuses it); fail closed rather than ignore an exclude
				reasons.add(unsupported(root.Kind))
				return authz.ScopeGrant{}, false
			}
			continue // the tenant root reaches activeDIQ's own store, not directory datasets
		}
		ev, ok := r.evals.ScopeEvaluator(string(root.Kind))
		if !ok || ev == nil {
			reasons.add(unsupported(root.Kind))
			if root.Exclude {
				return authz.ScopeGrant{}, false // an exclude we cannot render must not widen the grant
			}
			continue
		}
		term, err := termOf(ev, root)
		if err != nil {
			reasons.add(ReasonScopeTermInvalid)
			return authz.ScopeGrant{}, false
		}
		if root.Exclude {
			g.Exclude = append(g.Exclude, term)
		} else {
			g.Include = append(g.Include, term)
		}
	}
	return g, len(g.Include) > 0
}

var errTermMismatch = errors.New("rbac: evaluator returned a term for a different root")

// termOf asks the evaluator for the root's term and checks the answer. EP-6 evaluators are module
// code, and the compiler cannot tell a valid term for the wrong region from the right one, so a term
// is accepted only when it names exactly the connection and root it was given and its kind is the
// one this root kind stands for (authz.TermKind.String is the root-kind name). Anything else is an
// error and the caller drops the assignment.
func termOf(ev authz.ScopeEvaluator, root Root) (authz.ScopeTerm, error) {
	conn, err := authz.ParseObjectID(root.Connection)
	if err != nil {
		return authz.ScopeTerm{}, err
	}
	guid, err := authz.ParseObjectID(root.GUID)
	if err != nil {
		return authz.ScopeTerm{}, err
	}
	term, err := ev.Term(conn, guid)
	if err != nil {
		return authz.ScopeTerm{}, err
	}
	switch term.Kind {
	case authz.TermNamingContext, authz.TermSubtree, authz.TermOneLevel:
	default:
		return authz.ScopeTerm{}, errTermMismatch
	}
	if term.Connection != conn || term.Root != guid || term.Kind.String() != string(root.Kind) {
		return authz.ScopeTerm{}, errTermMismatch
	}
	return term, nil
}

// tokenLayer turns a token's scope narrowing into the layer AND-ed with the grants. A token root
// carries no kind: authz.Scope.covers reads it as "this object or any ancestor", which is a subtree
// term (a OneLevel include root is its direct children). The connection comes from inventory. A root
// that is zero or not found makes the layer grant nothing, as covers does for a zero root.
func (r *ReadScopes) tokenLayer(ctx context.Context, tx store.Tx, t tenant.ID, sc authz.Scope, reasons reasonSet) (*authz.TokenLayer, error) {
	layer := &authz.TokenLayer{}
	nothing := func() (*authz.TokenLayer, error) {
		reasons.add(ReasonScopeTokenUnresolved)
		return &authz.TokenLayer{}, nil
	}
	resolve := func(root authz.ScopeRoot, kind authz.TermKind) (authz.ScopeTerm, bool, error) {
		if root.ID.IsZero() || r.conns == nil {
			return authz.ScopeTerm{}, false, nil
		}
		conn, ok, err := r.conns.ConnectionOf(ctx, tx, t, root.ID)
		if err != nil {
			return authz.ScopeTerm{}, false, fmt.Errorf("rbac: resolving token scope root: %w", err)
		}
		if !ok || conn.IsZero() {
			return authz.ScopeTerm{}, false, nil
		}
		return authz.ScopeTerm{Kind: kind, Connection: conn, Root: root.ID}, true, nil
	}
	for _, root := range sc.Include {
		kind := authz.TermSubtree
		if root.OneLevel {
			kind = authz.TermOneLevel
		}
		term, ok, err := resolve(root, kind)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nothing()
		}
		layer.Include = append(layer.Include, term)
	}
	for _, root := range sc.Exclude { // covers excludes any target whose chain holds the root
		term, ok, err := resolve(root, authz.TermSubtree)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nothing()
		}
		layer.Exclude = append(layer.Exclude, term)
	}
	return layer, nil
}

func unsupported(k RootKind) authz.ScopeReason {
	return authz.ScopeReason(ReasonScopeKindUnsupportedPrefix + string(k))
}

// reasonSet collects reasons without duplicates; sorted gives a stable order.
type reasonSet map[authz.ScopeReason]struct{}

func (s reasonSet) add(r authz.ScopeReason) { s[r] = struct{}{} }

func (s reasonSet) sorted() []authz.ScopeReason {
	out := make([]authz.ScopeReason, 0, len(s))
	for r := range s {
		out = append(out, r)
	}
	slices.Sort(out)
	return out
}

// summary is the human text of a report run's scope_applied. It names counts, never GUIDs or names.
func summary(grants int, narrowed bool) string {
	var b strings.Builder
	switch grants {
	case 0:
		b.WriteString("No assignment grants read access to directory data")
	case 1:
		b.WriteString("Read access from 1 assignment")
	default:
		b.WriteString("Read access from " + strconv.Itoa(grants) + " assignments")
	}
	if narrowed {
		b.WriteString(", narrowed by the API token's scope")
	}
	return b.String()
}

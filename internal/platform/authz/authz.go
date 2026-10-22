// Package authz is the permission and scope kernel package (blueprint §5.1, EP-6).
//
// This file holds the pure evaluator (threat model §7.7): effective permission is
// role ∩ delegation scope ∩ token, checked on the target object, deny by default. It does no I/O.
// Callers supply live facts (the target's parent chain read from the DC at Plan and again at
// Apply, ADR-0005 rule 7); the evaluator fails closed when those facts are missing or incomplete.
package authz

import (
	"errors"
	"slices"
	"time"
)

// Permission names one thing a principal may be allowed to do, for example "objects.user.create".
type Permission string

// Reason says why a Decision came out as it did. It is stable, machine-readable and safe to log.
type Reason string

// Decision reasons.
const (
	ReasonAllowed          Reason = "allowed"
	ReasonNoPrincipal      Reason = "no_principal"
	ReasonOwnerDisabled    Reason = "owner_disabled"
	ReasonOwnerNoAuthority Reason = "owner_lost_authority"
	ReasonTokenExpired     Reason = "token_expired"
	ReasonTokenExcludes    Reason = "token_excludes_permission"
	ReasonTier0            Reason = "tier0_target"
	ReasonFactsIncomplete  Reason = "target_facts_incomplete"
	ReasonNotInScope       Reason = "not_granted_on_target"
)

// Typed errors returned by operations that refuse as a whole.
var (
	// ErrOwnerDead means a token or scheduled run's owner is disabled or holds no authority.
	ErrOwnerDead = errors.New("authz: owner is disabled or has lost authority")
	// ErrEscalation means a grantor lacks a privilege of the role over the whole scope.
	ErrEscalation = errors.New("authz: grantor does not hold every privilege of the role over the whole scope")
	// ErrInvalidGrant means the role or scope of a grant is empty or malformed.
	ErrInvalidGrant = errors.New("authz: invalid grant")
	// ErrFactsIncomplete means a scope root the check had to consult was not resolved live and
	// completely. The grant is refused: containment cannot be proven (fail closed).
	ErrFactsIncomplete = errors.New("authz: scope root facts incomplete")
	// ErrTokenInvalid means the token is missing or expired (distinct from a dead owner).
	ErrTokenInvalid = errors.New("authz: token missing or expired")
)

// ObjectID identifies a directory object by objectGUID (never by DN).
type ObjectID string

// Target is the live fact set about the object an operation touches.
type Target struct {
	ID ObjectID
	// Ancestors are the GUIDs of the live parent chain, nearest parent first, up to the naming
	// context root. Complete must be true only when the chain was read live and fully.
	Ancestors []ObjectID
	Complete  bool
	// Tier0 is the Tier-0 flag (DM-16.I8): no role or scope may lift it.
	Tier0 bool
}

// chain returns the target itself followed by its ancestors.
func (t Target) chain() []ObjectID { return append([]ObjectID{t.ID}, t.Ancestors...) }

// Scope is a delegation scope: include roots minus exclude roots. An empty Include matches nothing.
type Scope struct {
	Include []ScopeRoot
	Exclude []ScopeRoot
}

// ScopeRoot is an OU, container or object that roots part of a scope. Ancestors are needed so
// containment of one scope in another can be decided without a directory read.
//
// Ancestors and Complete must be set only by a live resolver reading the directory, never from
// request input: forged ancestors on a new root would make containment checks pass. Complete is
// true only when the chain was read live and fully (a domain-root has zero ancestors and is complete).
// CheckGrant refuses any root it consults that is not Complete.
type ScopeRoot struct {
	ID        ObjectID
	Ancestors []ObjectID
	Complete  bool
}

// within reports whether id is this root or one of its ancestors. A blank ID never matches.
func (r ScopeRoot) within(id ObjectID) bool {
	if id == "" || r.ID == "" {
		return false
	}
	return r.ID == id || slices.Contains(r.Ancestors, id)
}

// valid reports whether the root has a GUID and a completely resolved chain.
func (r ScopeRoot) valid() bool { return r.ID != "" && r.Complete && !slices.Contains(r.Ancestors, "") }

func (s Scope) roots() []ScopeRoot { return append(slices.Clone(s.Include), s.Exclude...) }

// covers reports whether the scope contains the target: some chain element is an include root and
// no chain element is an exclude root.
func (s Scope) covers(t Target) bool {
	if t.ID == "" || !t.Complete {
		return false
	}
	chain := t.chain()
	if slices.Contains(chain, "") {
		return false
	}
	for _, e := range s.Exclude {
		if slices.Contains(chain, e.ID) {
			return false
		}
	}
	for _, i := range s.Include {
		if slices.Contains(chain, i.ID) {
			return true
		}
	}
	return false
}

// Role is a set of permissions.
type Role struct {
	Permissions []Permission
}

func (r Role) has(p Permission) bool { return slices.Contains(r.Permissions, p) }

// Assignment is role × scope for one principal.
type Assignment struct {
	Role  Role
	Scope Scope
}

// Principal is the human (or owner) whose authority is evaluated. Assignments must be the current
// ones, including group-derived ones, resolved by the caller.
type Principal struct {
	ID          string
	Disabled    bool
	Assignments []Assignment
}

// Token is an API token's constraint. Effective permission is the owner's current authority
// intersected with Permissions; an empty set allows nothing. A nil *Token means no token (a session).
type Token struct {
	Permissions []Permission
	// ExpiresAt is mandatory for API tokens; the zero value is treated as already expired.
	ExpiresAt time.Time
	// Scope narrows the token to part of the owner's scope (DM-32 scope_narrowing). Nil means no
	// narrowing; a non-nil empty Scope matches nothing.
	Scope *Scope
}

// Decision is the outcome of one check.
type Decision struct {
	Allowed bool
	Reason  Reason
}

func deny(r Reason) Decision { return Decision{Reason: r} }

// Evaluator evaluates permissions at a point in time.
type Evaluator struct {
	Now func() time.Time
}

func (e Evaluator) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

// ownerAlive refuses a disabled owner or one with no authority left (TM-TB2-T8).
func ownerAlive(p *Principal) (Reason, bool) {
	if p == nil || p.ID == "" {
		return ReasonNoPrincipal, false
	}
	if p.Disabled {
		return ReasonOwnerDisabled, false
	}
	if len(p.Assignments) == 0 {
		return ReasonOwnerNoAuthority, false
	}
	return "", true
}

func (e Evaluator) tokenOK(tok *Token, perm Permission) (Reason, bool) {
	if tok == nil {
		return "", true
	}
	if tok.ExpiresAt.IsZero() || !e.now().Before(tok.ExpiresAt) {
		return ReasonTokenExpired, false
	}
	if !slices.Contains(tok.Permissions, perm) {
		return ReasonTokenExcludes, false
	}
	return "", true
}

// Authorize decides whether p, acting through tok (nil for a session), may exercise perm on target.
// effective = role ∩ scope ∩ token, deny by default.
func (e Evaluator) Authorize(p *Principal, tok *Token, perm Permission, target Target) Decision {
	if r, ok := ownerAlive(p); !ok {
		return deny(r)
	}
	if r, ok := e.tokenOK(tok, perm); !ok {
		return deny(r)
	}
	if target.ID == "" || !target.Complete || slices.Contains(target.Ancestors, "") {
		return deny(ReasonFactsIncomplete)
	}
	if target.Tier0 {
		return deny(ReasonTier0)
	}
	if tok != nil && tok.Scope != nil && !tok.Scope.covers(target) {
		return deny(ReasonTokenExcludes)
	}
	for _, a := range p.Assignments {
		if a.Role.has(perm) && a.Scope.covers(target) {
			return Decision{Allowed: true, Reason: ReasonAllowed}
		}
	}
	return deny(ReasonNotInScope)
}

// ItemDecision is the per-item result of a bulk check.
type ItemDecision struct {
	Target Target
	Decision
}

// BulkResult is the per-item outcome of AuthorizeItems.
type BulkResult struct {
	Items   []ItemDecision
	Allowed int
	Refused int
}

// AuthorizeItems checks every item independently (TM-TB1-T8): one refused item never aborts the
// others, and an owner who is dead refuses every item.
func (e Evaluator) AuthorizeItems(p *Principal, tok *Token, perm Permission, targets []Target) BulkResult {
	res := BulkResult{Items: make([]ItemDecision, 0, len(targets))}
	for _, t := range targets {
		d := e.Authorize(p, tok, perm, t)
		if d.Allowed {
			res.Allowed++
		} else {
			res.Refused++
		}
		res.Items = append(res.Items, ItemDecision{Target: t, Decision: d})
	}
	return res
}

// ReportRows is the outcome of compiling a report with its owner's scope.
type ReportRows struct {
	Permitted []Target
	// Omitted is for internal audit only. It must never reach a report recipient: counts of
	// out-of-scope rows leak existence (TM-TB1-T8); any count shown comes after authorisation.
	Omitted int
}

// FilterForOwner trims report candidates to what the owner may see now (TM-TB15-T2). A disabled
// owner or one without authority returns ErrOwnerDead: the schedule stops, it does not deliver.
func (e Evaluator) FilterForOwner(owner *Principal, perm Permission, candidates []Target) (ReportRows, error) {
	if _, ok := ownerAlive(owner); !ok {
		return ReportRows{}, ErrOwnerDead
	}
	var out ReportRows
	for _, t := range candidates {
		if e.Authorize(owner, nil, perm, t).Allowed {
			out.Permitted = append(out.Permitted, t)
		} else {
			out.Omitted++
		}
	}
	return out, nil
}

// CheckToken reports ErrOwnerDead when a token's owner is disabled or lost authority, and
// ErrTokenInvalid when the token is missing or expired (TM-TB2-T8). Call it when a token is presented, before any operation.
func (e Evaluator) CheckToken(owner *Principal, tok *Token) error {
	if _, ok := ownerAlive(owner); !ok {
		return ErrOwnerDead
	}
	if tok == nil || tok.ExpiresAt.IsZero() || !e.now().Before(tok.ExpiresAt) {
		return ErrTokenInvalid
	}
	return nil
}

// CheckGrant enforces no-escalation (DM-36.I1, TM-TB1-T11): the grantor must hold every permission
// of the role over the whole of the scope, through a single assignment that contains it. When the
// grantor acts through a token, the token must carry every permission too. Containment is
// conservative: a scope split across several of the grantor's assignments is refused.
func (e Evaluator) CheckGrant(grantor *Principal, tok *Token, role Role, scope Scope) error {
	if len(role.Permissions) == 0 || len(scope.Include) == 0 {
		return ErrInvalidGrant
	}
	if _, ok := ownerAlive(grantor); !ok {
		return ErrOwnerDead
	}
	if slices.ContainsFunc(scope.Include, func(r ScopeRoot) bool { return r.ID == "" }) ||
		slices.ContainsFunc(scope.Exclude, func(r ScopeRoot) bool { return r.ID == "" }) {
		return ErrInvalidGrant
	}
	if !grantRootsComplete(grantor, tok, role, scope) {
		return ErrFactsIncomplete
	}
	for _, perm := range role.Permissions {
		if r, ok := e.tokenOK(tok, perm); !ok {
			if r == ReasonTokenExpired {
				return ErrTokenInvalid
			}
			return ErrEscalation
		}
		if tok != nil && tok.Scope != nil && !scopeContains(*tok.Scope, scope) {
			return ErrEscalation
		}
		if !holdsOverScope(grantor, perm, scope) {
			return ErrEscalation
		}
	}
	return nil
}

func holdsOverScope(g *Principal, perm Permission, s Scope) bool {
	for _, root := range s.Include {
		if !slices.ContainsFunc(g.Assignments, func(a Assignment) bool {
			return a.Role.has(perm) && assignmentContains(a.Scope, root, s.Exclude)
		}) {
			return false
		}
	}
	return true
}

// assignmentContains reports whether grantor scope g contains the whole subtree of root, minus the
// new scope's own excludes.
func assignmentContains(g Scope, root ScopeRoot, newExcl []ScopeRoot) bool {
	covered := false
	for _, i := range g.Include {
		if root.within(i.ID) {
			covered = true
			break
		}
	}
	if !covered {
		return false
	}
	for _, ge := range g.Exclude {
		if root.within(ge.ID) {
			return false // root itself sits in a grantor exclusion
		}
		if !ge.within(root.ID) {
			continue // grantor exclusion lies outside this root's subtree
		}
		// The grantor cannot act inside ge, so the new scope must exclude it too.
		if !slices.ContainsFunc(newExcl, func(ne ScopeRoot) bool { return ge.within(ne.ID) }) {
			return false
		}
	}
	return true
}

// scopeContains reports whether g contains every include root of s (minus s's own excludes).
func scopeContains(g, s Scope) bool {
	return !slices.ContainsFunc(s.Include, func(root ScopeRoot) bool {
		return !assignmentContains(g, root, s.Exclude)
	})
}

// grantRootsComplete reports whether every root CheckGrant will consult is valid and Complete: the
// new scope, the token scope, and the scopes of grantor assignments carrying any role permission.
func grantRootsComplete(g *Principal, tok *Token, role Role, scope Scope) bool {
	ok := func(s Scope) bool {
		return !slices.ContainsFunc(s.roots(), func(r ScopeRoot) bool { return !r.valid() })
	}
	if !ok(scope) || (tok != nil && tok.Scope != nil && !ok(*tok.Scope)) {
		return false
	}
	for _, a := range g.Assignments {
		if slices.ContainsFunc(role.Permissions, a.Role.has) && !ok(a.Scope) {
			return false
		}
	}
	return true
}

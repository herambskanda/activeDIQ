// Package authz is the permission and scope kernel package (blueprint §5.1, EP-6).
//
// This file holds the pure evaluator (threat model §7.7): effective permission is
// role ∩ delegation scope ∩ token, checked on the target object, deny by default. It does no I/O.
// Callers supply live facts (the target's parent chain read from the DC at Plan and again at
// Apply, ADR-0005 rule 7); the evaluator fails closed when those facts are missing or incomplete.
package authz

import (
	"encoding/hex"
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
	// ErrInvalidObjectID means a string is not a canonical, non-zero object GUID.
	ErrInvalidObjectID = errors.New("authz: invalid object id")
	// ErrTokenInvalid means the token is missing or expired (distinct from a dead owner).
	ErrTokenInvalid = errors.New("authz: token missing or expired")
	// ErrTokenRefused means a token cannot be used for a permission: it is expired, it has no
	// expiry, it does not list the permission, or its constraint could not be read. A read-scope
	// producer returns it so the caller fails the run (reports: token_refused).
	ErrTokenRefused = errors.New("authz: token refused for this permission")
)

// ObjectID identifies a directory object by objectGUID (never by DN). It is an opaque comparable
// value, not text, so two spellings of one GUID cannot compare unequal and silently skip an
// exclusion. The zero value is invalid and never matches anything.
//
// Canonical byte order is the AD octet order of objectGUID (MS-DTYP 2.3.4: Data1-3 little-endian),
// i.e. the bytes LDAP returns. Build values ONLY with ObjectIDFromOctets (raw objectGUID bytes) or
// ParseObjectID (text form); both yield the same value for the same object. Converting from any
// other type with ObjectID(x) is forbidden. The platform may not import directory code, so
// integrators call these constructors.
type ObjectID [16]byte

// IsZero reports whether id is the invalid zero value.
func (id ObjectID) IsZero() bool { return id == ObjectID{} }

// ObjectIDFromOctets builds an ObjectID from the 16 raw objectGUID bytes in AD octet order.
// Any other length or the all-zero GUID is an error: callers fail closed.
func ObjectIDFromOctets(b []byte) (ObjectID, error) {
	var id ObjectID
	if len(b) != len(id) {
		return id, ErrInvalidObjectID
	}
	copy(id[:], b)
	if id.IsZero() {
		return ObjectID{}, ErrInvalidObjectID
	}
	return id, nil
}

// ParseObjectID parses the dashed 8-4-4-4-12 hex form (either case). Anything else, including
// braces, other lengths and the all-zero GUID, is an error: callers fail closed.
func ParseObjectID(s string) (ObjectID, error) {
	var id ObjectID
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return id, ErrInvalidObjectID
	}
	raw := s[0:8] + s[9:13] + s[14:18] + s[19:23] + s[24:]
	var text [16]byte
	if _, err := hex.Decode(text[:], []byte(raw)); err != nil || text == ([16]byte{}) {
		return ObjectID{}, ErrInvalidObjectID
	}
	// Text is RFC order; convert to AD octet order (Data1, Data2, Data3 byte-swapped).
	id = text
	slices.Reverse(id[0:4])
	slices.Reverse(id[4:6])
	slices.Reverse(id[6:8])
	return id, nil
}

// Target is the live fact set about the object an operation touches.
type Target struct {
	ID ObjectID
	// Ancestors are the GUIDs of the live parent chain, nearest parent first, up to the naming
	// context root. Complete must be true only when the chain was read live and fully.
	Ancestors []ObjectID
	Complete  bool
	// Tier0 is the Tier-0 flag (DM-16.I8): no role or scope may lift it.
	Tier0 bool
	// CorrelatedTier0 is true when the target has any correlation to a tier0 object on the other
	// side (C16, E5). Correlation-derived grants never apply to it.
	CorrelatedTier0 bool
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
//
// OneLevel narrows an include root (ou_one_level, DM-35) to the direct children of the OU: only a
// target whose nearest parent is the root is covered, never the root itself or anything deeper.
// Every consumer treats a OneLevel root as the narrower set; none may read it as a subtree. An
// exclude root is never OneLevel (the loader and the grant path refuse it).
type ScopeRoot struct {
	ID        ObjectID
	Ancestors []ObjectID
	Complete  bool
	OneLevel  bool
}

// within reports whether id is this root or one of its ancestors. A blank ID never matches.
func (r ScopeRoot) within(id ObjectID) bool {
	if id.IsZero() || r.ID.IsZero() {
		return false
	}
	return r.ID == id || slices.Contains(r.Ancestors, id)
}

// valid reports whether the root has a GUID and a completely resolved chain.
func (r ScopeRoot) valid() bool {
	return !r.ID.IsZero() && r.Complete && !slices.Contains(r.Ancestors, ObjectID{})
}

func (s Scope) roots() []ScopeRoot { return append(slices.Clone(s.Include), s.Exclude...) }

// covers reports whether the scope contains the target: some chain element is an include root and
// no chain element is an exclude root.
//
// A scope with any zero-ID root (include or exclude) covers nothing: an exclusion that could not
// be resolved must narrow, never widen.
func (s Scope) covers(t Target) bool {
	if t.ID.IsZero() || !t.Complete {
		return false
	}
	for _, r := range s.roots() {
		if r.ID.IsZero() {
			return false
		}
	}
	chain := t.chain()
	if slices.Contains(chain, ObjectID{}) {
		return false
	}
	for _, e := range s.Exclude {
		if slices.Contains(chain, e.ID) {
			return false
		}
	}
	for _, i := range s.Include {
		if i.OneLevel {
			// Direct children only: the nearest parent is the root. The root itself and deeper
			// descendants are not covered.
			if len(t.Ancestors) > 0 && t.Ancestors[0] == i.ID {
				return true
			}
			continue
		}
		if slices.Contains(chain, i.ID) {
			return true
		}
	}
	return false
}

// Role is a set of permissions.
type Role struct {
	Permissions []Permission
	// TenantOwner marks the tenant-owner role. It never carries across a correlation (TM-D17 (h)).
	TenantOwner bool
}

// has: the tenant-owner role holds every permission (DM-34.I1); its reach is still its scope's.
// A platform-only permission (platformOnly) is never held by a Role: not by listing, not by the
// tenant-owner role. Platform scope is not a delegation scope, so no tenant or delegation assignment
// reaches it (TM-D1, T-0250).
func (r Role) has(p Permission) bool {
	if IsPlatformOnly(p) {
		return false
	}
	return r.TenantOwner || slices.Contains(r.Permissions, p)
}

// Holds reports whether the role grants p, with the same rules Authorize applies: the tenant-owner
// role holds every permission except a platform-only one, which no role holds.
func (r Role) Holds(p Permission) bool { return r.has(p) }

// platformOnly lists the permissions exercised at platform scope only (installation operator, ADR-0002
// "Configuration scope"). Delegation and tenant scopes cannot hold them, so no role listing one can
// be granted and the tenant-owner role does not imply them.
var platformOnly = []Permission{"connections.tier0_override.acknowledge"}

// IsPlatformOnly reports whether p is a platform-scope-only permission.
func IsPlatformOnly(p Permission) bool { return slices.Contains(platformOnly, p) }

// Assignment is role × scope for one principal.
type Assignment struct {
	Role  Role
	Scope Scope
	// Via is non-nil when the assignment reaches the principal through a correlation (hybrid.go).
	Via *Derivation
}

// Principal is the human (or owner) whose authority is evaluated. Assignments must be the current
// ones, including group-derived ones, resolved by the caller.
type Principal struct {
	ID          string
	Disabled    bool
	Assignments []Assignment
	// AuthorityFactor is true when the session being evaluated holds a current activeDIQ authority
	// factor (TM-D19 rule 1). Correlation-derived assignments apply only when it is true; the zero
	// value denies them.
	AuthorityFactor bool
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
	// HybridRefusals lists correlation-derived grants that matched the permission and target but
	// were skipped by the hybrid gate. The caller audits each with its reason, allowed or not.
	HybridRefusals []HybridRefusal
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
	return e.authorize(p, tok, perm, target, false)
}

// AuthorizeRead is the read oracle (reports modules/reports.md §4.6): Authorize without the two
// limits that apply to writes. A Tier-0 target is not refused, because Tier-0 does not narrow reads
// (DM-35.I5); and a correlation-derived (Via) assignment contributes nothing at 2a. Everything else
// is the Authorize path: owner liveness, tokenOK, the target's facts, the token's Scope and each
// assignment's role and scope. The read-scope producer (rbac.ReadScopes) and its property test are
// held to this one decision, so there is no second containment implementation.
func (e Evaluator) AuthorizeRead(p *Principal, tok *Token, perm Permission, target Target) Decision {
	return e.authorize(p, tok, perm, target, true)
}

func (e Evaluator) authorize(p *Principal, tok *Token, perm Permission, target Target, read bool) Decision {
	if r, ok := ownerAlive(p); !ok {
		return deny(r)
	}
	if r, ok := e.tokenOK(tok, perm); !ok {
		return deny(r)
	}
	if target.ID.IsZero() || !target.Complete || slices.Contains(target.Ancestors, ObjectID{}) {
		return deny(ReasonFactsIncomplete)
	}
	if target.Tier0 && !read {
		return deny(ReasonTier0)
	}
	if tok != nil && tok.Scope != nil && !tok.Scope.covers(target) {
		return deny(ReasonTokenExcludes)
	}
	var refusals []HybridRefusal
	for _, a := range p.Assignments {
		if !a.Role.has(perm) || !a.Scope.covers(target) {
			continue
		}
		if a.Via != nil {
			if read {
				continue
			}
			r, ok := hybridCheck(a, perm, p.AuthorityFactor)
			if ok && target.CorrelatedTier0 {
				r, ok = HybridRefusal{Reason: ReasonHybridTier0}, false
			}
			if !ok {
				refusals = append(refusals, r)
				continue
			}
		}
		return Decision{Allowed: true, Reason: ReasonAllowed, HybridRefusals: refusals}
	}
	if len(refusals) > 0 {
		return Decision{Reason: refusals[0].Reason, HybridRefusals: refusals}
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

// CheckTokenFor reports ErrTokenRefused when tok cannot exercise perm now: it has no expiry, it has
// expired, or it does not list perm. A nil token (a session) is always usable. These are the same
// two reasons Authorize refuses on (tokenOK); it exists so a producer that builds a query rather
// than deciding a target applies the identical test.
func (e Evaluator) CheckTokenFor(tok *Token, perm Permission) error {
	if _, ok := e.tokenOK(tok, perm); !ok {
		return ErrTokenRefused
	}
	return nil
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
	if len(role.Permissions) == 0 || len(scope.Include) == 0 || slices.ContainsFunc(role.Permissions, IsPlatformOnly) {
		return ErrInvalidGrant
	}
	if _, ok := ownerAlive(grantor); !ok {
		return ErrOwnerDead
	}
	if slices.ContainsFunc(scope.Include, func(r ScopeRoot) bool { return r.ID.IsZero() }) ||
		slices.ContainsFunc(scope.Exclude, func(r ScopeRoot) bool { return r.ID.IsZero() }) {
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
			// A grant is RBAC administration, so it never crosses a correlation (TM-D17 rule 5):
			// a correlation-derived assignment can never back a grant, whatever its state.
			return a.Via == nil && a.Role.has(perm) && assignmentContains(a.Scope, root, s.Exclude)
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
		if i.OneLevel {
			// A one-level grantor root reaches only the direct children of its OU. It contains a
			// new root only when that is the same one-level root: a subtree below it, or a deeper
			// one-level root, reaches objects the grantor cannot act on.
			if root.OneLevel && root.ID == i.ID {
				covered = true
				break
			}
			continue
		}
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
		if a.Via == nil && slices.ContainsFunc(role.Permissions, a.Role.has) && !ok(a.Scope) {
			return false
		}
	}
	return true
}

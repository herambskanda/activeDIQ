package authz

import "strings"

// Hybrid gate (threat model §6.8, TM-D17 rules 1, 4 (g) and 5 (h)).
//
// A grant that reaches an sso account through a correlation (DM-36.I2 directory-group grants,
// DM-35.I6 include_correlated) crosses from one administrative domain to another. It is applied
// only when the correlation is matched, the tenant's takeover_protection is attested, neither side
// is tier0, and the permission is not one that never crosses. Anything else is skipped, the
// refusal is returned on the Decision for the caller's audit, and direct (non-derived) grants
// still apply. The evaluator does no I/O: the caller supplies the facts, read live.

// Hybrid refusal reasons. They are stable, machine-readable and safe to log.
const (
	// ReasonHybridUnattested: takeover_protection is not attested (DM-10.I7), so every
	// correlation-derived grant is denied (degraded mode).
	ReasonHybridUnattested Reason = "hybrid_takeover_not_attested"
	// ReasonHybridNotMatched: the correlation is candidate, broken or unknown. CorrelationReason
	// on the refusal carries the gate's own reason (not_synced, cloud_managed, sid_mismatch,
	// reconfirm_required, tenant_takeover_open, ...).
	ReasonHybridNotMatched Reason = "hybrid_correlation_not_matched"
	// ReasonHybridTier0: either side of the correlation is tier0 (TM-D2, C16, E5).
	ReasonHybridTier0 Reason = "hybrid_correlation_tier0"
	// ReasonHybridNeverCrosses: tenant-owner, or a permission administering RBAC, delegation
	// scopes or connections, is never effective across a correlation (rule 5 (h)).
	ReasonHybridNeverCrosses Reason = "hybrid_authority_never_crosses"
)

// Takeover protection states (DM-10.I7), as read through the connections port.
const TakeoverAttested = "attested"

// Correlation state matched is the only state that carries authority (DM-20.I4).
const CorrelationMatched = "matched"

// Correlation is the live fact set about the correlation a derived grant came through.
type Correlation struct {
	// State is the stored DM-20 state; only "matched" carries authority.
	State string
	// Reason is the gate's reason when State is not matched. Informational, for the audit.
	Reason string
	// Takeover is the Entra connection's takeover_protection as the connections port reports it.
	// Empty (unreadable) counts as not attested.
	Takeover string
	// Tier0Either is true when the AD side or the Entra side is tier0 (any correlation counts for
	// protection, C16/E5). It must be set by the resolver from the tier0 classifier, fail-closed.
	Tier0Either bool
}

// Derivation marks an assignment as reaching the principal through a correlation. A nil
// Assignment.Via means a direct grant. Resolvers must set Via on every correlation-derived
// assignment; leaving it nil on one is a bypass.
type Derivation struct {
	// Correlation is the correlation facts. Nil means the facts could not be established: refused.
	Correlation *Correlation
}

// neverCrossPrefixes name the permission families that administer RBAC, delegation scopes or
// connections. Rule 5 (h): they are assigned only to the console account itself.
var neverCrossPrefixes = []string{"rbac.", "authz.", "delegation.", "scope.", "connections.", "tenant.",
	// inventory.tier0_ administers the Tier-0 designation itself (TM-D2, rule 5 (h)).
	"inventory.tier0_"}

// NeverCrosses reports whether permission p is one that never carries across a correlation.
func NeverCrosses(p Permission) bool {
	for _, pre := range neverCrossPrefixes {
		if strings.HasPrefix(string(p), pre) {
			return true
		}
	}
	return false
}

// HybridRefusal is one correlation-derived grant that was skipped, for the audit trail.
type HybridRefusal struct {
	Reason Reason
	// CorrelationReason is the gate's reason for a non-matched correlation, else empty.
	CorrelationReason string
}

// hybridCheck decides whether a derived assignment may apply for perm. ok is false with the refusal.
func hybridCheck(a Assignment, perm Permission) (HybridRefusal, bool) {
	c := a.Via.Correlation
	if c == nil {
		return HybridRefusal{Reason: ReasonHybridNotMatched, CorrelationReason: "facts_missing"}, false
	}
	if c.Takeover != TakeoverAttested {
		return HybridRefusal{Reason: ReasonHybridUnattested, CorrelationReason: "tenant_takeover_open"}, false
	}
	if c.State != CorrelationMatched {
		return HybridRefusal{Reason: ReasonHybridNotMatched, CorrelationReason: c.Reason}, false
	}
	if c.Tier0Either {
		return HybridRefusal{Reason: ReasonHybridTier0}, false
	}
	if a.Role.TenantOwner || NeverCrosses(perm) {
		return HybridRefusal{Reason: ReasonHybridNeverCrosses}, false
	}
	return HybridRefusal{}, true
}

package inventory

import (
	"bytes"
	"strings"
	"time"
)

// TakeoverProtection is the Entra connection's attested state of the two tenant sync features
// (DM-10.I7). It is computed from the latest attestation; the gate never reads the flags live.
type TakeoverProtection string

// The states a connection reports.
const (
	TakeoverAttested TakeoverProtection = "attested"
	TakeoverOpen     TakeoverProtection = "open"
	TakeoverStale    TakeoverProtection = "stale"
)

// GateInput is everything the DM-20.I4 gate looks at. The sync ingester fills it from the two
// inventories and the connection registry; Evaluate does no I/O, so the gate is one pure, testable
// function whose only inputs are visible here.
type GateInput struct {
	// IsGroup selects I1b: a group matches on its SID, a user on an anchor corroborated by the SID.
	IsGroup bool

	// SideGone: one of the two objects is purged or deleted. The correlation goes broken.
	SideGone bool

	// (a) onPremisesSyncEnabled; nil is null (never synced, SOA transferred, rollback pending).
	EntraSyncEnabled *bool
	// (b) onPremisesSyncBehavior.isCloudManaged; nil when it cannot be read, and then (a) decides.
	EntraCloudManaged *bool
	// (c) the Entra object's onPremisesSecurityIdentifier and the AD object's current objectSid, binary.
	EntraSID []byte
	ADSID    []byte
	// (d) onPremisesDomainName (empty when not populated), the AD object's domain DNS name, and
	// whether the HybridLink between that domain and the tenant is confirmed (DM-21.I2).
	EntraDomainName string
	ADDomainName    string
	LinkConfirmed   bool
	// (e) how many AD objects the anchor resolves to across every linked AD connection (I1a).
	AnchorMatches int
	// (f) the Entra connection's takeover_protection and whether first_attested_at is still unset.
	Takeover        TakeoverProtection
	FirstAttestedAt time.Time
	// (g) the Entra object's cloud_seen_at (DM-16.I9); zero when never seen cloud-only.
	CloudSeenAt time.Time

	// Prior is the stored correlation for these two objects, if any. Its markers survive broken and
	// removed (DM-20 Lifecycle): eligibility is set once and only goes down.
	Prior *Prior
}

// Prior is what a stored correlation contributes to the next evaluation.
type Prior struct {
	State            State
	EligibleSince    time.Time
	EligibilityClass string
	ReconfirmedAt    time.Time
}

// Verdict is the result of one evaluation: the state to store, why not matched, and the I4(g) markers.
type Verdict struct {
	State  State
	Reason Reason
	// EligibleSince and EligibilityClass are the markers to store (both set or both empty).
	EligibleSince    time.Time
	EligibilityClass string
}

// Candidate reasons, in the order the gate checks them (DM-20.I4: the first check that fails).
const (
	ReasonNotSynced          Reason = "not_synced"
	ReasonCloudManaged       Reason = "cloud_managed"
	ReasonSIDMismatch        Reason = "sid_mismatch"
	ReasonDomainMismatch     Reason = "domain_mismatch"
	ReasonLinkUnconfirmed    Reason = "link_unconfirmed"
	ReasonAmbiguousAnchor    Reason = "ambiguous_anchor"
	ReasonTenantTakeoverOpen Reason = "tenant_takeover_open"
	ReasonReconfirmRequired  Reason = "reconfirm_required"
)

// Eligibility classes (I4(g)).
const (
	ClassInstallTime = "install_time"
	ClassAttested    = "attested"
	ClassLapsed      = "lapsed"
)

// Evaluate runs the DM-20.I4 gate (a)–(g) at time now. It fails closed: any input it cannot
// establish counts as a failed check, never a pass.
//
// Eligibility is (a)–(e). It is recorded the first time it holds (class from the connection's
// attestation at that moment) and never rewritten or cleared. State then follows the first failing
// check in the order a–g. A broken correlation never goes straight to matched (Lifecycle): when the
// objects match again it returns as a candidate for one cycle (no reason, no re-confirmation).
func Evaluate(in GateInput, now time.Time) Verdict {
	v := Verdict{}
	if in.Prior != nil {
		v.EligibleSince, v.EligibilityClass = in.Prior.EligibleSince, in.Prior.EligibilityClass
	}
	if in.SideGone {
		return keep(v, StateBroken, "")
	}
	// A group's SID is the match itself (I1b): a different SID means the group moved domain and the
	// correlation is broken until the Entra object carries the new one, never re-matched by name.
	sidOK := len(in.ADSID) > 0 && bytes.Equal(in.EntraSID, in.ADSID)
	if in.IsGroup && !sidOK {
		return keep(v, StateBroken, "")
	}

	reason := firstEligibilityFailure(in, sidOK)
	if reason == "" && v.EligibleSince.IsZero() {
		v.EligibleSince, v.EligibilityClass = now.UTC(), classNow(in)
	}
	if reason != "" {
		return keep(v, StateCandidate, reason)
	}
	// (f) the tenant blocks cloud-object takeover, as attested.
	if in.Takeover != TakeoverAttested {
		return keep(v, StateCandidate, ReasonTenantTakeoverOpen)
	}
	// (g) a re-confirmation is required while a cloud observation is newer than it, or the correlation
	// formed while an attestation had lapsed and was never re-confirmed.
	var rec time.Time
	if in.Prior != nil {
		rec = in.Prior.ReconfirmedAt
	}
	if (!in.CloudSeenAt.IsZero() && (rec.IsZero() || rec.Before(in.CloudSeenAt))) ||
		(v.EligibilityClass == ClassLapsed && rec.IsZero()) {
		return keep(v, StateCandidate, ReasonReconfirmRequired)
	}
	// A broken correlation never goes straight to matched (Lifecycle): it passes through candidate
	// for one cycle. This is a hold, not a re-confirmation: nothing is stored or asked of the owner,
	// and the next cycle matches if the checks still pass. The reason stays empty on purpose.
	if in.Prior != nil && in.Prior.State == StateBroken {
		return keep(v, StateCandidate, "")
	}
	return keep(v, StateMatched, "")
}

func keep(v Verdict, s State, r Reason) Verdict { v.State, v.Reason = s, r; return v }

// firstEligibilityFailure is the first failing check among (a)–(e), or "".
func firstEligibilityFailure(in GateInput, sidOK bool) Reason {
	switch {
	case in.EntraSyncEnabled == nil || !*in.EntraSyncEnabled:
		return ReasonNotSynced
	case in.EntraCloudManaged != nil && *in.EntraCloudManaged:
		return ReasonCloudManaged
	case !sidOK:
		return ReasonSIDMismatch
	case in.EntraDomainName != "" && !strings.EqualFold(strings.TrimSuffix(in.EntraDomainName, "."), strings.TrimSuffix(in.ADDomainName, ".")):
		return ReasonDomainMismatch
	case !in.LinkConfirmed:
		return ReasonLinkUnconfirmed
	case in.AnchorMatches != 1:
		return ReasonAmbiguousAnchor
	}
	return ""
}

// classNow is the eligibility class at the moment of first eligibility (I4(g)).
func classNow(in GateInput) string {
	switch {
	case in.FirstAttestedAt.IsZero():
		return ClassInstallTime
	case in.Takeover == TakeoverAttested:
		return ClassAttested
	}
	return ClassLapsed
}

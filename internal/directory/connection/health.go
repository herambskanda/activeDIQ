package connection

import (
	"context"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// HealthStatus is the one-word rights health of a connection (spec §8.1).
type HealthStatus string

// The rights health statuses. tier0_installation outranks the rest: while an override is in force the
// installation is Tier 0 whatever the latest run says (spec FR-14).
const (
	HealthUnknown   HealthStatus = "unknown"            // never verified
	HealthOK        HealthStatus = "ok"                 // the newest run passed with nothing to report
	HealthAttention HealthStatus = "needs_attention"    // excess or missing rights, or a run that did not pass
	HealthTier0     HealthStatus = "tier0_installation" // an override is in force: activeDIQ is Tier 0 in this forest
)

// RightsStaleAfter is 2× the 24 h ceiling on the rights check cadence (spec §8.1 rule 5): a rights
// row older than this is shown greyed as "not checked since", never as still passing.
const RightsStaleAfter = 48 * time.Hour

// OverrideSummary is what a health reader sees of an override in force: who and when, never the
// fingerprints (DM-24.I5).
type OverrideSummary struct {
	ID             Tier0OverrideID
	AcknowledgedBy string
	AcknowledgedAt time.Time
}

// Health is the API model of a connection's rights health. The counts are visible to every reader of
// the connection; the lists are filled only when the caller may see findings (FR-16).
type Health struct {
	ConnectionID       ID
	State              State
	Status             HealthStatus
	Tier0Installation  bool // the permanent banner: "activeDIQ is Tier 0 in this forest" (FR-14)
	Override           *OverrideSummary
	WriteGateOpen      bool // DM-10.I11
	LastVerificationID VerificationID
	Verdict            Verdict
	RightsCheckedAt    *time.Time
	RightsStale        bool
	ExcessiveCount     int
	MissingCount       int
	Excessive          []Finding // rights held that should not be (V7 block, V9 warn, Entra EV3/EV5)
	Missing            []Finding // rights an enabled family needs and the identity lacks (V8, EV4)
}

// isMissing splits a run's findings into the two halves the health check reports every run
// (TM-D1). Findings that are neither a right nor an answer (could_not_verify) belong to neither list;
// the outcome and verdict carry them.
func isMissing(f Finding) bool { return f.Kind == FindingMissingRight }

func isExcess(f Finding) bool {
	return f.Kind != FindingMissingRight && f.Kind != "could_not_verify" && f.Severity != SeverityInfo
}

// Health returns the rights health of a connection at time now. Everything is derived from the
// newest run and the override in force; nothing is stored (DM-25.I3).
func (Store) Health(ctx context.Context, tx store.Tx, id ID, withFindings bool, now time.Time) (Health, error) {
	c, err := Store{}.Get(ctx, tx, id)
	if err != nil {
		return Health{}, err
	}
	h := Health{ConnectionID: c.ID, State: c.State, Status: HealthUnknown}
	ov, err := overrideInForce(ctx, tx, c)
	if err != nil {
		return Health{}, err
	}
	if ov != nil {
		h.Tier0Installation, h.Status = true, HealthTier0
		h.Override = &OverrideSummary{ID: ov.ID, AcknowledgedBy: ov.AcknowledgedBy, AcknowledgedAt: ov.AcknowledgedAt}
	}
	if c.LastVerificationID == "" {
		return h, nil
	}
	v, err := getVerification(ctx, tx, c.ID, VerificationID(c.LastVerificationID), true)
	if err != nil {
		return Health{}, err
	}
	h.LastVerificationID, h.Verdict = v.ID, v.Verdict
	at := v.CompletedAt
	h.RightsCheckedAt, h.RightsStale = &at, now.Sub(at) > RightsStaleAfter
	h.WriteGateOpen = WriteGateOpen(c.Kind, &v, ov)
	for _, f := range v.Findings {
		switch {
		case isMissing(f):
			h.MissingCount++
			if withFindings {
				h.Missing = append(h.Missing, f)
			}
		case isExcess(f):
			h.ExcessiveCount++
			if withFindings {
				h.Excessive = append(h.Excessive, f)
			}
		}
	}
	if h.Status != HealthTier0 {
		if v.Verdict == VerdictPass && h.ExcessiveCount == 0 && h.MissingCount == 0 {
			h.Status = HealthOK
		} else {
			h.Status = HealthAttention
		}
	}
	return h, nil
}

// Health reads a connection's rights health. withFindings must be true only for an account that may
// start a verification on the connection.
func (r *Registry) Health(ctx context.Context, tid tenant.ID, id ID, withFindings bool, now time.Time) (h Health, err error) {
	err = r.with(ctx, tid, func(ctx context.Context, tx store.Tx) (e error) {
		h, e = r.s.Health(ctx, tx, id, withFindings, now)
		return
	})
	return h, err
}

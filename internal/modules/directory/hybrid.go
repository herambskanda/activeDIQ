package directory

import (
	"context"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/modules/directory/api"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// Correlations is the DM-20 read port the classifier needs. *inventory.Reader satisfies it.
type Correlations interface {
	CorrelationsFor(ctx context.Context, tid tenant.ID, ref inventory.Ref) (inventory.Correlations, error)
}

// Takeovers reads an Entra connection's derived takeover protection (DM-10.I7). *connection.Registry
// satisfies it.
type Takeovers interface {
	GetTakeover(ctx context.Context, tid tenant.ID, id connection.ID, now time.Time) (connection.Takeover, error)
}

// Classifier states how a directory user stands in the cross-directory correlation (TM-D17).
// It only reads: the same facts, and the same rule, as authz's hybrid gate, so what the response says
// a correlation can do is what the gate would let it do.
type Classifier struct {
	Corr      Correlations
	Takeovers Takeovers
	Now       func() time.Time
}

// Reasons added to the gate's own (authz.ReasonHybrid*). Stable codes, safe to show.
const (
	reasonFactsMissing = "hybrid_facts_missing"
	reasonNotEvaluated = "hybrid_not_evaluated"
)

func (c Classifier) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Classify classifies the user guid of connection conn. Any fact it cannot read makes the state
// unknown with no authority: it never answers not_hybrid for a user it could not check.
func (c Classifier) Classify(ctx context.Context, tid tenant.ID, conn connection.ID, guid string) api.HybridClassification {
	unknown := func(reason string) api.HybridClassification {
		return hybrid(api.HybridStateUnknown, false, reason)
	}
	if c.Corr == nil {
		return unknown(reasonNotEvaluated)
	}
	ref := inventory.Ref{Connection: inventory.ConnectionID(conn), Object: inventory.GUID(guid)}
	if !ref.Valid() {
		return unknown(reasonNotEvaluated)
	}
	cs, err := c.Corr.CorrelationsFor(ctx, tid, ref)
	if err != nil {
		return unknown(reasonNotEvaluated)
	}
	if len(cs.Links) == 0 {
		return hybrid(api.HybridStateNotHybrid, false, "")
	}
	// The strongest recorded state wins: matched, then candidate, then broken.
	var best *inventory.Link
	rank := func(s inventory.State) int {
		switch s {
		case inventory.StateMatched:
			return 3
		case inventory.StateCandidate:
			return 2
		case inventory.StateBroken:
			return 1
		}
		return 0
	}
	for i := range cs.Links {
		if rank(cs.Links[i].State) > 0 && (best == nil || rank(cs.Links[i].State) > rank(best.State)) {
			best = &cs.Links[i]
		}
	}
	if best == nil {
		return unknown(reasonNotEvaluated)
	}
	switch best.State {
	case inventory.StateCandidate:
		return hybrid(api.HybridStateCandidate, false, string(best.Reason))
	case inventory.StateBroken:
		return hybrid(api.HybridStateBroken, false, string(best.Reason))
	}
	// Matched: authority needs an evaluation with an as-of, tier0 facts with an as-of, neither side
	// tier0, and takeover protection attested on the Entra side (TM-D17 rules 2 and 4).
	if cs.EvaluatedAt.IsZero() || best.FactsAsOf.IsZero() {
		return hybrid(api.HybridStateMatched, false, reasonFactsMissing)
	}
	if best.SelfTier0 || best.PeerTier0 {
		return hybrid(api.HybridStateMatched, false, string(authz.ReasonHybridTier0))
	}
	entra := best.Peer.Connection
	if best.PeerKind == "ad_forest" {
		entra = best.Self.Connection
	}
	if c.Takeovers == nil {
		return hybrid(api.HybridStateMatched, false, string(authz.ReasonHybridUnattested))
	}
	tk, err := c.Takeovers.GetTakeover(ctx, tid, connection.ID(entra), c.now())
	if err != nil || string(tk.State) != authz.TakeoverAttested {
		return hybrid(api.HybridStateMatched, false, string(authz.ReasonHybridUnattested))
	}
	return hybrid(api.HybridStateMatched, true, "")
}

func hybrid(s api.HybridState, authority bool, reason string) api.HybridClassification {
	h := api.HybridClassification{State: s, CarriesAuthority: authority}
	if reason != "" {
		h.Reason = &reason
	}
	return h
}

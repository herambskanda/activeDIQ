package directory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/modules/directory"
	"github.com/skenzeriq/activediq/internal/modules/directory/api"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

const (
	adConn    = "11111111-1111-4111-8111-111111111111"
	entraConn = "22222222-2222-4222-8222-222222222222"
	userGUID  = "aaaaaaaa-0000-4000-8000-00000000000a"
	entraGUID = "bbbbbbbb-0000-4000-8000-00000000000b"
)

type corrFake struct {
	cs  inventory.Correlations
	err error
}

func (c corrFake) CorrelationsFor(context.Context, tenant.ID, inventory.Ref) (inventory.Correlations, error) {
	return c.cs, c.err
}

type takeFake struct {
	state connection.TakeoverProtection
	err   error
	asked connection.ID
}

func (f takeFake) GetTakeover(_ context.Context, _ tenant.ID, id connection.ID, _ time.Time) (connection.Takeover, error) {
	return connection.Takeover{State: f.state}, f.err
}

func link(state inventory.State, mod func(*inventory.Link)) inventory.Link {
	l := inventory.Link{Self: inventory.Ref{Connection: adConn, Object: userGUID}, Peer: inventory.Ref{Connection: entraConn, Object: entraGUID},
		State: state, PeerKind: "entra_tenant", FactsAsOf: time.Unix(1700000000, 0)}
	if mod != nil {
		mod(&l)
	}
	return l
}

func matchedLinks() inventory.Correlations {
	return inventory.Correlations{Links: []inventory.Link{link(inventory.StateMatched, nil)}, EvaluatedAt: time.Unix(1700000000, 0)}
}

func classify(c directory.Classifier) api.HybridClassification {
	return c.Classify(context.Background(), tenant.ID{}, adConn, userGUID)
}

func reason(h api.HybridClassification) string {
	if h.Reason == nil {
		return ""
	}
	return *h.Reason
}

func TestClassifier(t *testing.T) {
	attested := takeFake{state: connection.TakeoverAttested}
	tier0 := matchedLinks()
	tier0.Links[0].PeerTier0 = true
	noAsOf := matchedLinks()
	noAsOf.EvaluatedAt = time.Time{}
	noFacts := matchedLinks()
	noFacts.Links[0].FactsAsOf = time.Time{}
	mixed := inventory.Correlations{EvaluatedAt: time.Unix(1700000000, 0), Links: []inventory.Link{
		link(inventory.StateBroken, nil), link(inventory.StateCandidate, func(l *inventory.Link) { l.Reason = "not_synced" }), link(inventory.StateMatched, nil)}}
	adSide := inventory.Correlations{EvaluatedAt: time.Unix(1700000000, 0), Links: []inventory.Link{link(inventory.StateMatched, func(l *inventory.Link) {
		l.Self, l.Peer, l.PeerKind = inventory.Ref{Connection: entraConn, Object: entraGUID}, inventory.Ref{Connection: adConn, Object: userGUID}, "ad_forest"
	})}}
	cases := []struct {
		name  string
		c     directory.Classifier
		state api.HybridState
		auth  bool
		why   string
	}{
		{"no correlation", directory.Classifier{Corr: corrFake{}, Takeovers: attested}, api.HybridStateNotHybrid, false, ""},
		{"matched and attested", directory.Classifier{Corr: corrFake{cs: matchedLinks()}, Takeovers: attested}, api.HybridStateMatched, true, ""},
		{"matched from the entra side's link", directory.Classifier{Corr: corrFake{cs: adSide}, Takeovers: attested}, api.HybridStateMatched, true, ""},
		{"strongest wins", directory.Classifier{Corr: corrFake{cs: mixed}, Takeovers: attested}, api.HybridStateMatched, true, ""},
		{"candidate keeps its reason", directory.Classifier{Corr: corrFake{cs: inventory.Correlations{Links: []inventory.Link{link(inventory.StateCandidate, func(l *inventory.Link) { l.Reason = "cloud_managed" })}}}, Takeovers: attested}, api.HybridStateCandidate, false, "cloud_managed"},
		{"broken", directory.Classifier{Corr: corrFake{cs: inventory.Correlations{Links: []inventory.Link{link(inventory.StateBroken, nil)}}}, Takeovers: attested}, api.HybridStateBroken, false, ""},
		{"takeover open", directory.Classifier{Corr: corrFake{cs: matchedLinks()}, Takeovers: takeFake{state: connection.TakeoverOpen}}, api.HybridStateMatched, false, "hybrid_takeover_not_attested"},
		{"takeover unreadable", directory.Classifier{Corr: corrFake{cs: matchedLinks()}, Takeovers: takeFake{err: errors.New("db")}}, api.HybridStateMatched, false, "hybrid_takeover_not_attested"},
		{"no takeover source", directory.Classifier{Corr: corrFake{cs: matchedLinks()}}, api.HybridStateMatched, false, "hybrid_takeover_not_attested"},
		{"tier0 peer", directory.Classifier{Corr: corrFake{cs: tier0}, Takeovers: attested}, api.HybridStateMatched, false, "hybrid_correlation_tier0"},
		{"no evaluation as-of", directory.Classifier{Corr: corrFake{cs: noAsOf}, Takeovers: attested}, api.HybridStateMatched, false, "hybrid_facts_missing"},
		{"no tier0 facts as-of", directory.Classifier{Corr: corrFake{cs: noFacts}, Takeovers: attested}, api.HybridStateMatched, false, "hybrid_facts_missing"},
		{"read fails", directory.Classifier{Corr: corrFake{err: errors.New("db")}, Takeovers: attested}, api.HybridStateUnknown, false, "hybrid_not_evaluated"},
		{"no source", directory.Classifier{}, api.HybridStateUnknown, false, "hybrid_not_evaluated"},
		{"removed link only", directory.Classifier{Corr: corrFake{cs: inventory.Correlations{Links: []inventory.Link{link(inventory.StateRemoved, nil)}}}, Takeovers: attested}, api.HybridStateUnknown, false, "hybrid_not_evaluated"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classify(tc.c)
			if got.State != tc.state || got.CarriesAuthority != tc.auth || reason(got) != tc.why {
				t.Fatalf("got state=%s authority=%v reason=%q, want %s %v %q", got.State, got.CarriesAuthority, reason(got), tc.state, tc.auth, tc.why)
			}
		})
	}
}

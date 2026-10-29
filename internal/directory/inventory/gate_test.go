package inventory_test

import (
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
)

var (
	t0   = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	t1   = t0.Add(24 * time.Hour)
	yes  = true
	no   = false
	asid = []byte{1, 1, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 7, 0, 0, 0}
)

// good is an input that passes (a)–(g) for an attested tenant.
func good() inventory.GateInput {
	return inventory.GateInput{
		EntraSyncEnabled: &yes, EntraCloudManaged: &no, EntraSID: asid, ADSID: asid,
		EntraDomainName: "Corp.Example.com", ADDomainName: "corp.example.com", LinkConfirmed: true,
		AnchorMatches: 1, Takeover: inventory.TakeoverAttested, FirstAttestedAt: t0,
	}
}

// DM-20.I4: matched only when (a)-(g) all pass; otherwise candidate naming the first failing check.
func TestGateFirstFailingCheck(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*inventory.GateInput)
		state  inventory.State
		reason inventory.Reason
	}{
		{"all pass", func(*inventory.GateInput) {}, inventory.StateMatched, ""},
		{"a null", func(g *inventory.GateInput) { g.EntraSyncEnabled = nil }, inventory.StateCandidate, inventory.ReasonNotSynced},
		{"a false", func(g *inventory.GateInput) { g.EntraSyncEnabled = &no }, inventory.StateCandidate, inventory.ReasonNotSynced},
		{"b cloud managed", func(g *inventory.GateInput) { g.EntraCloudManaged = &yes }, inventory.StateCandidate, inventory.ReasonCloudManaged},
		{"b unreadable, a decides", func(g *inventory.GateInput) { g.EntraCloudManaged = nil }, inventory.StateMatched, ""},
		{"c user SID differs", func(g *inventory.GateInput) { g.EntraSID = []byte{9, 9, 9, 9, 9, 9, 9, 9} }, inventory.StateCandidate, inventory.ReasonSIDMismatch},
		{"c user SID absent (Cloud Sync)", func(g *inventory.GateInput) { g.EntraSID = nil }, inventory.StateCandidate, inventory.ReasonSIDMismatch},
		{"c AD SID unknown fails closed", func(g *inventory.GateInput) { g.ADSID, g.EntraSID = nil, nil }, inventory.StateCandidate, inventory.ReasonSIDMismatch},
		{"d domain differs", func(g *inventory.GateInput) { g.EntraDomainName = "other.example.com" }, inventory.StateCandidate, inventory.ReasonDomainMismatch},
		{"d domain empty is not checked", func(g *inventory.GateInput) { g.EntraDomainName = "" }, inventory.StateMatched, ""},
		{"d link unconfirmed", func(g *inventory.GateInput) { g.LinkConfirmed = false }, inventory.StateCandidate, inventory.ReasonLinkUnconfirmed},
		{"e anchor matches two", func(g *inventory.GateInput) { g.AnchorMatches = 2 }, inventory.StateCandidate, inventory.ReasonAmbiguousAnchor},
		{"e anchor matches none", func(g *inventory.GateInput) { g.AnchorMatches = 0 }, inventory.StateCandidate, inventory.ReasonAmbiguousAnchor},
		{"f open", func(g *inventory.GateInput) { g.Takeover = inventory.TakeoverOpen }, inventory.StateCandidate, inventory.ReasonTenantTakeoverOpen},
		{"f unset fails closed", func(g *inventory.GateInput) { g.Takeover = "" }, inventory.StateCandidate, inventory.ReasonTenantTakeoverOpen},
		{"order: a before f", func(g *inventory.GateInput) { g.EntraSyncEnabled = nil; g.Takeover = inventory.TakeoverOpen }, inventory.StateCandidate, inventory.ReasonNotSynced},
		{"order: c before e", func(g *inventory.GateInput) { g.EntraSID = nil; g.AnchorMatches = 3 }, inventory.StateCandidate, inventory.ReasonSIDMismatch},
		{"g cloud seen, never reconfirmed", func(g *inventory.GateInput) { g.CloudSeenAt = t0 }, inventory.StateCandidate, inventory.ReasonReconfirmRequired},
		{"group SID differs: broken, not re-matched", func(g *inventory.GateInput) { g.IsGroup = true; g.EntraSID = []byte{9, 9, 9, 9, 9, 9, 9, 9} }, inventory.StateBroken, ""},
		{"side purged", func(g *inventory.GateInput) { g.SideGone = true }, inventory.StateBroken, ""},
	}
	for _, c := range cases {
		in := good()
		c.mutate(&in)
		v := inventory.Evaluate(in, t1)
		if v.State != c.state || v.Reason != c.reason {
			t.Errorf("%s: got %s/%q, want %s/%q", c.name, v.State, v.Reason, c.state, c.reason)
		}
	}
}

// I4(g): eligibility is set once with the class of the moment, and survives a failing gate.
func TestGateEligibilityClassAndMarkers(t *testing.T) {
	// Install time: no attestation yet. Candidate, but eligible and recorded.
	in := good()
	in.FirstAttestedAt, in.Takeover = time.Time{}, inventory.TakeoverOpen
	v := inventory.Evaluate(in, t0)
	if v.State != inventory.StateCandidate || v.Reason != inventory.ReasonTenantTakeoverOpen || v.EligibilityClass != "install_time" || !v.EligibleSince.Equal(t0) {
		t.Fatalf("install: %+v", v)
	}
	// First attestation arrives: matched with no re-confirmation; markers unchanged.
	in = good()
	in.Prior = &inventory.Prior{State: inventory.StateCandidate, EligibleSince: v.EligibleSince, EligibilityClass: v.EligibilityClass}
	if v2 := inventory.Evaluate(in, t1); v2.State != inventory.StateMatched || v2.EligibilityClass != "install_time" || !v2.EligibleSince.Equal(t0) {
		t.Fatalf("after attestation: %+v", v2)
	}
	// Attested at the moment of first eligibility.
	if v3 := inventory.Evaluate(good(), t1); v3.EligibilityClass != "attested" || v3.State != inventory.StateMatched {
		t.Fatalf("attested: %+v", v3)
	}
	// Lapsed: first attested earlier, now open. Not matched; and when attestation returns it still needs a re-confirmation.
	in = good()
	in.Takeover = inventory.TakeoverStale
	v4 := inventory.Evaluate(in, t0)
	if v4.EligibilityClass != "lapsed" {
		t.Fatalf("lapsed: %+v", v4)
	}
	in = good()
	in.Prior = &inventory.Prior{State: inventory.StateCandidate, EligibleSince: v4.EligibleSince, EligibilityClass: "lapsed"}
	if v5 := inventory.Evaluate(in, t1); v5.State != inventory.StateCandidate || v5.Reason != inventory.ReasonReconfirmRequired {
		t.Fatalf("lapsed, attested again: %+v", v5)
	}
	in.Prior.ReconfirmedAt = t1
	if v6 := inventory.Evaluate(in, t1); v6.State != inventory.StateMatched {
		t.Fatalf("lapsed, reconfirmed: %+v", v6)
	}
	// A cloud observation newer than the re-confirmation requires a new one.
	in.CloudSeenAt = t1.Add(time.Hour)
	if v7 := inventory.Evaluate(in, t1); v7.Reason != inventory.ReasonReconfirmRequired {
		t.Fatalf("cloud seen after reconfirm: %+v", v7)
	}
	// Eligibility only goes down: the markers survive a failing gate and are never rewritten.
	in = good()
	in.EntraSyncEnabled = nil
	in.Prior = &inventory.Prior{State: inventory.StateMatched, EligibleSince: t0, EligibilityClass: "install_time"}
	if v8 := inventory.Evaluate(in, t1); v8.State != inventory.StateCandidate || !v8.EligibleSince.Equal(t0) || v8.EligibilityClass != "install_time" {
		t.Fatalf("markers lost: %+v", v8)
	}
	// Broken keeps the markers and returns only to candidate, never straight to matched.
	in = good()
	in.Prior = &inventory.Prior{State: inventory.StateBroken, EligibleSince: t0, EligibilityClass: "attested"}
	if v9 := inventory.Evaluate(in, t1); v9.State != inventory.StateCandidate || v9.EligibleSince != t0 {
		t.Fatalf("broken re-form: %+v", v9)
	}
	// The hold is one cycle and asks nothing of the owner: no reason, and the next cycle matches.
	if v9 := inventory.Evaluate(in, t1); v9.Reason != "" {
		t.Fatalf("broken hold carries a reason: %+v", v9)
	}
	in.Prior = &inventory.Prior{State: inventory.StateCandidate, EligibleSince: t0, EligibilityClass: "attested"}
	if v10 := inventory.Evaluate(in, t1); v10.State != inventory.StateMatched {
		t.Fatalf("second cycle after broken: %+v", v10)
	}
}

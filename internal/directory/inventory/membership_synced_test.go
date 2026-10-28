package inventory_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/authn"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

// The nine TM-F-AUTHZ cases of threat-model §7.7 (TM-D18 extension, D18-1 and D18-2).
var (
	t3 = t2.Add(time.Hour)
	t4 = t3.Add(time.Hour)
)

const (
	sUser  = "eeeeeeee-0000-4000-8000-0000000000d1"
	sEG    = "eeeeeeee-0000-4000-8000-0000000000d2" // the synced Entra group
	sEG2   = "eeeeeeee-0000-4000-8000-0000000000d3"
	sOuter = "eeeeeeee-0000-4000-8000-0000000000d4"
	sADG   = "aaaaaaaa-0000-4000-8000-0000000000d2" // its AD source
)

var sidG = []byte{1, 1, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 9, 9, 0, 0}

// adSrc is an AD security group with an optional fact. computed is when the fact was computed.
func adSrc(g string, broad any, computed time.Time) inventory.Observation {
	o := adGroup(g, -2147483646, broad)
	o.SID = sidG
	if !computed.IsZero() {
		o.Attributes[inventory.AttrBroadMembershipWriteAt] = computed.UTC().Format(time.RFC3339)
	}
	return o
}

// syncedGroup is an Entra group Graph reports as synced from sidG.
func syncedGroup(g string, members ...string) inventory.Observation {
	o := enGroup(g, true, "", members...)
	yes := true
	o.Attributes[inventory.AttrOnPremisesSyncEnabled] = true
	o.OnPremisesSyncEnabled = &yes
	o.OnPremisesSID = sidG
	return o
}

type synced struct {
	*env
	t *testing.T
}

// pair seeds the matched correlation of sEG with sADG and a completed evaluation.
func (s synced) pair(state, reason string, tier0 bool, asOf time.Time) {
	s.t.Helper()
	if state == "candidate" {
		s.seed(s.t, s.a, inventory.Ref{Connection: s.adA, Object: sADG}, inventory.Ref{Connection: s.enA, Object: sEG},
			state, reason, "match, ad_sid, facts_as_of", "sid", sidG, asOf)
	} else if tier0 {
		s.seed(s.t, s.a, inventory.Ref{Connection: s.adA, Object: sADG}, inventory.Ref{Connection: s.enA, Object: sEG},
			state, reason, "match, ad_sid, ad_tier0, ad_tier0_bases, facts_as_of", "sid", sidG, true, []string{"C16"}, asOf)
	} else {
		s.seed(s.t, s.a, inventory.Ref{Connection: s.adA, Object: sADG}, inventory.Ref{Connection: s.enA, Object: sEG},
			state, reason, "match, ad_sid, facts_as_of", "sid", sidG, asOf)
	}
	if err := s.exec(s.a, `INSERT INTO public.correlation_evaluations (tenant_id, connection_id, evaluated_at) VALUES ($1::uuid, $2::uuid, $3)`,
		s.a.String(), string(s.enA), asOf); err != nil {
		s.t.Fatal(err)
	}
}

func (s synced) groups(takeover string) authz.Groups {
	s.t.Helper()
	g, err := s.membership(inventory.Ref{Connection: s.enA, Object: sUser}, authn.KindSSO, takeover).GroupsOf(context.Background(), s.a.String(), mAcct)
	if err != nil {
		s.t.Fatal(err)
	}
	return g
}

func (s synced) want(label string, g authz.Groups, complete bool, guids_ ...string) {
	s.t.Helper()
	got := guids(g)
	slices.Sort(guids_)
	if g.Complete != complete || !slices.Equal(got, guids_) {
		s.t.Fatalf("%s: got %v complete=%v, want %v complete=%v", label, got, g.Complete, guids_, complete)
	}
}

func (s synced) populate_(c inventory.ConnectionID, at time.Time, obs ...inventory.Observation) {
	s.t.Helper()
	if _, err := s.populate(s.t, c, at, obs...); err != nil {
		s.t.Fatal(err)
	}
}

func run(t *testing.T, f func(s synced)) {
	storetest.EachVersion(t, func(t *testing.T, srv *storetest.Server) { f(synced{setup(t, srv), t}) })
}

func TestMembership_synced_weak_good_and_flip(t *testing.T) { // cases 1 and 3
	run(t, func(s synced) {
		now := time.Now()
		s.populate_(s.enA, t1, enUser(sUser, nil), syncedGroup(sEG, sUser))
		s.populate_(s.adA, t1, adSrc(sADG, true, now))
		s.pair("matched", "", false, now)
		// synced-weak: the AD source is open to a broad principal, whatever the Entra copy says.
		s.want("weak", s.groups("attested"), true)
		// synced-good, then the fact flips to true.
		s.populate_(s.adA, t2, adSrc(sADG, false, now))
		s.want("good", s.groups("attested"), true, sEG)
		s.populate_(s.adA, t3, adSrc(sADG, true, now))
		s.want("flipped", s.groups("attested"), true)
	})
}

func TestMembership_synced_unknown(t *testing.T) { // case 2
	now := time.Now()
	for _, tc := range []struct {
		name     string
		adFact   any
		computed time.Time
		noAD     bool
		state    string
		takeover string
		asOf     time.Time
	}{
		{"no fact", nil, now, false, "matched", "attested", now},
		{"fact without computed_at", false, time.Time{}, false, "matched", "attested", now},
		{"AD group absent", false, now, true, "matched", "attested", now},
		{"candidate", false, now, false, "candidate", "attested", now},
		{"broken", false, now, false, "broken", "attested", now},
		{"takeover not attested", false, now, false, "matched", "open", now},
		{"takeover unknown", false, now, false, "matched", "", now},
		{"pair older than 26h (evaluation)", false, now, false, "matched", "attested", now.Add(-27 * time.Hour)},
		{"pair older than 26h (fact)", false, now.Add(-27 * time.Hour), false, "matched", "attested", now},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run(t, func(s synced) {
				reason := ""
				if tc.state == "candidate" {
					reason = "sid_mismatch"
				}
				s.populate_(s.enA, t1, enUser(sUser, nil), syncedGroup(sEG, sUser))
				if !tc.noAD {
					s.populate_(s.adA, t1, adSrc(sADG, tc.adFact, tc.computed))
				}
				s.pair(tc.state, reason, false, tc.asOf)
				s.want(tc.name, s.groups(tc.takeover), false)
			})
		})
	}
}

func TestMembership_synced_tier0(t *testing.T) { // case 4
	run(t, func(s synced) {
		now := time.Now()
		s.populate_(s.enA, t1, enUser(sUser, nil), syncedGroup(sEG, sUser))
		s.populate_(s.adA, t1, adSrc(sADG, false, now))
		s.pair("matched", "", true, now)
		s.want("tier0", s.groups("attested"), true)
	})
}

func TestMembership_sync_flag(t *testing.T) { // case 5
	run(t, func(s synced) {
		g := enGroup(sEG, true, "", sUser)
		delete(g.Attributes, inventory.AttrOnPremisesSyncEnabled) // not read
		s.populate_(s.enA, t1, enUser(sUser, nil), g)
		s.want("absent", s.groups("attested"), false)
		g.Attributes[inventory.AttrOnPremisesSyncEnabled] = nil
		s.populate_(s.enA, t2, g)
		s.want("null", s.groups("attested"), true, sEG)
		g.Attributes[inventory.AttrOnPremisesSyncEnabled] = false
		s.populate_(s.enA, t3, g)
		s.want("false", s.groups("attested"), true, sEG)
	})
}

func TestMembership_synced_nest(t *testing.T) { // case 6
	run(t, func(s synced) {
		now := time.Now()
		outer := enGroup(sOuter, true, "Private", sEG)
		s.populate_(s.enA, t1, enUser(sUser, nil), syncedGroup(sEG, sUser), outer)
		s.populate_(s.adA, t1, adSrc(sADG, true, now))
		s.pair("matched", "", false, now)
		s.want("nest", s.groups("attested"), true) // not walked through the weak one
		s.populate_(s.adA, t2, adSrc(sADG, false, now))
		s.want("nest good", s.groups("attested"), true, sEG, sOuter)
	})
}

func TestMembership_forged_peer(t *testing.T) { // case 7
	t.Run("two Entra groups share one SID", func(t *testing.T) {
		run(t, func(s synced) {
			now := time.Now()
			s.populate_(s.enA, t1, enUser(sUser, nil), syncedGroup(sEG, sUser), syncedGroup(sEG2, sUser))
			s.populate_(s.adA, t1, adSrc(sADG, false, now))
			s.pair("matched", "", false, now)
			s.want("shared SID", s.groups("attested"), false)
		})
	})
	t.Run("claimed SID is not the matched source's", func(t *testing.T) {
		run(t, func(s synced) {
			now := time.Now()
			forged := syncedGroup(sEG, sUser)
			forged.OnPremisesSID = []byte{1, 1, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 7, 7, 0, 0} // another forest's group
			s.populate_(s.enA, t1, enUser(sUser, nil), forged)
			s.populate_(s.adA, t1, adSrc(sADG, false, now))
			s.pair("matched", "", false, now)
			s.want("other SID", s.groups("attested"), false)
		})
	})
}

func TestMembership_dynamic(t *testing.T) { // cases 8 and 9
	run(t, func(s synced) {
		dyn := func(g string, extra map[string]any, members ...string) inventory.Observation {
			o := enGroup(g, true, "Private", members...)
			o.Attributes[inventory.AttrGroupTypes] = []string{"DynamicMembership"}
			o.Attributes["membershipRule"] = `user.department -eq "IT"`
			for k, v := range extra {
				o.Attributes[k] = v
			}
			return o
		}
		s.populate_(s.enA, t1, enUser(sUser, nil), dyn(sEG, nil, sUser))
		s.want("dynamic", s.groups("attested"), true)
		s.populate_(s.enA, t2, dyn(sEG, map[string]any{"membershipRuleProcessingState": "Paused"}, sUser))
		s.want("paused", s.groups("attested"), true)
		// Nested: the dynamic group inside an eligible group, and an eligible group inside the dynamic one.
		s.populate_(s.enA, t3, enGroup(sOuter, true, "Private", sUser, sEG2), dyn(sEG, nil, sUser, sOuter), enGroup(sEG2, true, "Private"))
		g := s.groups("attested")
		if slices.Contains(guids(g), sEG) {
			t.Fatalf("dynamic group granted: %v", guids(g))
		}
		// groupTypes unreadable: unknown.
		bad := enGroup(sEG, true, "Private", sUser)
		delete(bad.Attributes, inventory.AttrGroupTypes)
		s.populate_(s.enA, t4, enUser(sUser, nil), bad)
		if g := s.groups("attested"); g.Complete || slices.Contains(guids(g), sEG) {
			t.Fatalf("groupTypes absent: %v complete=%v", guids(g), g.Complete)
		}
	})
}

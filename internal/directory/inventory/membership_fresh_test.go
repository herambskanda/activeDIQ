package inventory_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/authn"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

// R-D18-1: a direct AD group's "not broad" fact grants only while its computed-at is fresh.
func TestMembership_direct_AD_fact_freshness(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name string
		at   any // stored computed-at; nil removes the key
		want bool
	}{
		{"fresh", now.UTC().Format(time.RFC3339), true},
		{"absent", nil, false},
		{"unparseable", "yesterday", false},
		{"not a string", 42, false},
		{"older than 26h", now.Add(-27 * time.Hour).UTC().Format(time.RFC3339), false},
		{"40 days old", now.Add(-40 * 24 * time.Hour).UTC().Format(time.RFC3339), false},
		{"beyond future skew", now.Add(10 * time.Minute).UTC().Format(time.RFC3339), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
				e := setup(t, s)
				if _, err := e.populate(t, e.adA, t1, adUser(mUser, nc1), adGroup(mSec, -2147483646, false, mUser)); err != nil {
					t.Fatal(err)
				}
				syn := synced{e, t}
				if tc.at == nil {
					if err := e.exec(e.a, `UPDATE public.directory_objects SET attributes = attributes - $3 WHERE tenant_id = $1::uuid AND connection_id = $2::uuid`,
						e.a.String(), string(e.adA), inventory.AttrBroadMembershipWriteAt); err != nil {
						t.Fatal(err)
					}
				} else {
					syn.setAttr(mSec, e.adA, inventory.AttrBroadMembershipWriteAt, tc.at)
				}
				g, err := e.membership(inventory.Ref{Connection: e.adA, Object: mUser}, authn.KindDirectory, "").GroupsOf(context.Background(), e.a.String(), mAcct)
				if err != nil {
					t.Fatal(err)
				}
				got := slices.Contains(guids(g), mSec)
				if got != tc.want || g.Complete != tc.want {
					t.Fatalf("granted=%v complete=%v, want both %v", got, g.Complete, tc.want)
				}
			})
		})
	}
}

// Judge keys enter only through the typed fields (acceptance 2).
func TestPopulate_refuses_judge_keys_in_attributes(t *testing.T) {
	keys := []string{inventory.AttrGroupType, inventory.AttrSecurityEnabled, inventory.AttrVisibility, inventory.AttrGroupTypes,
		inventory.AttrBroadMembershipWrite, inventory.AttrWrittenBack, inventory.AttrBroadMembershipWriteAt, inventory.AttrOnPremisesSyncEnabled, "GROUPTYPE", "Diq_BroadMembershipWrite"}
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		for _, k := range keys {
			g := adGroup(mSec, -2147483646, false)
			g.Attributes = map[string]any{k: true}
			if _, err := e.populate(t, e.adA, t1, g); !errors.Is(err, inventory.ErrInvalid) {
				t.Errorf("key %q: err=%v, want ErrInvalid", k, err)
			}
		}
		if n := e.count(t, `SELECT count(*) FROM public.directory_objects`); n != 0 {
			t.Fatalf("%d rows stored from refused batches", n)
		}
	})
}

func TestPopulate_refuses_inconsistent_facts(t *testing.T) {
	yes := true
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		for name, tc := range map[string]struct {
			c   inventory.ConnectionID
			obs func() inventory.Observation
		}{
			"fact without computed-at": {e.adA, func() inventory.Observation {
				g := adGroup(mSec, -2147483646, false)
				g.Facts.BroadMembershipWriteAt = time.Time{}
				return g
			}},
			"computed-at without fact": {e.adA, func() inventory.Observation {
				g := adGroup(mSec, -2147483646, nil)
				g.Facts.BroadMembershipWriteAt = time.Now()
				return g
			}},
			"entra fact on AD group": {e.adA, func() inventory.Observation {
				g := adGroup(mSec, -2147483646, false)
				g.Facts.SecurityEnabled = &yes
				return g
			}},
			"AD fact on Entra group": {e.enA, func() inventory.Observation {
				g := enGroup(mEPriv, true, "Private")
				g.Facts.WrittenBack = &yes
				return g
			}},
			"sync enabled without Read": {e.enA, func() inventory.Observation {
				g := enGroup(mEPriv, true, "Private")
				g.OnPremisesSyncEnabled, g.OnPremisesSyncEnabledRead = &yes, false
				return g
			}},
		} {
			if _, err := e.populate(t, tc.c, t1, tc.obs()); !errors.Is(err, inventory.ErrInvalid) {
				t.Errorf("%s: err=%v, want ErrInvalid", name, err)
			}
		}
	})
}

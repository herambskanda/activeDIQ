package inventory_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/authn"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

func ptr[T any](v T) *T { return &v }

// typedAD is an AD security group carrying only typed producer fields (no Attributes map).
func typedAD(g string, broad bool, at time.Time, members ...string) inventory.Observation {
	o := inventory.Observation{Object: inventory.GUID(g), NC: nc1, Kind: inventory.KindGroup, Class: "group", State: inventory.ObjLive,
		Facts: inventory.GroupFacts{GroupType: ptr(int32(-2147483646)), BroadMembershipWrite: &broad, BroadMembershipWriteAt: at, WrittenBack: ptr(false)}, MembersComplete: true}
	for _, m := range members {
		o.Members = append(o.Members, inventory.GUID(m))
	}
	return o
}

func typedEntra(g string, syncRead bool, visibility *string, groupTypes []string, members ...string) inventory.Observation {
	o := inventory.Observation{Object: inventory.GUID(g), Kind: inventory.KindGroup, Class: "group", State: inventory.ObjActive,
		Facts: inventory.GroupFacts{GroupTypes: groupTypes, SecurityEnabled: ptr(true)}, OnPremisesSyncRead: syncRead, MembersComplete: true}
	if visibility != nil {
		o.Facts.Visibility = *visibility
	}
	for _, m := range members {
		o.Members = append(o.Members, inventory.GUID(m))
	}
	return o
}

func (e *env) attrs(t *testing.T, c inventory.ConnectionID, g string) (attrs string, col *bool) {
	t.Helper()
	err := e.db.WithTenant(context.Background(), e.a, func(ctx context.Context, tx store.Tx) error {
		return tx.QueryRow(ctx, `SELECT attributes::jsonb::text, on_prem_sync_enabled FROM public.directory_objects
			WHERE connection_id = $1::uuid AND object_guid = $2::uuid`, string(c), g).Scan(&attrs, &col)
	})
	if err != nil {
		t.Fatal(err)
	}
	attrs = strings.NewReplacer(": ", ":", ", ", ",").Replace(attrs)
	return
}

func TestGroupFacts_stored_together(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		at := t1.Add(-time.Hour).In(time.FixedZone("x", 3600)) // computed before the cycle, non-UTC input
		if _, err := e.populate(t, e.adA, t1, typedAD(sADG, false, at)); err != nil {
			t.Fatal(err)
		}
		a, _ := e.attrs(t, e.adA, sADG)
		for _, want := range []string{`"groupType":-2147483646`, `"diq_broadMembershipWrite":false`,
			`"diq_broadMembershipWriteComputedAt":"` + at.UTC().Format(time.RFC3339) + `"`, `"diq_writtenBack":false`} {
			if !strings.Contains(a, want) {
				t.Fatalf("attributes %s lack %s", a, want)
			}
		}
		// Entra: never synced is JSON null, typed column NULL; an unread key is absent.
		if _, err := e.populate(t, e.enA, t1, typedEntra(sEG, true, nil, []string{}), typedEntra(sEG2, false, ptr("Private"), []string{"Unified"})); err != nil {
			t.Fatal(err)
		}
		a, col := e.attrs(t, e.enA, sEG)
		if !strings.Contains(a, `"onPremisesSyncEnabled":null`) || !strings.Contains(a, `"groupTypes":[]`) || !strings.Contains(a, `"securityEnabled":true`) || col != nil {
			t.Fatalf("never synced: %s col=%v", a, col)
		}
		a, _ = e.attrs(t, e.enA, sEG2)
		if strings.Contains(a, "onPremisesSyncEnabled") || !strings.Contains(a, `"visibility":"Private"`) || !strings.Contains(a, `"groupTypes":["Unified"]`) {
			t.Fatalf("unread: %s", a)
		}
		// Synced: true in the attributes and the typed column and on_prem_sid.
		g := typedEntra(sOuter, true, nil, []string{})
		g.OnPremisesSyncEnabled, g.OnPremisesSID = ptr(true), sidG
		if _, err := e.populate(t, e.enA, t1, g); err != nil {
			t.Fatal(err)
		}
		a, col = e.attrs(t, e.enA, sOuter)
		if !strings.Contains(a, `"onPremisesSyncEnabled":true`) || col == nil || !*col {
			t.Fatalf("synced: %s col=%v", a, col)
		}
	})
}

func TestGroupFacts_refused(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		now := t1.Add(-time.Hour)
		fact := typedAD(sADG, false, now)
		noAt := typedAD(sADG, false, now)
		noAt.Facts.BroadMembershipWriteAt = time.Time{}
		atOnly := typedAD(sADG, false, now)
		atOnly.Facts.BroadMembershipWrite = nil
		clash := typedAD(sADG, false, now)
		clash.Attributes = map[string]any{inventory.AttrBroadMembershipWrite: true}
		user := inventory.Observation{Object: mUser, NC: nc1, Kind: inventory.KindUser, Class: "user", State: inventory.ObjLive, Facts: inventory.GroupFacts{GroupType: ptr(int32(2))}}
		for name, o := range map[string]inventory.Observation{"fact without time": noAt, "time without fact": atOnly,
			"typed and map": clash, "on a user": user} {
			if _, err := e.populate(t, e.adA, t1, o); !errors.Is(err, inventory.ErrInvalid) {
				t.Fatalf("%s: err = %v, want ErrInvalid", name, err)
			}
		}
		if _, err := e.populate(t, e.enA, t1, fact); !errors.Is(err, inventory.ErrInvalid) {
			t.Fatalf("AD fact on Entra: %v", err)
		}
		if _, err := e.populate(t, e.adA, t1, typedEntra(sEG, true, nil, []string{})); !errors.Is(err, inventory.ErrInvalid) {
			t.Fatalf("Entra fact on AD: %v", err)
		}
	})
}

// AC4: a fixture produced only through the typed fields reaches the expected verdicts.
func TestGroupFacts_judge_verdicts(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		ctx := context.Background()
		const adOpen, adClosed, enPriv, enPub, enDyn = "aaaaaaaa-0000-4000-8000-0000000000f1", "aaaaaaaa-0000-4000-8000-0000000000f2",
			"eeeeeeee-0000-4000-8000-0000000000f1", "eeeeeeee-0000-4000-8000-0000000000f2", "eeeeeeee-0000-4000-8000-0000000000f3"
		obs := time.Now() // the judge checks the fact's age against the wall clock
		now := obs.Add(-time.Hour)
		if _, err := e.populate(t, e.adA, obs, adUser(mUser, nc1), typedAD(adOpen, true, now, mUser), typedAD(adClosed, false, now, mUser)); err != nil {
			t.Fatal(err)
		}
		if _, err := e.populate(t, e.enA, t1, enUser(mEUser, nil),
			typedEntra(enPriv, true, ptr("Private"), []string{}, mEUser),
			typedEntra(enPub, true, ptr("Public"), []string{"Unified"}, mEUser),
			typedEntra(enDyn, true, ptr("Private"), []string{"DynamicMembership"}, mEUser)); err != nil {
			t.Fatal(err)
		}
		g, err := e.membership(inventory.Ref{Connection: e.adA, Object: mUser}, authn.KindDirectory, "").GroupsOf(ctx, e.a.String(), mAcct)
		if err != nil || !g.Complete || len(g.Groups) != 1 || g.Groups[0].GUID != adClosed {
			t.Fatalf("AD: %+v complete=%v err=%v, want only the closed group", g.Groups, g.Complete, err)
		}
		g, err = e.membership(inventory.Ref{Connection: e.enA, Object: mEUser}, authn.KindSSO, "").GroupsOf(ctx, e.a.String(), mAcct)
		if err != nil || !g.Complete || len(g.Groups) != 1 || g.Groups[0].GUID != enPriv {
			t.Fatalf("Entra: %+v complete=%v err=%v, want only the private security group", g.Groups, g.Complete, err)
		}
	})
}

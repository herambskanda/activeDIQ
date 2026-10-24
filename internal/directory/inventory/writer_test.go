package inventory_test

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

var w inventory.Writer

func (e *env) tx(t *testing.T, tid tenant.ID, fn func(ctx context.Context, tx store.Tx) error) error {
	t.Helper()
	return e.db.WithTenant(context.Background(), tid, fn)
}

func formation(e *env, ad, en string) inventory.Formation {
	g := good()
	g.FirstAttestedAt = time.Time{}
	return inventory.Formation{
		AD:    inventory.Ref{Connection: e.adA, Object: inventory.GUID(ad)},
		Entra: inventory.Ref{Connection: e.enA, Object: inventory.GUID(en)},
		Match: inventory.MatchAnchor, AnchorAttr: "ms-DS-ConsistencyGuid", AnchorValue: anchor,
		Gate: g, Now: t1,
	}
}

func (e *env) form(t *testing.T, f inventory.Formation) (inventory.Formed, error) {
	t.Helper()
	var out inventory.Formed
	err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) (err error) { out, err = w.Form(ctx, tx, f); return })
	return out, err
}

// Acceptance 1: the writer forms matched only when the gate passes, stores the candidate reason
// otherwise, and the read API sees it from both sides.
func TestFormStoresGateVerdict(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		ctx := context.Background()
		f := formation(e, adG1, enG1)
		f.Gate.FirstAttestedAt = t0 // attested tenant
		f.EntraBases, f.FactsAsOf = []inventory.Basis{"E1"}, t1
		got, err := e.form(t, f)
		if err != nil || !got.Created || got.Verdict.State != inventory.StateMatched {
			t.Fatalf("form: %+v %v", got, err)
		}
		ls, err := e.r.CorrelationsFor(ctx, e.a, f.AD)
		if err != nil || len(ls) != 1 {
			t.Fatalf("read: %v %v", ls, err)
		}
		l := ls[0]
		if l.State != inventory.StateMatched || l.EligibilityClass != "attested" || l.EligibleSince.IsZero() || l.GateCheckedAt.IsZero() ||
			!l.PeerTier0 || !reflect.DeepEqual(l.PeerBases, []inventory.Basis{"E1"}) || l.AnchorAttr != "ms-DS-ConsistencyGuid" {
			t.Fatalf("stored: %+v", l)
		}
		// Sync sees (a) fail: the same row goes back to candidate, markers kept; no second row.
		f.Gate.EntraSyncEnabled = nil
		f.Now = t1.Add(time.Hour)
		got2, err := e.form(t, f)
		if err != nil || got2.Created || got2.ID != got.ID || got2.Verdict.State != inventory.StateCandidate || got2.Verdict.Reason != inventory.ReasonNotSynced {
			t.Fatalf("re-form: %+v %v", got2, err)
		}
		ls, _ = e.r.CorrelationsFor(ctx, e.a, f.AD)
		if len(ls) != 1 || ls[0].State != inventory.StateCandidate || ls[0].Reason != "not_synced" || !ls[0].EligibleSince.Equal(l.EligibleSince) || ls[0].EligibilityClass != "attested" {
			t.Fatalf("after fail: %+v", ls)
		}
		// Two Entra objects of one tenant for one AD object is refused (I2).
		if _, err := e.form(t, formation(e, adG1, enG2)); !errors.Is(err, inventory.ErrConflict) {
			t.Fatalf("I2: %v", err)
		}
		// Sides gone: broken. Then removed: hidden from reads, and re-forming inherits the markers.
		f.Gate.SideGone = true
		if g, err := e.form(t, f); err != nil || g.Verdict.State != inventory.StateBroken {
			t.Fatalf("broken: %+v %v", g, err)
		}
		if err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error { return w.Remove(ctx, tx, f.AD, f.Entra) }); err != nil {
			t.Fatal(err)
		}
		if ls, err := e.r.CorrelationsFor(ctx, e.a, f.AD); err != nil || len(ls) != 0 {
			t.Fatalf("removed visible: %v %v", ls, err)
		}
		f.Gate.SideGone = false
		f.Now = t1.Add(48 * time.Hour)
		got3, err := e.form(t, f)
		if err != nil || !got3.Created || got3.Verdict.EligibleSince.IsZero() || !got3.Verdict.EligibleSince.Equal(l.EligibleSince) {
			t.Fatalf("re-form after removal: %+v %v", got3, err)
		}
	})
}

// The install-time population is candidate until the tenant's first attestation, then matched.
func TestFormInstallTimePopulation(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		f := formation(e, adG1, enG1)
		f.Gate.Takeover = inventory.TakeoverOpen
		g, err := e.form(t, f)
		if err != nil || g.Verdict.State != inventory.StateCandidate || g.Verdict.Reason != inventory.ReasonTenantTakeoverOpen || g.Verdict.EligibilityClass != "install_time" {
			t.Fatalf("install: %+v %v", g, err)
		}
		f.Gate.Takeover, f.Gate.FirstAttestedAt, f.Now = inventory.TakeoverAttested, t1, t1.Add(time.Hour)
		if g, err = e.form(t, f); err != nil || g.Verdict.State != inventory.StateMatched || g.Verdict.EligibilityClass != "install_time" {
			t.Fatalf("attested: %+v %v", g, err)
		}
	})
}

func TestFormRefusesBadInput(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		bad := map[string]func(*inventory.Formation){
			"same connection":  func(f *inventory.Formation) { f.Entra.Connection = f.AD.Connection },
			"anchor w/o value": func(f *inventory.Formation) { f.AnchorValue = nil },
			"sid w/o sid":      func(f *inventory.Formation) { f.Match, f.Gate.ADSID = inventory.MatchSID, nil },
			"bases w/o as-of":  func(f *inventory.Formation) { f.ADBases, f.FactsAsOf = []inventory.Basis{"C1"}, time.Time{} },
			"unknown match":    func(f *inventory.Formation) { f.Match = "name" },
			"non-canonical":    func(f *inventory.Formation) { f.AD.Object = "AAAAAAAA-0000-4000-8000-000000000001" },
		}
		for n, m := range bad {
			f := formation(e, adG1, enG1)
			m(&f)
			if _, err := e.form(t, f); !errors.Is(err, inventory.ErrInvalid) {
				t.Errorf("%s: %v", n, err)
			}
		}
		// A basis of the other side's namespace is refused by the schema.
		f := formation(e, adG1, enG1)
		f.ADBases, f.FactsAsOf = []inventory.Basis{"E1"}, t1
		if _, err := e.form(t, f); !errors.Is(err, inventory.ErrInvalid) {
			t.Errorf("foreign basis: %v", err)
		}
		// Another tenant's connection is not one of this tenant's.
		f = formation(e, adG1, enG1)
		f.AD.Connection = e.adB
		if _, err := e.form(t, f); !errors.Is(err, inventory.ErrUnknownConnection) {
			t.Errorf("other tenant: %v", err)
		}
		// No tenant context at all.
		conn, err := e.d.App(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close(context.Background())
		if _, err := w.Form(context.Background(), conn, formation(e, adG1, enG1)); !errors.Is(err, inventory.ErrNoTenant) {
			t.Errorf("no tenant: %v", err)
		}
	})
}

// Acceptance 2: the GroupSource returns transitive membership, terminates on a cycle, and is tenant scoped.
func TestGroupSourceTransitive(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		ctx := context.Background()
		const (
			user = "aaaaaaaa-0000-4000-8000-0000000000a1"
			g1   = "aaaaaaaa-0000-4000-8000-0000000000b1"
			g2   = "aaaaaaaa-0000-4000-8000-0000000000b2"
			g3   = "aaaaaaaa-0000-4000-8000-0000000000b3"
			far  = "aaaaaaaa-0000-4000-8000-0000000000b4"
		)
		edge := func(g, m string) {
			if err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error {
				return w.SetMember(ctx, tx, e.adA, inventory.GUID(g), inventory.GUID(m), t1)
			}); err != nil {
				t.Fatal(err)
			}
		}
		edge(g1, user) // user ∈ g1 ∈ g2 ∈ g3 ∈ g1 (a cycle); far is unrelated
		edge(g2, g1)
		edge(g3, g2)
		edge(g1, g3)
		edge(far, g3) // far contains g3, so far is also above the user
		gs := inventory.NewGroups(e.db)
		got, err := gs.GroupsOf(ctx, e.a, e.adA, user)
		want := []inventory.GUID{g1, g2, g3, far}
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("transitive: %v %v", got, err)
		}
		if got, err := gs.GroupsOf(ctx, e.b, e.adA, user); err != nil || len(got) != 0 {
			t.Fatalf("tenant scope: %v %v", got, err)
		}
		// A removed edge no longer counts.
		_ = e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error {
			return w.RemoveMember(ctx, tx, e.adA, g1, user, t1.Add(time.Hour))
		})
		if got, _ := gs.GroupsOf(ctx, e.a, e.adA, user); len(got) != 0 {
			t.Fatalf("removed edge: %v", got)
		}
		edge(g1, user)

		// Reader.DesignationsFor finds a designation on a group two levels up.
		if err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error {
			_, err := w.Designate(ctx, tx, e.adA, far, "alice")
			return err
		}); err != nil {
			t.Fatal(err)
		}
		r := inventory.NewReader(e.db, gs)
		d, err := r.DesignationsFor(ctx, e.a, e.adA, []inventory.GUID{user})
		if err != nil || !reflect.DeepEqual(d, []inventory.GUID{far}) {
			t.Fatalf("designations through nesting: %v %v", d, err)
		}
	})
}

// Acceptance 4: removal is a soft delete, DELETE is revoked, a removed designation no longer protects
// and can be designated again.
func TestDesignationSoftDelete(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		ctx := context.Background()
		const obj = "aaaaaaaa-0000-4000-8000-0000000000c1"
		run := func(fn func(ctx context.Context, tx store.Tx) error) error { return e.tx(t, e.a, fn) }
		designate := func() (bool, error) {
			var ch bool
			err := run(func(ctx context.Context, tx store.Tx) (err error) {
				ch, err = w.Designate(ctx, tx, e.adA, obj, "alice")
				return
			})
			return ch, err
		}
		if ch, err := designate(); err != nil || !ch {
			t.Fatalf("designate: %v %v", ch, err)
		}
		if ch, err := designate(); err != nil || ch {
			t.Fatalf("designate twice should be a no-op: %v %v", ch, err)
		}
		if err := run(func(ctx context.Context, tx store.Tx) error { return w.Undesignate(ctx, tx, e.adA, obj, "bob") }); err != nil {
			t.Fatal(err)
		}
		if err := run(func(ctx context.Context, tx store.Tx) error { return w.Undesignate(ctx, tx, e.adA, obj, "bob") }); !errors.Is(err, inventory.ErrNotFound) {
			t.Fatalf("undesignate twice: %v", err)
		}
		d, err := e.r.DesignationsFor(ctx, e.a, e.adA, []inventory.GUID{obj})
		if err != nil || len(d) != 0 {
			t.Fatalf("removed designation still protects: %v %v", d, err)
		}
		var by string
		var at *time.Time
		_ = run(func(ctx context.Context, tx store.Tx) error {
			return tx.QueryRow(ctx, `SELECT removed_by, removed_at FROM public.tier0_designations WHERE object_guid = $1::uuid`, obj).Scan(&by, &at)
		})
		if by != "bob" || at == nil {
			t.Fatalf("removal not recorded: %q %v", by, at)
		}
		if err := run(func(ctx context.Context, tx store.Tx) error {
			_, err := tx.Exec(ctx, `DELETE FROM public.tier0_designations`)
			return err
		}); err == nil {
			t.Fatal("activediq_app can still DELETE designations")
		}
		if ch, err := designate(); err != nil || !ch {
			t.Fatalf("re-designate: %v %v", ch, err)
		}
		if d, _ := e.r.DesignationsFor(ctx, e.a, e.adA, []inventory.GUID{obj}); len(d) != 1 {
			t.Fatalf("re-designated: %v", d)
		}
		// A connection of another tenant is refused.
		if err := run(func(ctx context.Context, tx store.Tx) error {
			_, err := w.Designate(ctx, tx, e.adB, obj, "alice")
			return err
		}); !errors.Is(err, inventory.ErrUnknownConnection) {
			t.Fatalf("other tenant's connection: %v", err)
		}
	})
}

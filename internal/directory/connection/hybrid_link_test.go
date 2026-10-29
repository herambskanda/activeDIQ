package connection_test

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/directory/connection/connectiontest"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/migrations"
)

const (
	ncA = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	ncB = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
)

// Acceptance 2: every ordered pair of link states is legal exactly when DM-21 declares it.
func TestHybridLinkTransitionTable(t *testing.T) {
	legal := map[[2]connection.LinkState]bool{
		{connection.LinkProposed, connection.LinkConfirmed}: true,
		{connection.LinkConfirmed, connection.LinkRemoved}:  true,
		{connection.LinkProposed, connection.LinkRemoved}:   true,
	}
	for _, from := range connection.LinkStates() {
		for _, to := range connection.LinkStates() {
			if got, want := connection.CanTransitionLink(from, to), legal[[2]connection.LinkState{from, to}]; got != want {
				t.Errorf("%s → %s: %v, want %v", from, to, got, want)
			}
		}
	}
	if len(connection.LinkStates()) != 3 || len(connection.LinkEdges()) != len(legal) || connection.CanTransitionLink("x", "removed") {
		t.Fatal("table shape")
	}
}

func TestHybridLinkMigrationEdgesMatchTheGoTable(t *testing.T) {
	b, err := migrations.FS.ReadFile("0005_connection_hybrid_links.sql")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	i := strings.Index(src, "(OLD.state, NEW.state) NOT IN (")
	if i < 0 {
		t.Fatal("no edge list in the guard trigger")
	}
	list := src[i : i+strings.Index(src[i:], ") THEN")]
	got := map[[2]string]bool{}
	for _, m := range regexp.MustCompile(`\('(\w+)', '(\w+)'\)`).FindAllStringSubmatch(list, -1) {
		got[[2]string{m[1], m[2]}] = true
	}
	if len(got) != len(connection.LinkEdges()) {
		t.Fatalf("SQL lists %d edges, Go declares %d", len(got), len(connection.LinkEdges()))
	}
	for _, e := range connection.LinkEdges() {
		if !got[[2]string{string(e.From), string(e.To)}] {
			t.Errorf("edge %s → %s missing from the guard trigger", e.From, e.To)
		}
	}
}

func (e *env) entra(t *testing.T, tid tenant.ID, name string) connection.Connection {
	t.Helper()
	c, err := e.reg.Create(context.Background(), tid, connection.New{Kind: connection.KindEntraTenant, DisplayName: name, CredentialID: cred})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (e *env) ad(t *testing.T, tid tenant.ID, name string) connection.Connection {
	t.Helper()
	c, err := e.reg.Create(context.Background(), tid, forest(name))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// Acceptances 1, 3 and 4 against the database.
func TestHybridLinkStore(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		ctx := context.Background()
		ad, en := e.ad(t, e.a, "corp"), e.entra(t, e.a, "tenant")
		n := connection.NewHybridLink{ADConnectionID: ad.ID, NCGUID: ncA, EntraConnectionID: en.ID}

		if has, err := e.reg.HasHybridLink(ctx, e.a, ad.ID); err != nil || has {
			t.Fatalf("no links: %v %v", has, err)
		}
		// Discovered: proposed, trusts nothing, but counts for HasHybridLink.
		p, err := e.reg.DiscoverHybridLink(ctx, e.a, n)
		if err != nil || p.State != connection.LinkProposed || p.Origin != connection.OriginDiscovered {
			t.Fatalf("discover: %+v %v", p, err)
		}
		if ok, err := e.reg.Confirmed(ctx, e.a, ad.ID, ncA, en.ID); err != nil || ok {
			t.Fatalf("proposed must not be confirmed: %v %v", ok, err)
		}
		if has, err := e.reg.HasHybridLink(ctx, e.a, ad.ID); err != nil || !has {
			t.Fatalf("proposed counts: %v %v", has, err)
		}
		if _, err := e.reg.DiscoverHybridLink(ctx, e.a, n); !errors.Is(err, connection.ErrDuplicateHybridLink) {
			t.Fatalf("duplicate: %v", err)
		}
		// Illegal and stale transitions leave it alone.
		if _, err := e.reg.TransitionHybridLink(ctx, e.a, p.ID, connection.LinkConfirmed, connection.LinkProposed); !errors.Is(err, connection.ErrIllegalLinkTransition) {
			t.Fatalf("backwards: %v", err)
		}
		if _, err := e.reg.TransitionHybridLink(ctx, e.a, p.ID, connection.LinkConfirmed, connection.LinkRemoved); !errors.Is(err, connection.ErrLinkStateConflict) {
			t.Fatalf("stale from: %v", err)
		}
		c, err := e.reg.TransitionHybridLink(ctx, e.a, p.ID, connection.LinkProposed, connection.LinkConfirmed)
		if err != nil || c.State != connection.LinkConfirmed {
			t.Fatalf("confirm: %+v %v", c, err)
		}
		if ok, err := e.reg.Confirmed(ctx, e.a, ad.ID, ncA, en.ID); err != nil || !ok {
			t.Fatalf("confirmed: %v %v", ok, err)
		}
		if ok, _ := e.reg.Confirmed(ctx, e.a, ad.ID, ncB, en.ID); ok {
			t.Fatal("another domain is not covered by the link")
		}
		// Tenant isolation: tenant B sees nothing, and cannot read or move A's link.
		if has, _ := e.reg.HasHybridLink(ctx, e.b, ad.ID); has {
			t.Fatal("tenant B sees A's link")
		}
		if _, err := e.reg.GetHybridLink(ctx, e.b, p.ID); !errors.Is(err, connection.ErrHybridLinkNotFound) {
			t.Fatalf("cross-tenant get: %v", err)
		}
		if _, err := e.reg.TransitionHybridLink(ctx, e.b, p.ID, connection.LinkConfirmed, connection.LinkRemoved); !errors.Is(err, connection.ErrHybridLinkNotFound) {
			t.Fatalf("cross-tenant transition: %v", err)
		}
		// Removed: gone from the read, row kept, terminal, and the triple can be declared again.
		if _, err := e.reg.TransitionHybridLink(ctx, e.a, p.ID, connection.LinkConfirmed, connection.LinkRemoved); err != nil {
			t.Fatal(err)
		}
		if has, err := e.reg.HasHybridLink(ctx, e.a, ad.ID); err != nil || has {
			t.Fatalf("removed does not count: %v %v", has, err)
		}
		if ok, _ := e.reg.Confirmed(ctx, e.a, ad.ID, ncA, en.ID); ok {
			t.Fatal("removed is not confirmed")
		}
		if ls, _ := e.reg.ListHybridLinks(ctx, e.a, ad.ID, false); len(ls) != 0 {
			t.Fatalf("list hides removed: %v", ls)
		}
		if ls, _ := e.reg.ListHybridLinks(ctx, e.a, ad.ID, true); len(ls) != 1 {
			t.Fatalf("list with removed: %v", ls)
		}
		d, err := e.reg.DeclareHybridLink(ctx, e.a, n)
		if err != nil || d.State != connection.LinkConfirmed || d.Origin != connection.OriginDeclared {
			t.Fatalf("declare: %+v %v", d, err)
		}
		if ok, err := e.reg.Confirmed(ctx, e.a, ad.ID, ncA, en.ID); err != nil || !ok {
			t.Fatalf("declared is confirmed: %v %v", ok, err)
		}
	})
}

// Bad input and a read with no tenant return errors, never false.
func TestHybridLinkReadsFailClosed(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		ctx := context.Background()
		ad, en := e.ad(t, e.a, "corp"), e.entra(t, e.a, "tenant")
		if has, err := e.reg.HasHybridLink(ctx, tenant.ID{}, ad.ID); err == nil || has {
			t.Fatalf("no tenant: %v %v", has, err)
		}
		if has, err := e.reg.HasHybridLink(ctx, e.a, "not-a-uuid"); !errors.Is(err, connection.ErrInvalid) || has {
			t.Fatalf("bad id: %v %v", has, err)
		}
		if ok, err := e.reg.Confirmed(ctx, e.a, ad.ID, "bad", en.ID); !errors.Is(err, connection.ErrInvalid) || ok {
			t.Fatalf("bad nc: %v %v", ok, err)
		}
		err := e.platform(func(ctx context.Context, tx store.Tx) error {
			_, err := connection.Store{}.HasLink(ctx, tx, ad.ID)
			return err
		})
		if !errors.Is(err, connection.ErrNoTenant) {
			t.Fatalf("outside WithTenant: %v", err)
		}
	})
}

// The database refuses what the Go store would never send (I2, sides, immutability, kinds).
func TestHybridLinkDatabaseGuards(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		ctx := context.Background()
		ad, en := e.ad(t, e.a, "corp"), e.entra(t, e.a, "tenant")
		other := e.ad(t, e.b, "other")
		ins := `INSERT INTO public.hybrid_links (tenant_id, ad_connection_id, nc_guid, entra_connection_id, origin, state)
			VALUES (NULLIF(current_setting('app.tenant_id', true), '')::uuid, $1::uuid, $2, $3::uuid, $4, $5)`
		if _, err := e.raw(e.a, ins, string(ad.ID), ncA, string(en.ID), "discovered", "confirmed"); err == nil {
			t.Error("discovery must not insert a confirmed link")
		}
		if _, err := e.raw(e.a, ins, string(ad.ID), ncA, string(en.ID), "declared", "proposed"); err == nil {
			t.Error("declared+proposed is not a door")
		}
		if _, err := e.raw(e.a, ins, string(en.ID), ncA, string(ad.ID), "declared", "confirmed"); err == nil {
			t.Error("sides swapped")
		}
		if _, err := e.raw(e.a, ins, string(other.ID), ncA, string(en.ID), "declared", "confirmed"); err == nil {
			t.Error("a connection of another tenant")
		}
		l, err := e.reg.DeclareHybridLink(ctx, e.a, connection.NewHybridLink{ADConnectionID: ad.ID, NCGUID: ncA, EntraConnectionID: en.ID})
		if err != nil {
			t.Fatal(err)
		}
		for _, q := range []string{
			`UPDATE public.hybrid_links SET state = 'proposed'`,
			`UPDATE public.hybrid_links SET nc_guid = '` + ncB + `'`,
			`UPDATE public.hybrid_links SET origin = 'discovered'`,
			`DELETE FROM public.hybrid_links`,
		} {
			if _, err := e.raw(e.a, q); err == nil {
				t.Errorf("%s must fail", q)
			}
		}
		if _, err := e.reg.TransitionHybridLink(ctx, e.a, l.ID, connection.LinkConfirmed, connection.LinkRemoved); err != nil {
			t.Fatal(err)
		}
		if _, err := e.raw(e.a, `UPDATE public.hybrid_links SET state = 'confirmed'`); err == nil {
			t.Error("removed is terminal")
		}
		// An Entra side that is an AD connection is refused through the store too.
		if _, err := e.reg.DeclareHybridLink(ctx, e.a, connection.NewHybridLink{ADConnectionID: en.ID, NCGUID: ncA, EntraConnectionID: ad.ID}); !errors.Is(err, connection.ErrInvalid) {
			t.Errorf("wrong kinds: %v", err)
		}
		if _, err := e.reg.DeclareHybridLink(ctx, e.a, connection.NewHybridLink{ADConnectionID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", NCGUID: ncA, EntraConnectionID: en.ID}); !errors.Is(err, connection.ErrInvalid) {
			t.Errorf("unknown connection: %v", err)
		}
	})
}

// The in-memory fake obeys the same rules as the store, and fails closed on a fault.
func TestFakeHybridLinks(t *testing.T) {
	ctx := context.Background()
	tid, other := tenant.New(), tenant.New()
	f := connectiontest.NewHybridLinks()
	n := connection.NewHybridLink{ADConnectionID: idA, NCGUID: ncA, EntraConnectionID: idB}
	p, err := f.Discover(tid, n)
	if err != nil || p.State != connection.LinkProposed {
		t.Fatal(p, err)
	}
	if ok, _ := f.Confirmed(ctx, tid, idA, ncA, idB); ok {
		t.Fatal("proposed is not confirmed")
	}
	if has, _ := f.HasHybridLink(ctx, tid, idA); !has {
		t.Fatal("proposed counts")
	}
	if has, _ := f.HasHybridLink(ctx, other, idA); has {
		t.Fatal("tenant scoped")
	}
	if _, err := f.Transition(tid, p.ID, connection.LinkRemoved, connection.LinkProposed); !errors.Is(err, connection.ErrIllegalLinkTransition) {
		t.Fatal(err)
	}
	if _, err := f.Transition(tid, p.ID, connection.LinkProposed, connection.LinkConfirmed); err != nil {
		t.Fatal(err)
	}
	if ok, _ := f.Confirmed(ctx, tid, idA, ncA, idB); !ok {
		t.Fatal("confirmed")
	}
	if _, err := f.Transition(tid, p.ID, connection.LinkConfirmed, connection.LinkRemoved); err != nil {
		t.Fatal(err)
	}
	if has, _ := f.HasHybridLink(ctx, tid, idA); has {
		t.Fatal("removed does not count")
	}
	f.Err = errors.New("boom")
	if has, err := f.HasHybridLink(ctx, tid, idA); err == nil || has {
		t.Fatal("a read error is an error, never false")
	}
}

// Bad or non-canonical input fails closed in the fake exactly as in the store.
func TestFakeHybridLinksInputValidation(t *testing.T) {
	ctx := context.Background()
	tid := tenant.New()
	f := connectiontest.NewHybridLinks()
	if _, err := f.Declare(tid, connection.NewHybridLink{ADConnectionID: idA, NCGUID: ncA, EntraConnectionID: idB}); err != nil {
		t.Fatal(err)
	}
	if has, err := f.HasHybridLink(ctx, tid, "not-a-uuid"); !errors.Is(err, connection.ErrInvalid) || has {
		t.Fatal(has, err)
	}
	if ok, err := f.Confirmed(ctx, tid, idA, "bad", idB); !errors.Is(err, connection.ErrInvalid) || ok {
		t.Fatal(ok, err)
	}
	if ok, err := f.Confirmed(ctx, tid, idA, ncA, "bad"); !errors.Is(err, connection.ErrInvalid) || ok {
		t.Fatal(ok, err)
	}
	up := func(s string) string { return strings.ToUpper(s) }
	if has, err := f.HasHybridLink(ctx, tid, connection.ID(up(string(idA)))); err != nil || !has {
		t.Fatal(has, err)
	}
	if ok, err := f.Confirmed(ctx, tid, connection.ID(up(string(idA))), connection.NCGUID(up(string(ncA))), connection.ID(up(string(idB)))); err != nil || !ok {
		t.Fatal(ok, err)
	}
}

func TestHybridLinkListsAboveTheBoundAreErrTooMany(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		ctx := context.Background()
		ad, en := e.ad(t, e.a, "corp"), e.entra(t, e.a, "tenant")
		for i := 0; i < 1001; i++ {
			n := connection.NewHybridLink{ADConnectionID: ad.ID, NCGUID: connection.NCGUID(fmt.Sprintf("cccccccc-cccc-4ccc-8ccc-%012x", i)), EntraConnectionID: en.ID}
			if _, err := e.reg.DiscoverHybridLink(ctx, e.a, n); err != nil {
				t.Fatal(err)
			}
		}
		if ls, err := e.reg.ListHybridLinks(ctx, e.a, ad.ID, false); !errors.Is(err, connection.ErrTooMany) || ls != nil {
			t.Fatalf("AD side: %d links, %v", len(ls), err)
		}
		err := e.db.WithTenant(ctx, e.a, func(ctx context.Context, tx store.Tx) error {
			_, err := connection.Store{}.ListHybridLinksForEntra(ctx, tx, en.ID)
			return err
		})
		if !errors.Is(err, connection.ErrTooMany) {
			t.Fatalf("Entra side: %v", err)
		}
	})
}

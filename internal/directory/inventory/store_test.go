package inventory_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

func TestMain(m *testing.M) { os.Exit(storetest.Main(m)) }

const (
	cred = "11111111-1111-4111-8111-111111111111"
	adG1 = "aaaaaaaa-0000-4000-8000-000000000001"
	adG2 = "aaaaaaaa-0000-4000-8000-000000000002"
	adG3 = "aaaaaaaa-0000-4000-8000-000000000003"
	enG1 = "eeeeeeee-0000-4000-8000-000000000001"
	enG2 = "eeeeeeee-0000-4000-8000-000000000002"
	enG3 = "eeeeeeee-0000-4000-8000-000000000003"
)

type env struct {
	d      *storetest.Database
	db     *store.DB
	a, b   tenant.ID
	adA    inventory.ConnectionID // tenant A's AD forest
	enA    inventory.ConnectionID // tenant A's Entra tenant
	adB    inventory.ConnectionID
	groups *inventory.Fake
	r      *inventory.Reader
}

func (e *env) conn(t *testing.T, tid tenant.ID, kind connection.Kind, tr connection.Transport) inventory.ConnectionID {
	t.Helper()
	c, err := connection.NewRegistry(e.db).Create(context.Background(), tid,
		connection.New{Kind: kind, DisplayName: "c", CredentialID: cred, Transport: tr})
	if err != nil {
		t.Fatalf("seed connection: %v", err)
	}
	return inventory.ConnectionID(c.ID)
}

// exec runs fixture SQL in the tenant's transaction (row-level security is forced). The writer of these tables is another ticket.
func (e *env) exec(tid tenant.ID, sql string, args ...any) error {
	return e.db.WithTenant(context.Background(), tid, func(ctx context.Context, tx store.Tx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	})
}

func setup(t *testing.T, s *storetest.Server) *env {
	t.Helper()
	d := s.NewDatabase(t)
	d.Migrate(t)
	e := &env{d: d, groups: inventory.NewFake()}
	e.a = tenanttest.Seed(t, d.ExecOwner, "A")
	e.b = tenanttest.Seed(t, d.ExecOwner, "B")
	db, err := store.Open(context.Background(), store.Config{DSN: d.AppDSN()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	e.db = db
	e.adA = e.conn(t, e.a, connection.KindADForest, connection.TransportLDAPS)
	e.enA = e.conn(t, e.a, connection.KindEntraTenant, "")
	e.adB = e.conn(t, e.b, connection.KindADForest, connection.TransportLDAPS)
	e.r = inventory.NewReader(db, e.groups)
	return e
}

// seed inserts one correlation row as the owner role (the writer is another ticket).
func (e *env) seed(t *testing.T, tid tenant.ID, ad, en inventory.Ref, state, reason, set string, args ...any) {
	t.Helper()
	q := fmt.Sprintf(`INSERT INTO public.correlations (tenant_id, ad_connection_id, ad_object_guid, entra_connection_id, entra_object_guid,
		state, candidate_reason, gate_checked_at, eligible_since, eligibility_class, %s)
		VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::uuid, $6, $7, now(), now(), 'attested', %s)`, set, placeholders(len(args), 8))
	all := append([]any{tid.String(), string(ad.Connection), string(ad.Object), string(en.Connection), string(en.Object), state, reason}, args...)
	if err := e.exec(tid, q, all...); err != nil {
		t.Fatalf("seed correlation: %v", err)
	}
}

func placeholders(n, from int) string {
	s := ""
	for i := 0; i < n; i++ {
		if i > 0 {
			s += ", "
		}
		s += fmt.Sprintf("$%d", from+i)
	}
	return s
}

var (
	anchor = []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	sid    = []byte{1, 1, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 1, 0, 0, 0}
)

// Acceptance 1: every state, from either side, with peer tier0, bases, anchor and SID evidence.
func TestCorrelationsForReturnsEveryStateFromEitherSide(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		ctx := context.Background()
		ad := func(g string) inventory.Ref { return inventory.Ref{Connection: e.adA, Object: inventory.GUID(g)} }
		en := func(g string) inventory.Ref { return inventory.Ref{Connection: e.enA, Object: inventory.GUID(g)} }
		// candidate: the Entra peer is tier0 (E1), anchor match.
		e.seed(t, e.a, ad(adG1), en(enG1), "candidate", "not_synced",
			"match, anchor_attr, anchor_value, ad_sid, entra_tier0, entra_tier0_bases, facts_as_of",
			"anchor", "ms-DS-ConsistencyGuid", anchor, sid, true, []string{"E1"}, time.Now())
		// matched: the AD object is tier0 (C1), SID match.
		e.seed(t, e.a, ad(adG2), en(enG2), "matched", "",
			"match, ad_sid, ad_tier0, ad_tier0_bases, facts_as_of", "sid", sid, true, []string{"C1", "designated"}, time.Now())
		// broken: neither tier0.
		e.seed(t, e.a, ad(adG3), en(enG3), "broken", "",
			"match, anchor_attr, anchor_value", "anchor", "objectGUID", anchor)
		// removed: hidden.
		e.seed(t, e.a, ad(adG1), inventory.Ref{Connection: e.enA, Object: "eeeeeeee-0000-4000-8000-0000000000ff"}, "removed", "",
			"match, ad_sid", "sid", sid)

		got, err := e.r.CorrelationsFor(ctx, e.a, ad(adG1))
		if err != nil || len(got) != 1 {
			t.Fatalf("AD side: %v %+v", err, got)
		}
		l := got[0]
		if l.State != inventory.StateCandidate || l.Reason != "not_synced" || l.Peer != en(enG1) || l.Self != ad(adG1) ||
			l.PeerKind != "entra_tenant" || !l.PeerTier0 || !reflect.DeepEqual(l.PeerBases, []inventory.Basis{"E1"}) ||
			l.SelfTier0 || l.Match != inventory.MatchAnchor || l.AnchorAttr != "ms-DS-ConsistencyGuid" ||
			!bytes.Equal(l.AnchorValue, anchor) || !bytes.Equal(l.ADSID, sid) || l.FactsAsOf.IsZero() || l.GateCheckedAt.IsZero() {
			t.Fatalf("candidate link: %+v", l)
		}
		// The Entra side of the same row: the peer is the AD object and its tier0 facts swap.
		got, err = e.r.CorrelationsFor(ctx, e.a, en(enG1))
		if err != nil || len(got) != 1 {
			t.Fatalf("Entra side: %v %+v", err, got)
		}
		if l := got[0]; l.Peer != ad(adG1) || l.PeerKind != "ad_forest" || l.PeerTier0 || !l.SelfTier0 {
			t.Fatalf("Entra side link: %+v", l)
		}
		got, err = e.r.CorrelationsFor(ctx, e.a, ad(adG2))
		if err != nil || len(got) != 1 || got[0].State != inventory.StateMatched || got[0].Match != inventory.MatchSID ||
			!got[0].SelfTier0 || !reflect.DeepEqual(got[0].SelfBases, []inventory.Basis{"C1", "designated"}) || got[0].PeerTier0 {
			t.Fatalf("matched: %v %+v", err, got)
		}
		got, err = e.r.CorrelationsFor(ctx, e.a, en(enG3))
		if err != nil || len(got) != 1 || got[0].State != inventory.StateBroken {
			t.Fatalf("broken: %v %+v", err, got)
		}
		// A different tenant sees nothing, even with the same refs.
		got, err = e.r.CorrelationsFor(ctx, e.b, ad(adG1))
		if err != nil || len(got) != 0 {
			t.Fatalf("tenant B: %v %+v", err, got)
		}
	})
}

// Acceptance 2: removed is hidden (above, its peer is not returned); a store error is an error.
func TestCorrelationsForFailsClosed(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		ref := inventory.Ref{Connection: e.adA, Object: adG1}
		if _, err := e.r.CorrelationsFor(context.Background(), tenant.ID{}, ref); !errors.Is(err, inventory.ErrNoTenant) {
			t.Fatalf("no tenant: %v", err)
		}
		if _, err := e.r.CorrelationsFor(context.Background(), e.a, inventory.Ref{Connection: "x", Object: adG1}); !errors.Is(err, inventory.ErrInvalid) {
			t.Fatalf("invalid ref: %v", err)
		}
		// A cancelled context, then a closed database: both are errors, never an empty list.
		cctx, cancel := context.WithCancel(context.Background())
		cancel()
		if got, err := e.r.CorrelationsFor(cctx, e.a, ref); err == nil || got != nil {
			t.Fatalf("cancelled: %v %v", got, err)
		}
		e.db.Close()
		if got, err := e.r.CorrelationsFor(context.Background(), e.a, ref); err == nil || got != nil {
			t.Fatalf("closed db: %v %v", got, err)
		}
		if _, err := (*inventory.Reader)(nil).CorrelationsFor(context.Background(), e.a, ref); !errors.Is(err, inventory.ErrNotConfigured) {
			t.Fatalf("nil reader: %v", err)
		}
	})
}

// The database refuses a correlation whose tier0 flag disagrees with its bases, or that is matched
// without a gate time: the writer cannot store what a reader would misread.
func TestSchemaRefusesIncoherentRows(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		bad := func(name, state, reason, set string, args ...any) {
			q := fmt.Sprintf(`INSERT INTO public.correlations (tenant_id, ad_connection_id, ad_object_guid, entra_connection_id, entra_object_guid, state, candidate_reason, match, ad_sid, %s)
				VALUES ($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::uuid,$6,$7,'sid',$8,%s)`, set, placeholders(len(args), 9))
			all := append([]any{e.a.String(), string(e.adA), adG1, string(e.enA), enG1, state, reason, sid}, args...)
			if err := e.exec(e.a, q, all...); err == nil {
				t.Errorf("%s: accepted", name)
			}
		}
		bad("flag without bases", "broken", "", "ad_tier0", true)
		bad("unknown basis", "broken", "", "entra_tier0, entra_tier0_bases, facts_as_of", true, []string{"C1"}, "2026-01-01T00:00:00Z")
		bad("candidate without reason", "candidate", "", "ad_tier0", false)
		bad("matched without gate", "matched", "", "ad_tier0", false)
	})
}

// Acceptance 3: designations of a connection, direct and through a designated group, tenant-scoped.
func TestDesignationsForScopedByTenantAndConnection(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		ctx := context.Background()
		des := func(tid tenant.ID, c inventory.ConnectionID, g string) {
			if err := e.exec(tid, `INSERT INTO public.tier0_designations (tenant_id, connection_id, object_guid) VALUES ($1::uuid,$2::uuid,$3::uuid)`,
				tid.String(), string(c), g); err != nil {
				t.Fatal(err)
			}
		}
		grp := "bbbbbbbb-0000-4000-8000-000000000001"
		des(e.a, e.adA, adG1) // a designated user
		des(e.a, e.adA, grp)  // a designated group
		des(e.a, e.adA, adG3) // designated but not asked about
		des(e.b, e.adB, adG2) // another tenant
		des(e.b, e.adB, adG1) // another tenant, same GUID as tenant A's
		e.groups.AddMembership(e.a, e.adA, adG2, inventory.GUID(grp))

		got, err := e.r.DesignationsFor(ctx, e.a, e.adA, []inventory.GUID{adG1, adG2})
		want := []inventory.GUID{adG1, inventory.GUID(grp)}
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("A: %v %v want %v", err, got, want)
		}
		// Tenant B's designation of adG2 never shows in A, and A's connection is not B's.
		got, err = e.r.DesignationsFor(ctx, e.b, e.adB, []inventory.GUID{adG1, adG2})
		if err != nil || !reflect.DeepEqual(got, []inventory.GUID{adG1, adG2}) {
			t.Fatalf("B: %v %v", err, got)
		}
		got, err = e.r.DesignationsFor(ctx, e.b, e.adA, []inventory.GUID{adG1, adG2})
		if err != nil || len(got) != 0 {
			t.Fatalf("B asking for A's connection: %v %v", err, got)
		}
		got, err = e.r.DesignationsFor(ctx, e.a, e.adA, nil)
		if err != nil || got == nil || len(got) != 0 {
			t.Fatalf("empty set: %v %#v", err, got)
		}
		// Fail closed: a group-source error is an error, no tenant is an error, no group source too.
		e.groups.Err = errors.New("boom")
		if got, err := e.r.DesignationsFor(ctx, e.a, e.adA, []inventory.GUID{adG1}); err == nil || got != nil {
			t.Fatalf("group source error: %v %v", got, err)
		}
		e.groups.Err = nil
		if _, err := e.r.DesignationsFor(ctx, tenant.ID{}, e.adA, []inventory.GUID{adG1}); !errors.Is(err, inventory.ErrNoTenant) {
			t.Fatalf("no tenant: %v", err)
		}
		if _, err := inventory.NewReader(e.db, nil).DesignationsFor(ctx, e.a, e.adA, []inventory.GUID{adG1}); !errors.Is(err, inventory.ErrNotConfigured) {
			t.Fatalf("no group source: %v", err)
		}
		if _, err := e.r.DesignationsFor(ctx, e.a, e.adA, []inventory.GUID{"not-a-guid"}); !errors.Is(err, inventory.ErrInvalid) {
			t.Fatalf("invalid guid: %v", err)
		}
	})
}

package agentingest_test

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/agentingest"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/audit/chain"
	"github.com/skenzeriq/activediq/internal/platform/fleet"
	"github.com/skenzeriq/activediq/internal/platform/fleet/fleetsql"
	"github.com/skenzeriq/activediq/internal/platform/keys"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

type sink struct {
	mu  sync.Mutex
	evs []audit.Event
}

func (s *sink) Append(_ context.Context, _ store.Tx, ev audit.Event) error {
	if err := ev.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	s.evs = append(s.evs, ev)
	s.mu.Unlock()
	return nil
}

type alerts struct{ got []fleetsql.Alert }

func (a *alerts) Raise(_ context.Context, al fleetsql.Alert) { a.got = append(a.got, al) }

type claims struct{ ok bool }

func (c claims) Matches(context.Context, store.Tx, fleet.Identity, string) (bool, error) {
	return c.ok, nil
}

const (
	compA  = "11111111-1111-4111-8111-111111111111"
	compB  = "22222222-2222-4222-8222-222222222222"
	dcGUID = "33333333-3333-4333-8333-333333333333"
)

type env struct {
	db   *store.DB
	a, b tenant.ID
}

func setup(t *testing.T, s *storetest.Server) *env {
	t.Helper()
	d := s.NewDatabase(t)
	d.Migrate(t)
	a := tenanttest.Seed(t, d.ExecOwner, "A")
	b := tenanttest.Seed(t, d.ExecOwner, "B")
	db, err := store.Open(context.Background(), store.Config{DSN: d.AppDSN()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	return &env{db: db, a: a, b: b}
}

var observed = time.Date(2026, 10, 28, 6, 0, 0, 123456000, time.UTC)

func rec(seq uint64) agentingest.Record {
	return agentingest.Record{AgentSeq: seq, Type: agentingest.TypeEvent, Channel: "security", ObservedAt: observed,
		Fields: map[string]string{"event_id": "4740"}}
}

func count(t *testing.T, e *env, tid tenant.ID, where string, args ...any) int {
	t.Helper()
	var n int
	err := e.db.WithTenant(context.Background(), tid, func(ctx context.Context, tx store.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM public.agent_event WHERE `+where, args...).Scan(&n) // test-only constant predicates
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// S1: a payload that names another tenant and component is stored under the certificate's identity.
func TestS1IdentityIsStampedFromTheCertificateNotThePayload(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		ing := &agentingest.Ingester{DB: e.db, Audit: &sink{}}
		hostile := rec(1)
		hostile.Fields = map[string]string{"tenant_id": e.b.String(), "component_id": compB, "kind": "fileserver", "tenant": e.b.String()}
		res, err := ing.Append(context.Background(), fleet.Identity{Tenant: e.a, Kind: fleet.KindADDC, ComponentID: compA},
			agentingest.Batch{Records: []agentingest.Record{hostile}})
		if err != nil || res.Accepted != 1 {
			t.Fatalf("%+v %v", res, err)
		}
		if n := count(t, e, e.a, `component_id = $1::uuid`, compA); n != 1 {
			t.Fatalf("not stored under the certificate's component: %d", n)
		}
		if n := count(t, e, e.a, `component_id = $1::uuid`, compB); n != 0 {
			t.Fatal("payload component was honoured")
		}
		if n := count(t, e, e.b, `true`); n != 0 {
			t.Fatal("payload tenant was honoured")
		}
	})
}

func TestRedeliveryIsIdempotentAndOtherKindsAreRefused(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		sk := &sink{}
		ing := &agentingest.Ingester{DB: e.db, Audit: sk}
		id := fleet.Identity{Tenant: e.a, Kind: fleet.KindADDC, ComponentID: compA}
		b := agentingest.Batch{Records: []agentingest.Record{rec(1), rec(2), rec(3)}}
		if r, err := ing.Append(context.Background(), id, b); err != nil || r.Accepted != 3 || r.HighestSeq != 3 {
			t.Fatalf("%+v %v", r, err)
		}
		r, err := ing.Append(context.Background(), id, agentingest.Batch{Records: []agentingest.Record{rec(2), rec(3), rec(4)}})
		if err != nil || r.Accepted != 1 || r.Duplicates != 2 || r.HighestSeq != 4 {
			t.Fatalf("redelivery: %+v %v", r, err)
		}
		if n := count(t, e, e.a, `true`); n != 4 {
			t.Fatalf("rows: %d", n)
		}
		if len(sk.evs) != 2 {
			t.Fatalf("audit events: %d", len(sk.evs))
		}
		other := id
		other.Kind = fleet.KindConnector
		if _, err := ing.Append(context.Background(), other, b); !errors.Is(err, agentingest.ErrWrongKind) {
			t.Fatalf("connector cert: %v", err)
		}
		if _, err := ing.AppendAuthenticated(context.Background(), b); !errors.Is(err, agentingest.ErrNoIdentity) {
			t.Fatalf("no identity: %v", err)
		}
	})
}

func TestBadBatchesStoreNothing(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		ing := &agentingest.Ingester{DB: e.db, Audit: &sink{}}
		id := fleet.Identity{Tenant: e.a, Kind: fleet.KindADDC, ComponentID: compA}
		badType := rec(2)
		badType.Type = "bogus"
		badDC := rec(2)
		badDC.ReportedDCGUID = "not-a-guid"
		for name, recs := range map[string][]agentingest.Record{
			"empty": nil, "bad type": {rec(1), badType}, "bad guid": {rec(1), badDC}, "not increasing": {rec(2), rec(2)}, "zero seq": {rec(0)},
		} {
			if _, err := ing.Append(context.Background(), id, agentingest.Batch{Records: recs}); !errors.Is(err, agentingest.ErrInvalid) {
				t.Fatalf("%s: %v", name, err)
			}
		}
		if n := count(t, e, e.a, `true`); n != 0 {
			t.Fatalf("rows: %d", n)
		}
	})
}

func TestDCGUIDMismatchRaisesAlertButStoresTheRecord(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		al := &alerts{}
		ing := &agentingest.Ingester{DB: e.db, Audit: &sink{}, Alerts: al, Claims: claims{ok: false}}
		id := fleet.Identity{Tenant: e.a, Kind: fleet.KindADDC, ComponentID: compA}
		r := rec(1)
		r.ReportedDCGUID = dcGUID
		if _, err := ing.Append(context.Background(), id, agentingest.Batch{Records: []agentingest.Record{r}}); err != nil {
			t.Fatal(err)
		}
		if len(al.got) != 1 || al.got[0].Kind != agentingest.AlertDCGUIDMismatch || al.got[0].Component != compA || al.got[0].Tenant != e.a {
			t.Fatalf("alerts: %+v", al.got)
		}
		if n := count(t, e, e.a, `reported_dc_guid = $1::uuid`, dcGUID); n != 1 {
			t.Fatal("record not stored with the reported value")
		}
		al.got = nil
		ing.Claims = claims{ok: true}
		r2 := rec(2)
		r2.ReportedDCGUID = dcGUID
		_, _ = ing.Append(context.Background(), id, agentingest.Batch{Records: []agentingest.Record{r2}})
		if len(al.got) != 0 {
			t.Fatal("alert on a matching GUID")
		}
	})
}

func TestEventTableIsAppendOnlyForTheAppRole(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		ing := &agentingest.Ingester{DB: e.db, Audit: &sink{}}
		id := fleet.Identity{Tenant: e.a, Kind: fleet.KindADDC, ComponentID: compA}
		_, _ = ing.Append(context.Background(), id, agentingest.Batch{Records: []agentingest.Record{rec(1)}})
		for _, q := range []string{`UPDATE public.agent_event SET record_type = 'gap'`, `DELETE FROM public.agent_event`} {
			err := e.db.WithTenant(context.Background(), e.a, func(ctx context.Context, tx store.Tx) error {
				_, err := tx.Exec(ctx, q)
				return err
			})
			if err == nil {
				t.Fatalf("%q succeeded", q)
			}
		}
	})
}

type noAnchor struct{}

func (noAnchor) Anchor(context.Context, chain.Checkpoint) error { return nil }

type fixedKeys struct{}

func (fixedKeys) DEK(context.Context, store.Tx, tenant.ID, uint32) (keys.DEK, error) {
	return keys.DEKFromBytes(1, bytes.Repeat([]byte{9}, keys.DEKSize))
}

func fieldsOf(t *testing.T, e *env, seq int64) string {
	t.Helper()
	var f string
	err := e.db.WithTenant(context.Background(), e.a, func(ctx context.Context, tx store.Tx) error {
		return tx.QueryRow(ctx, `SELECT fields::text FROM public.agent_event WHERE agent_seq = $1`, seq).Scan(&f)
	})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// Content the database cannot hold must not stop collection: the record is repaired, marked, and stored.
func TestUnstorableContentIsRepairedNotRefused(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		ing := &agentingest.Ingester{DB: e.db, Audit: &sink{}}
		id := fleet.Identity{Tenant: e.a, Kind: fleet.KindADDC, ComponentID: compA}
		mk := func(seq uint64, k, v string) agentingest.Record {
			r := rec(seq)
			r.Fields = map[string]string{k: v}
			return r
		}
		b := agentingest.Batch{Records: []agentingest.Record{
			mk(1, "TargetUserName", "ev\x00il"),
			mk(2, "TargetUserName", "bad\xffbyte"),
			mk(3, "TargetUserName", "surr\xed\xa0\x80ogate"),
			mk(4, "TargetUserName", "fine"),
			mk(5, "k\x00ey", "v"),
		}}
		r, err := ing.Append(context.Background(), id, b)
		if err != nil || r.Accepted != 5 {
			t.Fatalf("%+v %v", r, err)
		}
		for seq := int64(1); seq <= 3; seq++ {
			f := fieldsOf(t, e, seq)
			if !bytes.Contains([]byte(f), []byte(`"_sanitized"`)) || !bytes.Contains([]byte(f), []byte(`TargetUserName`)) {
				t.Fatalf("seq %d not marked: %s", seq, f)
			}
		}
		if f := fieldsOf(t, e, 4); bytes.Contains([]byte(f), []byte("_sanitized")) {
			t.Fatalf("clean record marked: %s", f)
		}
		// a hostile marker from the agent is replaced
		h := mk(6, agentingest.SanitizedKey, "forged")
		if _, err := ing.Append(context.Background(), id, agentingest.Batch{Records: []agentingest.Record{h}}); err != nil {
			t.Fatal(err)
		}
		if f := fieldsOf(t, e, 6); bytes.Contains([]byte(f), []byte("forged")) {
			t.Fatalf("forged marker kept: %s", f)
		}
		over := rec(1 << 63)
		if _, err := ing.Append(context.Background(), id, agentingest.Batch{Records: []agentingest.Record{over}}); !errors.Is(err, agentingest.ErrInvalid) {
			t.Fatalf("seq > MaxInt64: %v", err)
		}
	})
}

// A redelivery with different content under a stored sequence is a divergence, not a duplicate.
func TestSeqDivergenceIsTypedAlertedAndNeverOverwrites(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		al := &alerts{}
		ing := &agentingest.Ingester{DB: e.db, Audit: &sink{}, Alerts: al}
		id := fleet.Identity{Tenant: e.a, Kind: fleet.KindADDC, ComponentID: compA}
		if _, err := ing.Append(context.Background(), id, agentingest.Batch{Records: []agentingest.Record{rec(1), rec(2)}}); err != nil {
			t.Fatal(err)
		}
		changed := rec(2)
		changed.Fields = map[string]string{"event_id": "4625"}
		r, err := ing.Append(context.Background(), id, agentingest.Batch{Records: []agentingest.Record{rec(1), changed, rec(3)}})
		var de *agentingest.DivergenceError
		if !errors.Is(err, agentingest.ErrSeqDivergence) || !errors.As(err, &de) || len(de.Seqs) != 1 || de.Seqs[0] != 2 {
			t.Fatalf("err: %v", err)
		}
		if r.Duplicates != 1 || r.Accepted != 1 || len(r.Diverged) != 1 {
			t.Fatalf("%+v", r)
		}
		if len(al.got) != 1 || al.got[0].Kind != agentingest.AlertSeqDivergence || al.got[0].Component != compA {
			t.Fatalf("alerts: %+v", al.got)
		}
		if f := fieldsOf(t, e, 2); !bytes.Contains([]byte(f), []byte("4740")) {
			t.Fatalf("stored row was replaced: %s", f)
		}
	})
}

// Against the real chainer (which refuses a reused event ID): a batch filling sequences below the maximum
// must still be audited.
func TestBatchesBelowTheMaximumAreAuditedByTheRealChainer(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		ch := audit.NewChainer(e.db)
		cp := audit.NewCheckpointer(ch, fixedKeys{}, noAnchor{})
		ctx := context.Background()
		if err := e.db.WithTenant(ctx, e.a, func(ctx context.Context, tx store.Tx) error { return cp.InitTenant(ctx, tx, e.a) }); err != nil {
			t.Fatal(err)
		}
		ing := &agentingest.Ingester{DB: e.db, Audit: ch}
		id := fleet.Identity{Tenant: e.a, Kind: fleet.KindADDC, ComponentID: compA}
		for _, recs := range [][]agentingest.Record{{rec(1), rec(2), rec(3), rec(10)}, {rec(4), rec(5)}, {rec(4), rec(5), rec(6)}} {
			if _, err := ing.Append(ctx, id, agentingest.Batch{Records: recs}); err != nil {
				t.Fatalf("batch ending %d: %v", recs[len(recs)-1].AgentSeq, err)
			}
		}
		var n int
		err := e.db.WithTenant(ctx, e.a, func(ctx context.Context, tx store.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM audit_event WHERE kind = $1`, string(agentingest.KindBatchAccepted)).Scan(&n)
		})
		if err != nil || n != 3 {
			t.Fatalf("audited batches: %d %v", n, err)
		}
	})
}

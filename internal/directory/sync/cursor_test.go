package sync_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/directory/inventory"
	dsync "github.com/skenzeriq/activediq/internal/directory/sync"
	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

func TestMain(m *testing.M) { os.Exit(storetest.Main(m)) }

const (
	cred = "11111111-1111-4111-8111-111111111111"
	nc1  = "bbbbbbbb-0000-4000-8000-0000000000a1"
	nc2  = "bbbbbbbb-0000-4000-8000-0000000000a2"
	dc1  = "dddddddd-0000-4000-8000-000000000001"
)

// secretCookie is the sentinel the leak tests look for in every rendering.
var secretCookie = []byte("SENTINEL-DIRSYNC-COOKIE-\x00\x01\x02-do-not-log")

type env struct {
	d     *storetest.Database
	db    *store.DB
	a, b  tenant.ID
	conn  inventory.ConnectionID // tenant A's AD forest
	connB inventory.ConnectionID
	store dsync.Store
}

func setup(t *testing.T, s *storetest.Server) *env {
	t.Helper()
	d := s.NewDatabase(t)
	d.Migrate(t)
	e := &env{d: d}
	e.a = tenanttest.Seed(t, d.ExecOwner, "A")
	e.b = tenanttest.Seed(t, d.ExecOwner, "B")
	db, err := store.Open(context.Background(), store.Config{DSN: d.AppDSN()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	e.db = db
	mk := func(tid tenant.ID) inventory.ConnectionID {
		c, err := connection.NewRegistry(db).Create(context.Background(), tid,
			connection.New{Kind: connection.KindADForest, DisplayName: "c", CredentialID: cred, Transport: connection.TransportLDAPS})
		if err != nil {
			t.Fatalf("seed connection: %v", err)
		}
		return inventory.ConnectionID(c.ID)
	}
	e.conn, e.connB = mk(e.a), mk(e.b)
	return e
}

func each(t *testing.T, fn func(t *testing.T, e *env)) {
	t.Helper()
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) { fn(t, setup(t, s)) })
}

func (e *env) key(t *testing.T, nc string) dsync.Key {
	t.Helper()
	p, err := dsync.NCPartition(nc)
	if err != nil {
		t.Fatal(err)
	}
	return dsync.Key{Connection: e.conn, Partition: p}
}

// tx runs fn in tenant tid's transaction; an error from fn rolls it back.
func (e *env) tx(tid tenant.ID, fn func(ctx context.Context, tx store.Tx) error) error {
	return e.db.WithTenant(context.Background(), tid, fn)
}

// lease acquires the key's lease for holder; it fails the test if the lease is not free.
func (e *env) lease(t *testing.T, k dsync.Key, holder string) jobs.Lease {
	t.Helper()
	return e.leaseFor(t, k, holder, time.Minute)
}

func (e *env) leaseFor(t *testing.T, k dsync.Key, holder string, ttl time.Duration) jobs.Lease {
	t.Helper()
	name, err := dsync.LeaseName(k)
	if err != nil {
		t.Fatal(err)
	}
	l, ok, err := jobs.AcquireLease(context.Background(), e.db, name, holder, ttl)
	if err != nil || !ok {
		t.Fatalf("acquire %s = %v, %v", name, ok, err)
	}
	return l
}

// lapse waits for a short lease (leaseFor with lapseTTL) to expire on the database clock, so the next
// acquire is a takeover with a higher token.
func lapse() { time.Sleep(3 * lapseTTL) }

const lapseTTL = 100 * time.Millisecond

func cookie(t *testing.T, b []byte) dsync.Cookie {
	t.Helper()
	c, err := dsync.NewCookie(b)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (e *env) claim(t *testing.T, k dsync.Key, l jobs.Lease) dsync.Cursor {
	t.Helper()
	var c dsync.Cursor
	if err := e.tx(e.a, func(ctx context.Context, tx store.Tx) (err error) { c, err = e.store.Claim(ctx, tx, k, l); return }); err != nil {
		t.Fatalf("claim: %v", err)
	}
	return c
}

func (e *env) full(l jobs.Lease, k dsync.Key, ck []byte) error {
	return e.tx(e.a, func(ctx context.Context, tx store.Tx) error {
		c, err := dsync.NewCookie(ck)
		if err != nil {
			return err
		}
		_, err = e.store.CompleteFull(ctx, tx, k, l, dsync.FullSync{At: time.Now().Add(-time.Minute), Cookie: c, IssuingDSA: dc1})
		return err
	})
}

func (e *env) advance(l jobs.Lease, k dsync.Key, ck []byte, change time.Time) error {
	return e.tx(e.a, func(ctx context.Context, tx store.Tx) error {
		c, err := dsync.NewCookie(ck)
		if err != nil {
			return err
		}
		_, err = e.store.Advance(ctx, tx, k, l, dsync.Move{Cookie: c, IssuingDSA: dc1, LastChange: change})
		return err
	})
}

func (e *env) get(t *testing.T, k dsync.Key) dsync.Cursor {
	t.Helper()
	var c dsync.Cursor
	if err := e.tx(e.a, func(ctx context.Context, tx store.Tx) (err error) { c, err = e.store.Get(ctx, tx, k); return }); err != nil {
		t.Fatalf("get: %v", err)
	}
	return c
}

func (e *env) position(t *testing.T, k dsync.Key, l jobs.Lease) (dsync.Cursor, dsync.Cookie, error) {
	t.Helper()
	var (
		c  dsync.Cursor
		ck dsync.Cookie
	)
	err := e.tx(e.a, func(ctx context.Context, tx store.Tx) (err error) {
		c, ck, err = e.store.Position(ctx, tx, k, l)
		return
	})
	return c, ck, err
}

// Acceptance 1: the migration's shape, as the runtime role sees it.
func TestMigrationShape(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		var cols []string
		err := e.tx(e.a, func(ctx context.Context, tx store.Tx) error {
			rows, err := tx.Query(ctx, `SELECT column_name FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'sync_cursors' ORDER BY ordinal_position`)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var c string
				if err := rows.Scan(&c); err != nil {
					return err
				}
				cols = append(cols, c)
			}
			return rows.Err()
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"tenant_id", "connection_id", "partition", "cookie", "issuing_dsa_guid", "last_full_sync_at", "last_change_at", "lease_fencing_token", "state"} {
			found := false
			for _, c := range cols {
				found = found || c == want
			}
			if !found {
				t.Errorf("column %s is missing (have %v)", want, cols)
			}
		}
		got, err := e.d.OwnerStrings(ctx, `SELECT a.attname FROM pg_index i JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY (i.indkey)
			WHERE i.indrelid = 'public.sync_cursors'::regclass AND i.indisprimary ORDER BY array_position(i.indkey::int2[], a.attnum)`)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Join(got, ",") != "tenant_id,connection_id,partition" {
			t.Errorf("primary key = %v, want (tenant_id, connection_id, partition)", got)
		}
		got, err = e.d.OwnerStrings(ctx, `SELECT relrowsecurity::text || ',' || relforcerowsecurity::text || ',' || has_table_privilege('activediq_app', 'public.sync_cursors', 'DELETE')::text
			|| ',' || has_table_privilege('activediq_app', 'public.sync_cursors', 'INSERT')::text FROM pg_class WHERE oid = 'public.sync_cursors'::regclass`)
		if err != nil || len(got) != 1 || got[0] != "true,true,false,true" {
			t.Errorf("rls, force, runtime DELETE, runtime INSERT = %v, %v; want true,true,false,true", got, err)
		}
		// The CHECK ties state to the lifecycle; the runtime role cannot insert another state.
		k := e.key(t, nc1)
		bad := e.tx(e.a, func(ctx context.Context, tx store.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO public.sync_cursors (tenant_id, connection_id, partition, state, lease_fencing_token)
				VALUES (NULLIF(current_setting('app.tenant_id', true), '')::uuid, $1::uuid, $2, 'bogus', 1)`, string(k.Connection), string(k.Partition))
			return err
		})
		if store.SQLState(bad) != "23514" {
			t.Errorf("insert of state 'bogus' = %v, want a CHECK violation", bad)
		}
		// The runtime role cannot delete.
		e.claim(t, k, e.lease(t, k, "node-a"))
		del := e.tx(e.a, func(ctx context.Context, tx store.Tx) error {
			_, err := tx.Exec(ctx, `DELETE FROM public.sync_cursors`)
			return err
		})
		if store.SQLState(del) != "42501" {
			t.Errorf("runtime DELETE = %v, want insufficient_privilege", del)
		}
	})
}

// Acceptance 2: A held token t, B took over with t+1; A's write is refused with a typed error and the row is
// unchanged; B's succeeds.
func TestDeposedHolderIsFenced(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		k := e.key(t, nc1)
		a := e.leaseFor(t, k, "node-a", lapseTTL)
		e.claim(t, k, a)
		if err := e.full(a, k, []byte("cookie-1")); err != nil {
			t.Fatalf("A full sync: %v", err)
		}
		lapse()
		b := e.lease(t, k, "node-b")
		if b.Token != a.Token+1 {
			t.Fatalf("B token = %d, want %d", b.Token, a.Token+1)
		}
		// Taking the lease over fences A as soon as B claims, before B has advanced anything.
		e.claim(t, k, b)
		before := e.get(t, k)

		err := e.advance(a, k, []byte("cookie-from-A"), time.Now())
		var fe *dsync.FencedError
		if !errors.Is(err, dsync.ErrFenced) || !errors.As(err, &fe) || fe.Held != a.Token || fe.Stored != b.Token {
			t.Fatalf("A's write = %v, want a *FencedError{Held:%d, Stored:%d}", err, a.Token, b.Token)
		}
		for name, op := range map[string]error{
			"CompleteFull": e.full(a, k, []byte("x")),
			"Claim":        e.tx(e.a, func(ctx context.Context, tx store.Tx) error { _, err := e.store.Claim(ctx, tx, k, a); return err }),
			"RequireResync": e.tx(e.a, func(ctx context.Context, tx store.Tx) error {
				_, err := e.store.RequireResync(ctx, tx, k, a)
				return err
			}),
		} {
			if !errors.Is(op, dsync.ErrFenced) {
				t.Errorf("A's %s = %v, want ErrFenced", name, op)
			}
		}
		if _, _, err := e.position(t, k, a); !errors.Is(err, dsync.ErrFenced) {
			t.Errorf("A's Position = %v, want ErrFenced: a deposed holder must not resume from the position", err)
		}
		if after := e.get(t, k); after != before {
			t.Fatalf("row changed by a fenced write:\n before %v\n after  %v", before, after)
		}
		_, ck, err := e.position(t, k, b)
		if err != nil || !bytes.Equal(ck.Bytes(), []byte("cookie-1")) {
			t.Fatalf("B's position = %q, %v; the fenced write must not have landed", ck.Bytes(), err)
		}
		if err := e.advance(b, k, []byte("cookie-2"), time.Now()); err != nil {
			t.Fatalf("B's write: %v", err)
		}
		if got := e.get(t, k); got.FencingToken != b.Token || got.State != dsync.StateIncremental {
			t.Fatalf("after B: %v", got)
		}
	})
}

// A holder renewing its own lease keeps its token and keeps writing; claiming twice is harmless.
func TestSameHolderKeepsWriting(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		k := e.key(t, nc1)
		a := e.lease(t, k, "node-a")
		e.claim(t, k, a)
		e.claim(t, k, a)
		if err := e.full(a, k, []byte("c1")); err != nil {
			t.Fatal(err)
		}
		for i := 2; i < 5; i++ {
			if err := e.advance(a, k, []byte(fmt.Sprintf("c%d", i)), time.Time{}); err != nil {
				t.Fatalf("advance %d: %v", i, err)
			}
		}
		c := e.get(t, k)
		if !c.LastChange.IsZero() {
			t.Errorf("a step that saw no change set last_change_at = %v", c.LastChange)
		}
		// last_change_at never moves back.
		hi := time.Now().Add(-time.Minute).UTC().Truncate(time.Microsecond)
		if err := e.advance(a, k, []byte("c5"), hi); err != nil {
			t.Fatal(err)
		}
		if err := e.advance(a, k, []byte("c6"), hi.Add(-time.Hour)); err != nil {
			t.Fatal(err)
		}
		if got := e.get(t, k).LastChange; !got.Equal(hi) {
			t.Errorf("last_change_at = %v after an older change, want %v", got, hi)
		}
		if err := e.advance(a, k, []byte("c7"), time.Now().Add(time.Hour)); !errors.Is(err, dsync.ErrInvalid) {
			t.Errorf("a change time in the future = %v, want ErrInvalid", err)
		}
		// A lease for another partition does not guard this cursor.
		other := e.key(t, nc2)
		o := e.lease(t, other, "node-a")
		err := e.advance(o, k, []byte("c8"), time.Time{})
		if !errors.Is(err, dsync.ErrWrongLease) {
			t.Errorf("another partition's lease = %v, want ErrWrongLease", err)
		}
	})
}

// Acceptance 3: the cursor commits and rolls back with the caller's transaction (DM-19.I1).
func TestCursorRollsBackWithTheCallersTransaction(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		k := e.key(t, nc1)
		a := e.lease(t, k, "node-a")
		boom := errors.New("inventory write failed")

		// A rolled-back claim leaves no row.
		err := e.tx(e.a, func(ctx context.Context, tx store.Tx) error {
			if _, err := e.store.Claim(ctx, tx, k, a); err != nil {
				return err
			}
			return boom
		})
		if !errors.Is(err, boom) {
			t.Fatalf("tx = %v", err)
		}
		err = e.tx(e.a, func(ctx context.Context, tx store.Tx) error { _, err := e.store.Get(ctx, tx, k); return err })
		if !errors.Is(err, dsync.ErrNotFound) {
			t.Fatalf("after a rolled-back claim, Get = %v, want ErrNotFound", err)
		}

		e.claim(t, k, a)
		if err := e.full(a, k, []byte("committed")); err != nil {
			t.Fatal(err)
		}
		before := e.get(t, k)

		// A rolled-back advance, resync and pause leave the committed row as it was.
		err = e.tx(e.a, func(ctx context.Context, tx store.Tx) error {
			if _, err := e.store.Advance(ctx, tx, k, a, dsync.Move{Cookie: cookie(t, []byte("rolled-back")), LastChange: time.Now()}); err != nil {
				return err
			}
			if _, err := e.store.RequireResync(ctx, tx, k, a); err != nil {
				return err
			}
			if _, err := e.store.PauseConnection(ctx, tx, k.Connection); err != nil {
				return err
			}
			return boom
		})
		if !errors.Is(err, boom) {
			t.Fatalf("tx = %v", err)
		}
		if after := e.get(t, k); after != before {
			t.Fatalf("row changed by a rolled-back transaction:\n before %v\n after  %v", before, after)
		}
		if _, ck, err := e.position(t, k, a); err != nil || !bytes.Equal(ck.Bytes(), []byte("committed")) {
			t.Fatalf("cookie = %q, %v; want the committed one", ck.Bytes(), err)
		}
	})
}

type op struct {
	name string
	run  func(e *env, tx store.Tx, ctx context.Context, k dsync.Key, l jobs.Lease) error
	to   dsync.State
}

func ops(t *testing.T) []op {
	ck := cookie(t, []byte("op-cookie"))
	return []op{
		{"Advance", func(e *env, tx store.Tx, ctx context.Context, k dsync.Key, l jobs.Lease) error {
			_, err := e.store.Advance(ctx, tx, k, l, dsync.Move{Cookie: ck})
			return err
		}, dsync.StateIncremental},
		{"CompleteFull", func(e *env, tx store.Tx, ctx context.Context, k dsync.Key, l jobs.Lease) error {
			_, err := e.store.CompleteFull(ctx, tx, k, l, dsync.FullSync{At: time.Now().Add(-time.Second), Cookie: ck})
			return err
		}, dsync.StateIncremental},
		{"RequireResync", func(e *env, tx store.Tx, ctx context.Context, k dsync.Key, l jobs.Lease) error {
			_, err := e.store.RequireResync(ctx, tx, k, l)
			return err
		}, dsync.StateResyncRequired},
	}
}

var states = []dsync.State{dsync.StateInitialSync, dsync.StateIncremental, dsync.StateResyncRequired, dsync.StatePaused}

// seedState puts a cursor in state s by walking the legal path from creation, using the store alone.
func (e *env) seedState(t *testing.T, k dsync.Key, l jobs.Lease, s dsync.State) {
	t.Helper()
	e.claim(t, k, l)
	steps := map[dsync.State][]string{
		dsync.StateInitialSync:    nil,
		dsync.StateIncremental:    {"full"},
		dsync.StateResyncRequired: {"full", "resync"},
		dsync.StatePaused:         {"pause"},
	}[s]
	for _, st := range steps {
		err := e.tx(e.a, func(ctx context.Context, tx store.Tx) error {
			switch st {
			case "full":
				_, err := e.store.CompleteFull(ctx, tx, k, l, dsync.FullSync{At: time.Now().Add(-time.Minute), Cookie: cookie(t, []byte("seed")), IssuingDSA: dc1})
				return err
			case "resync":
				_, err := e.store.RequireResync(ctx, tx, k, l)
				return err
			}
			_, err := e.store.PauseConnection(ctx, tx, k.Connection)
			return err
		})
		if err != nil {
			t.Fatalf("seed %s via %s: %v", s, st, err)
		}
	}
	if got := e.get(t, k).State; got != s {
		t.Fatalf("seeded state = %s, want %s", got, s)
	}
}

// Acceptance 4: every operation from every state. A refused move is a typed error and leaves the row alone.
func TestTransitionMatrix(t *testing.T) {
	ok := map[string]map[dsync.State]bool{
		"Advance":       {dsync.StateIncremental: true},
		"CompleteFull":  {dsync.StateInitialSync: true, dsync.StateResyncRequired: true},
		"RequireResync": {dsync.StateIncremental: true, dsync.StateResyncRequired: true},
	}
	each(t, func(t *testing.T, e *env) {
		n := 0
		for _, o := range ops(t) {
			for _, from := range states {
				n++
				// A new connection-scoped partition per case, so cases do not share a row.
				p, err := dsync.GraphPartition(fmt.Sprintf("p%d", n))
				if err != nil {
					t.Fatal(err)
				}
				k := dsync.Key{Connection: e.conn, Partition: p}
				l := e.lease(t, k, "node-a")
				e.seedState(t, k, l, from)
				before := e.get(t, k)
				err = e.tx(e.a, func(ctx context.Context, tx store.Tx) error { return o.run(e, tx, ctx, k, l) })
				after := e.get(t, k)
				if ok[o.name][from] {
					if err != nil {
						t.Errorf("%s from %s = %v, want success", o.name, from, err)
					}
					continue
				}
				var te *dsync.TransitionError
				if !errors.Is(err, dsync.ErrIllegalTransition) || !errors.As(err, &te) || te.From != from || te.To != o.to {
					t.Errorf("%s from %s = %v, want a TransitionError{%s -> %s}", o.name, from, err, from, o.to)
				}
				if after != before {
					t.Errorf("%s from %s changed the row:\n before %v\n after  %v", o.name, from, before, after)
				}
			}
		}
	})
}

// The Go lifecycle and the trigger agree on all sixteen pairs, so a writer that is not the store cannot skip
// a step either: paused straight to incremental, incremental back to initial_sync.
func TestLifecycleMatrixMatchesTheDatabase(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		n := 0
		for _, from := range states {
			for _, to := range states {
				n++
				p, _ := dsync.GraphPartition(fmt.Sprintf("m%d", n))
				k := dsync.Key{Connection: e.conn, Partition: p}
				// The raw row satisfies every CHECK in every state: a full sync time, no cookie.
				err := e.tx(e.a, func(ctx context.Context, tx store.Tx) error {
					_, err := tx.Exec(ctx, `INSERT INTO public.sync_cursors (tenant_id, connection_id, partition, state, last_full_sync_at, lease_fencing_token)
						VALUES (NULLIF(current_setting('app.tenant_id', true), '')::uuid, $1::uuid, $2, $3, now(), 1)`, string(k.Connection), string(k.Partition), string(from))
					return err
				})
				if err != nil {
					t.Fatalf("seed %s: %v", from, err)
				}
				err = e.tx(e.a, func(ctx context.Context, tx store.Tx) error {
					_, err := tx.Exec(ctx, `UPDATE public.sync_cursors SET state = $3 WHERE connection_id = $1::uuid AND partition = $2`, string(k.Connection), string(k.Partition), string(to))
					return err
				})
				want := from == to || dsync.CanTransition(from, to)
				if want && err != nil {
					t.Errorf("%s -> %s refused by the database: %v", from, to, err)
				}
				if !want && store.SQLState(err) != "AD403" {
					t.Errorf("%s -> %s = %v, want the guard's AD403", from, to, err)
				}
			}
		}
		for _, c := range []struct{ from, to dsync.State }{
			{dsync.StatePaused, dsync.StateIncremental}, {dsync.StateIncremental, dsync.StateInitialSync}, {dsync.StateResyncRequired, dsync.StateInitialSync},
		} {
			if dsync.CanTransition(c.from, c.to) {
				t.Errorf("%s -> %s must be illegal", c.from, c.to)
			}
		}
	})
}

// A suspended connection pauses its cursors; resumption sets resync_required and drops the cookie.
func TestSuspendPausesAndResumeRequiresResync(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		k1, k2 := e.key(t, nc1), e.key(t, nc2)
		l1, l2 := e.lease(t, k1, "node-a"), e.lease(t, k2, "node-a")
		e.seedState(t, k1, l1, dsync.StateIncremental)
		e.seedState(t, k2, l2, dsync.StateInitialSync)
		var n int64
		err := e.tx(e.a, func(ctx context.Context, tx store.Tx) (err error) {
			n, err = e.store.PauseConnection(ctx, tx, e.conn)
			return
		})
		if err != nil || n != 2 {
			t.Fatalf("pause = %d, %v; want 2 cursors", n, err)
		}
		for _, k := range []dsync.Key{k1, k2} {
			if got := e.get(t, k).State; got != dsync.StatePaused {
				t.Errorf("%s = %s, want paused", k.Partition, got)
			}
		}
		// The lease holder is stopped by the state, whatever its token.
		if err := e.advance(l1, k1, []byte("late"), time.Time{}); !errors.Is(err, dsync.ErrIllegalTransition) {
			t.Errorf("advance while paused = %v, want ErrIllegalTransition", err)
		}
		// Pausing again changes nothing.
		_ = e.tx(e.a, func(ctx context.Context, tx store.Tx) (err error) {
			n, err = e.store.PauseConnection(ctx, tx, e.conn)
			return
		})
		if n != 0 {
			t.Errorf("second pause touched %d cursors", n)
		}
		err = e.tx(e.a, func(ctx context.Context, tx store.Tx) (err error) {
			n, err = e.store.ResumeConnection(ctx, tx, e.conn)
			return
		})
		if err != nil || n != 2 {
			t.Fatalf("resume = %d, %v", n, err)
		}
		for _, k := range []dsync.Key{k1, k2} {
			c := e.get(t, k)
			if c.State != dsync.StateResyncRequired || c.HasCookie || c.IssuingDSA != "" {
				t.Errorf("%s after resume = %v, want resync_required with no cookie", k.Partition, c)
			}
		}
		if c := e.get(t, k1); c.LastFullSync.IsZero() {
			t.Error("resume dropped last_full_sync_at: it is the age of the inventory")
		}
		// A resync completes to incremental.
		if err := e.full(l1, k1, []byte("fresh")); err != nil {
			t.Fatalf("resync: %v", err)
		}
	})
}

// Acceptance 5: tenant Y sees no row of tenant X and cannot write one; no method returns the cookie.
func TestTenantIsolation(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		k := e.key(t, nc1)
		a := e.lease(t, k, "node-a")
		e.seedState(t, k, a, dsync.StateIncremental)
		before := e.get(t, k)

		err := e.tx(e.b, func(ctx context.Context, tx store.Tx) error { _, err := e.store.Get(ctx, tx, k); return err })
		if !errors.Is(err, dsync.ErrNotFound) {
			t.Errorf("tenant B Get = %v, want ErrNotFound", err)
		}
		var list []dsync.Cursor
		if err := e.tx(e.b, func(ctx context.Context, tx store.Tx) (err error) {
			list, err = e.store.List(ctx, tx, k.Connection)
			return
		}); err != nil || len(list) != 0 {
			t.Errorf("tenant B List = %v, %v; want nothing", list, err)
		}
		err = e.tx(e.b, func(ctx context.Context, tx store.Tx) error { _, _, err := e.store.Position(ctx, tx, k, a); return err })
		if !errors.Is(err, dsync.ErrNotFound) {
			t.Errorf("tenant B Position = %v, want ErrNotFound", err)
		}
		// B cannot create a cursor on A's connection (the connection is not B's), nor change A's.
		err = e.tx(e.b, func(ctx context.Context, tx store.Tx) error { _, err := e.store.Claim(ctx, tx, k, a); return err })
		if !errors.Is(err, dsync.ErrUnknownConnection) {
			t.Errorf("tenant B Claim on A's connection = %v, want ErrUnknownConnection", err)
		}
		err = e.tx(e.b, func(ctx context.Context, tx store.Tx) error {
			_, err := e.store.Advance(ctx, tx, k, a, dsync.Move{Cookie: cookie(t, []byte("evil"))})
			return err
		})
		if !errors.Is(err, dsync.ErrNotFound) {
			t.Errorf("tenant B Advance = %v, want ErrNotFound", err)
		}
		var n int64
		_ = e.tx(e.b, func(ctx context.Context, tx store.Tx) (err error) {
			n, err = e.store.PauseConnection(ctx, tx, k.Connection)
			return
		})
		if n != 0 {
			t.Errorf("tenant B paused %d of A's cursors", n)
		}
		// Raw SQL cannot reach the row, or forge one for tenant A, either.
		err = e.tx(e.b, func(ctx context.Context, tx store.Tx) error {
			tag, err := tx.Exec(ctx, `UPDATE public.sync_cursors SET state = 'paused'`)
			if err == nil && tag.RowsAffected() != 0 {
				err = errors.New("B updated a row")
			}
			return err
		})
		if err != nil {
			t.Errorf("raw update as B: %v", err)
		}
		err = e.tx(e.b, func(ctx context.Context, tx store.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO public.sync_cursors (tenant_id, connection_id, partition, lease_fencing_token) VALUES ($1::uuid, $2::uuid, 'users', 1)`, e.a.String(), string(e.conn))
			return err
		})
		if store.SQLState(err) != "42501" {
			t.Errorf("B inserting a row for tenant A = %v, want an RLS violation", err)
		}
		if after := e.get(t, k); after != before {
			t.Errorf("A's row changed: %v -> %v", before, after)
		}
		// No tenant at all.
		ctx := context.Background()
		conn, err := e.d.App(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close(ctx)
		raw, err := conn.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer raw.Rollback(ctx)
		_, err = e.store.Get(ctx, raw, k)
		if !errors.Is(err, dsync.ErrNoTenant) {
			t.Errorf("Get without a tenant = %v, want ErrNoTenant", err)
		}
	})
}

// Acceptance 5: the cookie is stored and resumed, and shows in no rendering of any type that carries it.
func TestCookieNeverLeaks(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		k := e.key(t, nc1)
		a := e.lease(t, k, "node-a")
		e.claim(t, k, a)
		if err := e.full(a, k, secretCookie); err != nil {
			t.Fatal(err)
		}
		var list []dsync.Cursor
		if err := e.tx(e.a, func(ctx context.Context, tx store.Tx) (err error) {
			list, err = e.store.List(ctx, tx, k.Connection)
			return
		}); err != nil || len(list) != 1 {
			t.Fatalf("list = %v, %v", list, err)
		}
		cur, ck, err := e.position(t, k, a)
		if err != nil || !bytes.Equal(ck.Bytes(), secretCookie) {
			t.Fatalf("the holder must get the cookie back intact: %q, %v", ck.Bytes(), err)
		}
		if !cur.HasCookie || cur.IssuingDSA != dc1 {
			t.Errorf("cursor = %v", cur)
		}

		// Cursor has no cookie field of any form.
		rt := reflect.TypeOf(dsync.Cursor{})
		for i := 0; i < rt.NumField(); i++ {
			f := rt.Field(i)
			if strings.Contains(strings.ToLower(f.Name), "cookie") && f.Type.Kind() != reflect.Bool {
				t.Errorf("Cursor.%s (%s) can carry the cookie", f.Name, f.Type)
			}
			if f.Type == reflect.TypeOf(dsync.Cookie{}) || f.Type == reflect.TypeOf([]byte(nil)) {
				t.Errorf("Cursor.%s is %s", f.Name, f.Type)
			}
		}

		var logBuf bytes.Buffer
		lg := slog.New(slog.NewJSONHandler(&logBuf, nil))
		lg.Info("cursor", "cursor", cur, "list", list, "cookie", ck)
		lg.Info("cursor", slog.Any("c", list[0]), slog.Any("k", ck))
		renderings := []string{logBuf.String()}
		for _, v := range []any{cur, &cur, list, ck, &ck, struct{ C dsync.Cookie }{ck}, map[string]any{"c": ck}} {
			for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d"} {
				renderings = append(renderings, fmt.Sprintf(verb, v))
			}
		}
		renderings = append(renderings, cur.String(), ck.String(), ck.GoString())
		if b, err := json.Marshal(cur); err == nil {
			renderings = append(renderings, string(b))
		}
		if _, err := json.Marshal(ck); err == nil {
			t.Error("json.Marshal of a Cookie succeeded")
		}
		if _, err := json.Marshal(struct{ C dsync.Cookie }{ck}); err == nil {
			t.Error("json.Marshal of a struct holding a Cookie succeeded")
		}
		hex := fmt.Sprintf("%x", secretCookie)
		for i, r := range renderings {
			if strings.Contains(r, string(secretCookie)) || strings.Contains(r, "SENTINEL") || strings.Contains(strings.ToLower(r), hex) {
				t.Errorf("rendering %d leaks the cookie: %.120q", i, r)
			}
		}

		// A typed error from the store never echoes the cookie either.
		err = e.advance(a, dsync.Key{Connection: e.conn, Partition: "users"}, secretCookie, time.Time{})
		if err == nil || strings.Contains(err.Error(), "SENTINEL") {
			t.Errorf("error for a missing cursor = %v", err)
		}
	})
}

// Input checks that need no database.
func TestKeysLeasesAndCookies(t *testing.T) {
	for _, bad := range []string{"", "x", "00000000-0000-0000-0000-000000000000", "BBBBBBBB-0000-4000-8000-0000000000a1x", "bbbbbbbb-0000-4000-8000-0000000000a1' OR '1'='1"} {
		if _, err := dsync.NCPartition(bad); !errors.Is(err, dsync.ErrInvalid) {
			t.Errorf("NCPartition(%q) = %v, want ErrInvalid", bad, err)
		}
	}
	if p, err := dsync.NCPartition(strings.ToUpper(nc1)); err != nil || string(p) != nc1 {
		t.Errorf("NCPartition upper-case = %q, %v; want the canonical lower-case form", p, err)
	}
	for _, bad := range []string{"", "Users", "1users", "us-ers", "u.sers", strings.Repeat("a", 41)} {
		if _, err := dsync.GraphPartition(bad); !errors.Is(err, dsync.ErrInvalid) {
			t.Errorf("GraphPartition(%q) = %v, want ErrInvalid", bad, err)
		}
	}
	if _, err := dsync.GraphPartition(strings.Repeat("a", 40)); err != nil {
		t.Errorf("a 40 character partition: %v", err)
	}
	if _, err := dsync.NewCookie(nil); !errors.Is(err, dsync.ErrInvalid) {
		t.Errorf("empty cookie = %v", err)
	}
	if _, err := dsync.NewCookie(make([]byte, 64*1024+1)); !errors.Is(err, dsync.ErrInvalid) {
		t.Errorf("oversized cookie = %v", err)
	}
	if !(dsync.Cookie{}).IsZero() {
		t.Error("zero Cookie is not zero")
	}
	in := []byte{1, 2, 3}
	c, _ := dsync.NewCookie(in)
	in[0] = 9
	out := c.Bytes()
	out[1] = 9
	if !bytes.Equal(c.Bytes(), []byte{1, 2, 3}) {
		t.Error("the Cookie shares memory with its input or its output")
	}
	p, _ := dsync.NCPartition(nc1)
	name, err := dsync.LeaseName(dsync.Key{Connection: "aaaaaaaa-0000-4000-8000-000000000001", Partition: p})
	if err != nil || name != "sync.cursor.aaaaaaaa000040008000000000000001.bbbbbbbb000040008000"+"0000000000a1" {
		t.Errorf("LeaseName = %q, %v", name, err)
	}
	if _, err := dsync.LeaseName(dsync.Key{Connection: "nope", Partition: p}); !errors.Is(err, dsync.ErrInvalid) {
		t.Errorf("LeaseName of a bad key = %v", err)
	}
	long, _ := dsync.GraphPartition(strings.Repeat("a", 40))
	if n, _ := dsync.LeaseName(dsync.Key{Connection: "aaaaaaaa-0000-4000-8000-000000000001", Partition: long}); len(n) > 100 {
		t.Errorf("lease name is %d characters; the platform allows 100", len(n))
	}
}

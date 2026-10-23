package audit_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/audit/chain"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/keys"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

func TestMain(m *testing.M) { os.Exit(storetest.Main(m)) }

type fixedKeys struct{}

func (fixedKeys) DEK(context.Context, store.Tx, tenant.ID, uint32) (keys.DEK, error) {
	return keys.DEKFromBytes(1, bytes.Repeat([]byte{9}, keys.DEKSize))
}

type recAnchor struct {
	mu  sync.Mutex
	got []chain.Checkpoint
	err error
}

func (r *recAnchor) Anchor(_ context.Context, c chain.Checkpoint) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.got = append(r.got, c)
	return r.err
}

type rig struct {
	t      *testing.T
	d      *storetest.Database
	db     *store.DB
	ch     *audit.Chainer
	cp     *audit.Checkpointer
	anchor *recAnchor
	id     tenant.ID
}

func setup(t *testing.T, s *storetest.Server) *rig {
	t.Helper()
	d := s.NewDatabase(t)
	d.Migrate(t)
	ctx := context.Background()
	db, err := store.Open(ctx, store.Config{DSN: d.AppDSN()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	r := &rig{t: t, d: d, db: db, anchor: &recAnchor{}}
	r.ch = audit.NewChainer(db)
	r.cp = audit.NewCheckpointer(r.ch, fixedKeys{}, r.anchor)
	r.id = r.newTenant("A")
	return r
}

func (r *rig) newTenant(name string) tenant.ID {
	r.t.Helper()
	id := tenanttest.Seed(r.t, r.d.ExecOwner, name)
	err := r.db.WithTenant(context.Background(), id, func(ctx context.Context, tx store.Tx) error { return r.cp.InitTenant(ctx, tx, id) })
	if err != nil {
		r.t.Fatal(err)
	}
	return id
}

var human = authority.Chain{Requester: authority.Principal{ID: "u1", Kind: authority.Human}}

func ev(id string) audit.Event {
	return audit.Event{ID: id, Kind: "operation.step.applied", At: time.Now(), Actor: human, Component: "test", Outcome: audit.Success,
		Target:  authority.TargetRef{Connection: "c1", GUID: "g-" + id, Class: "user"},
		Changes: []audit.Change{{Attribute: "mail", Before: []string{"a@x"}, After: []string{"b@x"}}, {Attribute: "unicodePwd", Secret: true}}}
}

func (r *rig) append(id tenant.ID, ids ...string) {
	r.t.Helper()
	err := r.db.WithTenant(context.Background(), id, func(ctx context.Context, tx store.Tx) error {
		for _, i := range ids {
			if err := r.ch.Append(ctx, tx, ev(i)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		r.t.Fatal(err)
	}
}

func (r *rig) export(id tenant.ID) chain.Bundle {
	r.t.Helper()
	b, err := audit.NewExporter(r.cp).Export(context.Background(), r.db, id, human, 0, 0)
	if err != nil && !errors.Is(err, audit.ErrAnchor) {
		r.t.Fatal(err)
	}
	return b
}

func (r *rig) pin(id tenant.ID) chain.Options {
	r.t.Helper()
	b, err := r.ownerKeyID(id)
	if err != nil {
		r.t.Fatal(err)
	}
	return chain.Options{Pinned: b}
}

func (r *rig) ownerKeyID(id tenant.ID) ([]string, error) {
	return r.adminStrings(`SELECT key_id FROM audit_checkpoint_key WHERE tenant_id = $1::uuid ORDER BY ordinal`, id.String())
}

// admin runs a statement as the superuser, which is not subject to row-level security: the way a database
// administrator tampers with the rows. (The owner role is subject to FORCE ROW LEVEL SECURITY.)
func (r *rig) admin(sql string, args ...any) error {
	ctx := context.Background()
	c, err := r.d.Admin(ctx)
	if err != nil {
		return err
	}
	defer c.Close(ctx)
	_, err = c.Exec(ctx, sql, args...)
	return err
}

func (r *rig) adminStrings(sql string, args ...any) ([]string, error) {
	ctx := context.Background()
	c, err := r.d.Admin(ctx)
	if err != nil {
		return nil, err
	}
	defer c.Close(ctx)
	rows, err := c.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func each(t *testing.T, fn func(t *testing.T, r *rig)) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) { fn(t, setup(t, s)) })
}

// Acceptance 1: the runtime role cannot UPDATE, DELETE or TRUNCATE the audit tables.
func TestRuntimeRoleCannotRewriteTheAuditTables(t *testing.T) {
	each(t, func(t *testing.T, r *rig) {
		r.append(r.id, "e1", "e2")
		if _, _, err := r.cp.Sign(context.Background(), r.db, r.id); err != nil && !errors.Is(err, audit.ErrAnchor) {
			t.Fatal(err)
		}
		for _, stmt := range []string{
			"UPDATE audit_event SET kind = kind", "DELETE FROM audit_event", "TRUNCATE audit_event",
			"UPDATE audit_checkpoint SET key_id = key_id", "DELETE FROM audit_checkpoint", "TRUNCATE audit_checkpoint",
			"UPDATE audit_checkpoint_key SET key_id = key_id", "DELETE FROM audit_checkpoint_key", "TRUNCATE audit_checkpoint_key",
		} {
			err := r.db.WithTenant(context.Background(), r.id, func(ctx context.Context, tx store.Tx) error {
				_, err := tx.Exec(ctx, stmt)
				return err
			})
			if store.SQLState(err) != "42501" {
				t.Errorf("%q: err = %v (SQLSTATE %q); want 42501 insufficient_privilege", stmt, err, store.SQLState(err))
			}
		}
		for _, stmt := range []string{"DELETE FROM audit_head", "TRUNCATE audit_head"} {
			err := r.db.WithTenant(context.Background(), r.id, func(ctx context.Context, tx store.Tx) error {
				_, err := tx.Exec(ctx, stmt)
				return err
			})
			if store.SQLState(err) != "42501" {
				t.Errorf("%q: err = %v; want 42501", stmt, err)
			}
		}
		// Catalogue view (fitness-audit A1's shape).
		got, err := r.adminStrings(`SELECT t || ':' || p FROM unnest(ARRAY['audit_event','audit_checkpoint','audit_checkpoint_key','audit_head']) t,
			unnest(ARRAY['UPDATE','DELETE','TRUNCATE']) p WHERE has_table_privilege('activediq_app', 'public.' || t, p) ORDER BY 1`)
		if err != nil {
			t.Fatal(err)
		}
		if fmt.Sprint(got) != "[audit_head:UPDATE]" {
			t.Fatalf("runtime role privileges = %v; want only audit_head:UPDATE", got)
		}
	})
}

func TestHeadGuards(t *testing.T) {
	each(t, func(t *testing.T, r *rig) {
		ctx := context.Background()
		other := tenanttest.Seed(t, r.d.ExecOwner, "B")
		run := func(id tenant.ID, sql string, args ...any) error {
			return r.db.WithTenant(ctx, id, func(ctx context.Context, tx store.Tx) error { _, err := tx.Exec(ctx, sql, args...); return err })
		}
		// A head that is not the genesis: refused. A genesis with a caller-supplied future `at`: accepted
		// with at = now().
		if err := run(other, `INSERT INTO audit_head (tenant_id, seq, hash, at) VALUES ($1::uuid, 5, $2, now())`, other.String(), bytes.Repeat([]byte{1}, 32)); store.SQLState(err) != "AD403" {
			t.Errorf("forged head: %v; want AD403", err)
		}
		g := chain.Genesis(mustUUID(other))
		if err := run(other, `INSERT INTO audit_head (tenant_id, seq, hash, at) VALUES ($1::uuid, 0, $2, now() + interval '10 years')`, other.String(), g[:]); err != nil {
			t.Fatalf("genesis head: %v", err)
		}
		var skewed bool
		if err := r.db.WithTenant(ctx, other, func(ctx context.Context, tx store.Tx) error {
			return tx.QueryRow(ctx, `SELECT at > now() + interval '1 day' FROM audit_head`).Scan(&skewed)
		}); err != nil || skewed {
			t.Fatalf("future at survived the genesis trigger (%v, %v)", skewed, err)
		}
		// One head per tenant, and a head only moves forward.
		if err := run(other, `INSERT INTO audit_head (tenant_id, seq, hash, at) VALUES ($1::uuid, 0, $2, now())`, other.String(), g[:]); err == nil {
			t.Error("a second head was created")
		}
		r.append(r.id, "e1", "e2")
		if err := run(r.id, `UPDATE audit_head SET seq = seq - 1`); store.SQLState(err) != "AD403" {
			t.Errorf("head moved back: %v; want AD403", err)
		}
		// A checkpoint for a head that was never chained.
		if err := run(r.id, `INSERT INTO audit_checkpoint (tenant_id, seq, hash, signed_at, key_id, prev_checkpoint_seq, prev_checkpoint_hash, signature)
			VALUES ($1::uuid, 2, $2, now(), $3, 0, $2, $4)`, r.id.String(), bytes.Repeat([]byte{7}, 32), string(bytes.Repeat([]byte("a"), 64)), bytes.Repeat([]byte{1}, 64)); store.SQLState(err) != "AD403" {
			t.Errorf("checkpoint for an unchained head: %v; want AD403", err)
		}
		// RLS: another tenant's rows are invisible and unwritable.
		var n int
		if err := r.db.WithTenant(ctx, other, func(ctx context.Context, tx store.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM audit_event`).Scan(&n)
		}); err != nil || n != 0 {
			t.Errorf("tenant B sees %d of A's events (%v)", n, err)
		}
	})
}

func TestChainVerifiesAndEveryCheckpointIsAnchoredAndExported(t *testing.T) {
	each(t, func(t *testing.T, r *rig) {
		r.append(r.id, "e1", "e2", "e3")
		cp, recorded, err := r.cp.Sign(context.Background(), r.db, r.id)
		if err != nil || !recorded {
			t.Fatalf("sign = %v, %v", recorded, err)
		}
		// Acceptance 3: the written checkpoint reached the anchor...
		if len(r.anchor.got) != 1 || r.anchor.got[0].Seq != cp.Seq || r.anchor.got[0].Seq != 5 {
			t.Fatalf("anchored = %+v; want the checkpoint at seq 5 (2 init events + 3)", r.anchor.got)
		}
		// ...and a second Sign with nothing new records nothing.
		if _, again, err := r.cp.Sign(context.Background(), r.db, r.id); err != nil || again {
			t.Fatalf("second sign recorded=%v err=%v", again, err)
		}
		r.append(r.id, "e4")
		b := r.export(r.id) // signs the head first
		if len(r.anchor.got) != 2 {
			t.Fatalf("the export's checkpoint was not anchored: %d anchored", len(r.anchor.got))
		}
		// ...and is in the export, which the offline verifier accepts.
		if len(b.Checkpoints) != 2 || b.Checkpoints[1].Seq != 6 || len(b.Events) != 6 || len(b.Keys) != 1 {
			t.Fatalf("export: %d checkpoints, %d events, %d keys", len(b.Checkpoints), len(b.Events), len(b.Keys))
		}
		res := chain.Verify(b, r.pin(r.id))
		if res.Status != chain.OK || res.TailUnsigned != 0 {
			t.Fatalf("verify = %+v", res)
		}
		if res := chain.Verify(b, chain.Options{Anchors: r.anchor.got}); res.Status != chain.OK {
			t.Fatalf("verify with SIEM anchors = %+v", res)
		}
		if res := chain.Verify(b, chain.Options{}); res.Status != chain.Unanchored {
			t.Fatalf("verify without a trust root = %s", res.Status)
		}
		// The envelope holds the attribute names and counts but not the values.
		env, _ := chain.ParseEnvelope(b.Events[2].Envelope)
		if len(env.Changes) != 2 || env.Changes[0].Attribute != "mail" || env.Changes[0].AfterCount != 1 || !env.Changes[1].Secret {
			t.Fatalf("changes = %+v", env.Changes)
		}
		if bytes.Contains(b.Events[2].Envelope, []byte("b@x")) {
			t.Fatal("a clear attribute value reached the chain")
		}
		// Export audits itself.
		var exp int
		_ = r.db.WithTenant(context.Background(), r.id, func(ctx context.Context, tx store.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM audit_event WHERE kind = 'audit.exported'`).Scan(&exp)
		})
		if exp != 1 {
			t.Fatalf("audit.exported events = %d; want 1", exp)
		}
	})
}

func TestAnchorFailureKeepsTheCheckpoint(t *testing.T) {
	each(t, func(t *testing.T, r *rig) {
		r.anchor.err = errors.New("sink down")
		r.append(r.id, "e1")
		cp, recorded, err := r.cp.Sign(context.Background(), r.db, r.id)
		if !errors.Is(err, audit.ErrAnchor) || !recorded || cp.Seq != 3 {
			t.Fatalf("sign = %+v %v %v; want recorded with ErrAnchor", cp, recorded, err)
		}
		if b := r.export(r.id); len(b.Checkpoints) != 1 {
			t.Fatalf("export has %d checkpoints; want the recorded one", len(b.Checkpoints))
		}
	})
}

// Acceptance 2, end to end: an edited, deleted or reordered row, changed with the owner's privileges the
// way a database administrator could, fails offline verification.
func TestTamperedDatabaseFailsVerification(t *testing.T) {
	cases := map[string]func(r *rig) error{
		"edited": func(r *rig) error {
			return r.admin(`UPDATE audit_event SET envelope = envelope || '\x00'::bytea WHERE tenant_id = $1::uuid AND seq = 4`, r.id.String())
		},
		"edited-and-rehashed-body": func(r *rig) error {
			return r.admin(`UPDATE audit_event SET hash = prev_hash WHERE tenant_id = $1::uuid AND seq = 4`, r.id.String())
		},
		"deleted": func(r *rig) error {
			return r.admin(`DELETE FROM audit_event WHERE tenant_id = $1::uuid AND seq = 4`, r.id.String())
		},
		"reordered": func(r *rig) error {
			if err := r.admin(`UPDATE audit_event SET seq = seq + 1000 WHERE seq IN (4, 5) AND tenant_id = $1::uuid`, r.id.String()); err != nil {
				return err
			}
			return r.admin(`UPDATE audit_event SET seq = CASE seq WHEN 1004 THEN 5 ELSE 4 END WHERE seq IN (1004, 1005) AND tenant_id = $1::uuid`, r.id.String())
		},
	}
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			each(t, func(t *testing.T, r *rig) {
				r.append(r.id, "e1", "e2", "e3", "e4")
				if _, _, err := r.cp.Sign(context.Background(), r.db, r.id); err != nil && !errors.Is(err, audit.ErrAnchor) {
					t.Fatal(err)
				}
				anchors := append([]chain.Checkpoint(nil), r.anchor.got...)
				if err := tamper(r); err != nil {
					t.Fatal(err)
				}
				var b chain.Bundle
				// The export itself re-signs a checkpoint only when the head moved; here it has not.
				b, err := audit.NewExporter(r.cp).Export(context.Background(), r.db, r.id, human, 0, 0)
				if err != nil && !errors.Is(err, audit.ErrAnchor) {
					t.Fatal(err)
				}
				res := chain.Verify(b, chain.Options{Pinned: r.pin(r.id).Pinned, Anchors: anchors})
				if res.Status != chain.Failed {
					t.Fatalf("tampered chain verified: %+v", res)
				}
			})
		})
	}
}

func TestRolledBackAppendLeavesNothingAndTheChainStaysGapless(t *testing.T) {
	each(t, func(t *testing.T, r *rig) {
		ctx := context.Background()
		boom := errors.New("boom")
		err := r.db.WithTenant(ctx, r.id, func(ctx context.Context, tx store.Tx) error {
			if err := r.ch.Append(ctx, tx, ev("rolled")); err != nil {
				return err
			}
			return boom
		})
		if !errors.Is(err, boom) {
			t.Fatal(err)
		}
		r.append(r.id, "kept")
		b := r.export(r.id)
		for _, e := range b.Events {
			env, _ := chain.ParseEnvelope(e.Envelope)
			if env.EventID == "rolled" {
				t.Fatal("a rolled-back event is in the chain")
			}
		}
		if res := chain.Verify(b, r.pin(r.id)); res.Status != chain.OK {
			t.Fatalf("verify = %+v", res)
		}
	})
}

func TestRetriedAppendIsRecordedOnce(t *testing.T) {
	each(t, func(t *testing.T, r *rig) {
		r.append(r.id, "same", "same")
		r.append(r.id, "same")
		b := r.export(r.id)
		n := 0
		for _, e := range b.Events {
			if env, _ := chain.ParseEnvelope(e.Envelope); env.EventID == "same" {
				n++
			}
		}
		if n != 1 {
			t.Fatalf("event recorded %d times; want once", n)
		}
	})
}

// An ID reused for different content must fail the transaction, never drop the record silently.
func TestReusedEventIDWithDifferentContentFailsClosed(t *testing.T) {
	each(t, func(t *testing.T, r *rig) {
		other := ev("dup")
		other.Target.GUID = "someone-else"
		before := len(r.export(r.id).Events)
		err := r.db.WithTenant(context.Background(), r.id, func(ctx context.Context, tx store.Tx) error {
			if err := r.ch.Append(ctx, tx, ev("dup")); err != nil {
				return err
			}
			return r.ch.Append(ctx, tx, other) // same transaction
		})
		if !errors.Is(err, audit.ErrEventIDReused) {
			t.Fatalf("same-transaction reuse: err = %v; want ErrEventIDReused", err)
		}
		r.append(r.id, "dup")
		err = r.db.WithTenant(context.Background(), r.id, func(ctx context.Context, tx store.Tx) error {
			return r.ch.Append(ctx, tx, other) // later transaction
		})
		if !errors.Is(err, audit.ErrEventIDReused) {
			t.Fatalf("cross-transaction reuse: err = %v; want ErrEventIDReused", err)
		}
		// Only the one genuine record (plus the exports' own events) was kept.
		n := 0
		for _, e := range r.export(r.id).Events {
			if env, _ := chain.ParseEnvelope(e.Envelope); env.EventID == "dup" {
				n++
			}
		}
		if n != 1 || len(r.export(r.id).Events) < before {
			t.Fatalf("dup recorded %d times", n)
		}
	})
}

func TestFailsClosedWhenMiswired(t *testing.T) {
	each(t, func(t *testing.T, r *rig) {
		ctx := context.Background()
		// A store opened without the hook refuses Append.
		bare, err := store.Open(ctx, store.Config{DSN: r.d.AppDSN()})
		if err != nil {
			t.Fatal(err)
		}
		defer bare.Close()
		err = bare.WithTenant(ctx, r.id, func(ctx context.Context, tx store.Tx) error { return r.ch.Append(ctx, tx, ev("x")) })
		if !errors.Is(err, store.ErrNoHook) {
			t.Errorf("append on an unhooked store = %v; want ErrNoHook", err)
		}
		// A tenant with no head cannot append: the commit fails.
		headless := tenanttest.Seed(t, r.d.ExecOwner, "headless")
		err = r.db.WithTenant(ctx, headless, func(ctx context.Context, tx store.Tx) error { return r.ch.Append(ctx, tx, ev("x")) })
		if !errors.Is(err, audit.ErrNoHead) {
			t.Errorf("append for a headless tenant = %v; want ErrNoHead", err)
		}
		// Transaction-control SQL inside a body is refused, so no body can commit around the hook.
		for _, sql := range []string{"COMMIT", "rollback", "SAVEPOINT s", "SELECT 1; COMMIT"} {
			err = r.db.WithTenant(ctx, r.id, func(ctx context.Context, tx store.Tx) error { _, err := tx.Exec(ctx, sql); return err })
			if !errors.Is(err, store.ErrTxControl) {
				t.Errorf("%q = %v; want ErrTxControl", sql, err)
			}
		}
		// A second hook panics.
		func() {
			defer func() {
				if recover() == nil {
					t.Error("a second SetBeforeCommit did not panic")
				}
			}()
			audit.NewChainer(r.db)
		}()
	})
}

func TestConcurrentAppendersLeaveNoGapAndTenantsStaySeparate(t *testing.T) {
	each(t, func(t *testing.T, r *rig) {
		other := r.newTenant("B")
		var wg sync.WaitGroup
		for i := range 32 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				id := r.id
				if i%2 == 1 {
					id = other
				}
				r.append(id, fmt.Sprintf("c%d", i), fmt.Sprintf("d%d", i))
			}()
		}
		wg.Wait()
		for _, id := range []tenant.ID{r.id, other} {
			b := r.export(id)
			// 2 init events + 16 txs x 2 events.
			if len(b.Events) != 34 {
				t.Fatalf("tenant has %d events; want 34", len(b.Events))
			}
			if res := chain.Verify(b, r.pin(id)); res.Status != chain.OK {
				t.Fatalf("verify = %+v", res)
			}
		}
	})
}

func TestKeyRotationKeepsTheChainVerifiable(t *testing.T) {
	each(t, func(t *testing.T, r *rig) {
		ctx := context.Background()
		r.append(r.id, "e1")
		if err := r.cp.Rotate(ctx, r.db, r.id, human); err != nil && !errors.Is(err, audit.ErrAnchor) {
			t.Fatal(err)
		}
		r.append(r.id, "e2")
		b := r.export(r.id)
		if len(b.Keys) != 2 || b.Keys[0].RetiredSeq == 0 || b.Keys[1].RetiredSeq != 0 {
			t.Fatalf("key windows = %+v", b.Keys)
		}
		if b.Checkpoints[len(b.Checkpoints)-1].KeyID != b.Keys[1].KeyID {
			t.Fatal("the newest checkpoint is not signed by the new key")
		}
		ids, _ := r.ownerKeyID(r.id)
		// Rotate cross-signs the new key with the outgoing one, so pinning only the old key vouches for it.
		if res := chain.Verify(b, chain.Options{Pinned: ids[:1]}); res.Status != chain.OK {
			t.Fatalf("verify (old key only) = %+v", res)
		}
		if res := chain.Verify(b, chain.Options{Pinned: ids}); res.Status != chain.OK {
			t.Fatalf("verify (both keys pinned) = %+v", res)
		}
	})
}

func TestPartialExportStartsAtCheckpoint(t *testing.T) {
	each(t, func(t *testing.T, r *rig) {
		ctx := context.Background()
		r.append(r.id, "e1", "e2")
		cp, _, err := r.cp.Sign(ctx, r.db, r.id)
		if err != nil && !errors.Is(err, audit.ErrAnchor) {
			t.Fatal(err)
		}
		r.append(r.id, "e3")
		x := audit.NewExporter(r.cp)
		b, err := x.Export(ctx, r.db, r.id, human, cp.Seq+1, 0)
		if err != nil && !errors.Is(err, audit.ErrAnchor) {
			t.Fatal(err)
		}
		if res := chain.Verify(b, r.pin(r.id)); res.Status != chain.OK {
			t.Fatalf("verify = %+v", res)
		}
		if _, err := x.Export(ctx, r.db, r.id, human, 3, 0); !errors.Is(err, audit.ErrNoBoundary) {
			t.Fatalf("export from a seq with no checkpoint below = %v; want ErrNoBoundary", err)
		}
	})
}

func mustUUID(id tenant.ID) [16]byte {
	u, err := chain.ParseUUID(id.String())
	if err != nil {
		panic(err)
	}
	return u
}

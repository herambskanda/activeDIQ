package audit_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/audit/chain"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

func (r *rig) sign() []chain.Checkpoint {
	r.t.Helper()
	if _, _, err := r.cp.Sign(context.Background(), r.db, r.id); err != nil && !errors.Is(err, audit.ErrAnchor) {
		r.t.Fatal(err)
	}
	cps, err := r.checkpoints(r.id)
	if err != nil {
		r.t.Fatal(err)
	}
	return cps
}

func (r *rig) checkpoints(id tenant.ID) ([]chain.Checkpoint, error) {
	var out []chain.Checkpoint
	err := r.db.WithTenant(context.Background(), id, func(ctx context.Context, tx store.Tx) error {
		var e error
		out, e = audit.ListCheckpoints(ctx, tx, id, 0, 0, 1<<20, false)
		return e
	})
	return out, err
}

type evAt struct {
	seq uint64
	at  time.Time
	id  string
}

func (r *rig) events(id tenant.ID) []evAt {
	r.t.Helper()
	ctx := context.Background()
	c, err := r.d.Admin(ctx)
	if err != nil {
		r.t.Fatal(err)
	}
	defer c.Close(ctx)
	rows, err := c.Query(ctx, `SELECT seq, at, event_id FROM audit_event WHERE tenant_id = $1::uuid ORDER BY seq`, id.String())
	if err != nil {
		r.t.Fatal(err)
	}
	defer rows.Close()
	var out []evAt
	for rows.Next() {
		var e evAt
		if err := rows.Scan(&e.seq, &e.at, &e.id); err != nil {
			r.t.Fatal(err)
		}
		out = append(out, e)
	}
	return out
}

func (r *rig) keySealedLengths(id tenant.ID) []int {
	r.t.Helper()
	ctx := context.Background()
	c, err := r.d.Admin(ctx)
	if err != nil {
		r.t.Fatal(err)
	}
	defer c.Close(ctx)
	rows, err := c.Query(ctx, `SELECT octet_length(sealed_private_key) FROM audit_checkpoint_key WHERE tenant_id = $1::uuid ORDER BY ordinal`, id.String())
	if err != nil {
		r.t.Fatal(err)
	}
	defer rows.Close()
	var out []int
	for rows.Next() {
		var n int
		if err := rows.Scan(&n); err != nil {
			r.t.Fatal(err)
		}
		out = append(out, n)
	}
	return out
}

func (r *rig) callWipe(id tenant.ID, keyID string) (wiped bool, err error) {
	err = r.db.WithTenant(context.Background(), id, func(ctx context.Context, tx store.Tx) error {
		return tx.QueryRow(ctx, `SELECT public.audit_wipe_retired_key($1)`, keyID).Scan(&wiped)
	})
	return wiped, err
}

// Acceptance 1: a rotated-out key's private material is destroyed through the SECURITY DEFINER function,
// and the runtime role cannot do it directly.
func TestRetiredKeyIsWipedThroughSecurityDefiner(t *testing.T) {
	each(t, func(t *testing.T, r *rig) {
		ctx := context.Background()
		r.append(r.id, "e1")
		if got := r.keySealedLengths(r.id); len(got) != 1 || got[0] == 0 {
			t.Fatalf("before rotation: sealed lengths = %v", got)
		}
		if err := r.cp.Rotate(ctx, r.db, r.id, human); err != nil && !errors.Is(err, audit.ErrAnchor) {
			t.Fatal(err)
		}
		if got := r.keySealedLengths(r.id); len(got) != 2 || got[0] != 0 || got[1] == 0 {
			t.Fatalf("after rotation: sealed lengths = %v; want the retired key empty and the current key sealed", got)
		}
		ids, _ := r.ownerKeyID(r.id)

		// The runtime role has no UPDATE of its own.
		err := r.db.WithTenant(ctx, r.id, func(ctx context.Context, tx store.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE audit_checkpoint_key SET sealed_private_key = '\x'::bytea`)
			return err
		})
		if store.SQLState(err) != "42501" {
			t.Errorf("direct UPDATE: %v; want 42501", err)
		}
		// The function is idempotent for a retired key, and refuses the current key.
		if wiped, err := r.callWipe(r.id, ids[0]); err != nil || wiped {
			t.Errorf("second wipe = %v, %v; want false, nil", wiped, err)
		}
		if _, err := r.callWipe(r.id, ids[1]); store.SQLState(err) != "AD403" {
			t.Errorf("wipe of the current key: %v; want AD403", err)
		}
		// Another tenant's key is invisible: row security gives the same answer as an unknown key.
		other := r.newTenant("B")
		if _, err := r.callWipe(other, ids[0]); store.SQLState(err) != "AD403" {
			t.Errorf("wipe of another tenant's key: %v; want AD403", err)
		}
		// Without a tenant context the function refuses.
		err = r.db.WithPlatform(ctx, "test: wipe without a tenant", func(ctx context.Context, tx store.Tx) error {
			var b bool
			return tx.QueryRow(ctx, `SELECT public.audit_wipe_retired_key($1)`, ids[0]).Scan(&b)
		})
		if store.SQLState(err) != "42501" {
			t.Errorf("wipe with no tenant: %v; want 42501", err)
		}
		// A key that is not the newest but has no committed retirement event is refused (seeded as a DBA would).
		if err := r.admin(`UPDATE audit_checkpoint_key SET sealed_private_key = '\x01'::bytea WHERE tenant_id = $1::uuid AND key_id = $2`, r.id.String(), ids[0]); err == nil {
			// the trigger only allows an empty value, so even a superuser cannot restore bytes
			t.Error("the update trigger accepted a non-empty sealed key")
		}
		if err := r.admin(`UPDATE audit_checkpoint_key SET ordinal = ordinal + 10 WHERE tenant_id = $1::uuid`, r.id.String()); err == nil {
			t.Error("the update trigger accepted a change other than the wipe")
		}
		// The chain still verifies and the new key signs.
		r.append(r.id, "e2")
		b := r.export(r.id)
		// The old key is wiped; its public key still vouches for the new one by cross-signature.
		if res := chain.Verify(b, chain.Options{Pinned: ids[:1]}); res.Status != chain.OK {
			t.Fatalf("verify = %+v", res)
		}
	})
}

func TestWipeRefusesAKeyWithoutRetirementEvent(t *testing.T) {
	each(t, func(t *testing.T, r *rig) {
		ids, _ := r.ownerKeyID(r.id)
		// A second key row with no chained retirement of the first (what a forged call would look like).
		if err := r.admin(`INSERT INTO audit_checkpoint_key (tenant_id, key_id, public_key, sealed_private_key, key_version, ordinal)
			VALUES ($1::uuid, repeat('a', 64), decode(repeat('01', 32), 'hex'), '\x01'::bytea, 1, 2)`, r.id.String()); err != nil {
			t.Fatal(err)
		}
		if _, err := r.callWipe(r.id, ids[0]); store.SQLState(err) != "AD403" {
			t.Fatalf("wipe without a retirement event: %v; want AD403", err)
		}
		if got := r.keySealedLengths(r.id); got[0] == 0 {
			t.Fatal("the key was wiped without a retirement event")
		}
	})
}

// cuts is a partitioning whose boundaries the test places itself, so which events share a partition does not
// depend on wall-clock timing: everything before the first cut is partition 0, and so on; after the last cut
// the partition stays open (it ends in the far future).
type cuts struct {
	mu sync.Mutex
	at []time.Time
}

var farFuture = time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)

// rollover installs a cuts partitioning on the rig's checkpointer.
func rollover(t *testing.T, r *rig) (*cuts, audit.Partitions) {
	t.Helper()
	c := &cuts{}
	p := audit.Partitions{
		Start: func(x time.Time) time.Time {
			c.mu.Lock()
			defer c.mu.Unlock()
			start := time.Time{}
			for _, k := range c.at {
				if !k.After(x) {
					start = k
				}
			}
			return start
		},
		End: func(x time.Time) time.Time {
			c.mu.Lock()
			defer c.mu.Unlock()
			for _, k := range c.at {
				if k.After(x) {
					return k
				}
			}
			return farFuture
		},
	}
	r.cp.WithPartitions(p)
	return c, p
}

// cut ends the current partition. The pauses keep every event already appended strictly before the cut and
// every later one strictly after it, whatever the clock resolution between the test and the database.
func (c *cuts) cut() {
	time.Sleep(20 * time.Millisecond)
	c.mu.Lock()
	c.at = append(c.at, time.Now())
	c.mu.Unlock()
	time.Sleep(20 * time.Millisecond)
}

// Acceptance 2 and 3: the last event of every ended partition is checkpointed before it can be purged, only
// fully checkpointed partitions are removed, and the retained chain still verifies.
func TestPartitionBoundaryCheckpointsAndRetentionPurge(t *testing.T) {
	each(t, func(t *testing.T, r *rig) {
		ctx := context.Background()
		cut, parts := rollover(t, r)
		owner, err := store.OpenMaintenance(ctx, store.Config{DSN: r.d.OwnerDSN()})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(owner.Close)
		purger := audit.NewPurger(owner).WithPartitions(parts)
		archive := "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

		r.append(r.id, "e1", "e2")
		cut.cut()
		r.append(r.id, "e3", "e4")
		cut.cut()

		// Nothing is checkpointed at a boundary yet: a purge is refused and removes nothing.
		before := len(r.events(r.id))
		if _, err := purger.Purge(ctx, r.id, audit.PurgeRequest{Before: time.Now(), ArchiveDigest: archive, Actor: human}); !errors.Is(err, audit.ErrNothingToPurge) {
			t.Fatalf("purge with no boundary checkpoint = %v; want ErrNothingToPurge", err)
		}
		if got := len(r.events(r.id)); got != before {
			t.Fatalf("a refused purge removed events: %d -> %d", before, got)
		}

		cps := r.sign()
		evs := r.events(r.id)
		have := map[uint64]bool{}
		for _, c := range cps {
			have[c.Seq] = true
		}
		now := time.Now()
		nBoundaries := 0
		for i, e := range evs {
			last := i == len(evs)-1 || !evs[i+1].at.Before(parts.End(e.at))
			if last && !parts.End(e.at).After(now) {
				nBoundaries++
				if !have[e.seq] {
					t.Errorf("event %d (%s) ends an ended partition and has no checkpoint; checkpoints = %v", e.seq, e.id, have)
				}
			}
		}
		if nBoundaries < 2 {
			t.Fatalf("only %d partitions ended; the test needs two", nBoundaries)
		}
		for i := 1; i < len(cps); i++ {
			if cps[i].PrevSeq != cps[i-1].Seq || cps[i].PrevHash != cps[i-1].Hash {
				t.Fatalf("checkpoint %d does not chain to its predecessor", cps[i].Seq)
			}
		}
		if res := chain.Verify(r.export(r.id), r.pin(r.id)); res.Status != chain.OK {
			t.Fatalf("verify after boundary checkpoints = %+v", res)
		}

		// e5 opens a partition that is not checkpointed and is not purgeable.
		r.append(r.id, "e5")
		var e4 uint64
		for _, e := range r.events(r.id) {
			if e.id == "e4" {
				e4 = e.seq
			}
		}
		if _, err := purger.Purge(ctx, r.id, audit.PurgeRequest{Before: time.Now(), Actor: human}); !errors.Is(err, audit.ErrPurgeNeedsArchive) {
			t.Fatalf("purge with no archive = %v; want ErrPurgeNeedsArchive", err)
		}
		if _, err := purger.Purge(ctx, r.id, audit.PurgeRequest{Before: time.Now().Add(time.Hour), ArchiveDigest: archive, Actor: human}); !errors.Is(err, audit.ErrBadPurgeRequest) {
			t.Fatalf("purge in the future = %v; want ErrBadPurgeRequest", err)
		}
		res, err := purger.Purge(ctx, r.id, audit.PurgeRequest{Before: time.Now(), ArchiveDigest: archive, Actor: human})
		if err != nil {
			t.Fatal(err)
		}
		if res.ToSeq != e4 || res.FromSeq != 1 || res.Events != int64(e4) || res.Boundary.Seq != e4 {
			t.Fatalf("purge = %+v; want seq 1..%d (up to e4)", res, e4)
		}
		left := r.events(r.id)
		if len(left) < 3 || left[0].seq != e4+1 || left[len(left)-1].id != fmt.Sprintf("audit.retention.purged.%d", e4) {
			t.Fatalf("retained events = %+v; want everything after e4 and then the purge event", left)
		}
		sawE5 := false
		for i, e := range left {
			sawE5 = sawE5 || e.id == "e5"
			if e.seq != e4+uint64(i)+1 {
				t.Fatalf("retained events have a gap at %d", e.seq)
			}
		}
		if !sawE5 {
			t.Fatal("e5 was purged with a partition that was not checkpointed")
		}
		if got, _ := r.checkpoints(r.id); len(got) != len(cps) {
			t.Fatalf("a purge changed the checkpoints: %d -> %d", len(cps), len(got))
		}
		// The retained chain verifies from the boundary checkpoint.
		b, err := audit.NewExporter(r.cp).Export(ctx, r.db, r.id, human, res.ToSeq+1, 0)
		if err != nil && !errors.Is(err, audit.ErrAnchor) {
			t.Fatal(err)
		}
		if v := chain.Verify(b, r.pin(r.id)); v.Status != chain.OK {
			t.Fatalf("verify after purge = %+v", v)
		}
		// Nothing more is purgeable, and the runtime role still cannot delete.
		if _, err := purger.Purge(ctx, r.id, audit.PurgeRequest{Before: time.Now(), WithoutArchive: true, Actor: human}); !errors.Is(err, audit.ErrNothingToPurge) {
			t.Fatalf("second purge = %v; want ErrNothingToPurge", err)
		}
	})
}

// Regression: once a purge has deleted the current key's introduction event, a later partition that ends
// must still be signed at its boundary (the key was introduced below the retained range), and the export
// must still verify.
func TestBoundaryCheckpointAfterPurgeRemovedKeyIntroduction(t *testing.T) {
	each(t, func(t *testing.T, r *rig) {
		ctx := context.Background()
		cut, parts := rollover(t, r)
		owner, err := store.OpenMaintenance(ctx, store.Config{DSN: r.d.OwnerDSN()})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(owner.Close)
		purger := audit.NewPurger(owner).WithPartitions(parts)

		r.append(r.id, "e1")
		cut.cut()
		r.append(r.id, "e2")
		r.sign() // boundary checkpoint at e1 (and the head)
		purged, err := purger.Purge(ctx, r.id, audit.PurgeRequest{Before: time.Now(), WithoutArchive: true, Actor: human})
		if err != nil {
			t.Fatal(err)
		}
		if evs := r.events(r.id); evs[0].id == "audit.tenant.initialised" {
			t.Fatalf("the purge kept the key introduction: %+v", evs)
		}
		// The partition holding e2 and the purge event ends; signing must cover it.
		cut.cut()
		r.append(r.id, "e3")
		cps := r.sign()
		last := cps[len(cps)-1]
		if len(cps) < 3 {
			t.Fatalf("checkpoints = %d; want the boundary, the head and the boundary after the purge", len(cps))
		}
		b, err := audit.NewExporter(r.cp).Export(ctx, r.db, r.id, human, purged.ToSeq+1, 0)
		if err != nil && !errors.Is(err, audit.ErrAnchor) {
			t.Fatal(err)
		}
		if res := chain.Verify(b, r.pin(r.id)); res.Status != chain.OK {
			t.Fatalf("verify = %+v (last checkpoint seq %d)", res, last.Seq)
		}
	})
}

// Rows signed at a boundary survive a rotation: Rotate signs the ended partitions under the outgoing key
// before it retires it, so no boundary checkpoint needs a key that is gone.
func TestBoundaryCheckpointsAcrossRotation(t *testing.T) {
	each(t, func(t *testing.T, r *rig) {
		ctx := context.Background()
		cut, _ := rollover(t, r)
		r.append(r.id, "e1")
		cut.cut()
		r.append(r.id, "e2")
		if err := r.cp.Rotate(ctx, r.db, r.id, human); err != nil && !errors.Is(err, audit.ErrAnchor) {
			t.Fatal(err)
		}
		r.append(r.id, "e3")
		r.sign()
		ids, _ := r.ownerKeyID(r.id)
		if res := chain.Verify(r.export(r.id), chain.Options{Pinned: ids[:1]}); res.Status != chain.OK {
			t.Fatalf("verify = %+v", res)
		}
	})
}

// isolatedDB opens a store whose every session defaults to the given isolation level, so the chain hook
// meets a transaction that is not READ COMMITTED.
func (r *rig) isolatedDB(level string) (*store.DB, *audit.Chainer) {
	r.t.Helper()
	db, err := store.Open(context.Background(), store.Config{DSN: r.d.AppDSN() + " default_transaction_isolation='" + level + "'"})
	if err != nil {
		r.t.Fatal(err)
	}
	r.t.Cleanup(db.Close)
	return db, audit.NewChainer(db)
}

// Acceptance 4 (A2): a transaction at REPEATABLE READ or SERIALIZABLE cannot append: the commit hook
// refuses it and the transaction rolls back, so the chain stays gap-free and ordered, also while such
// transactions race READ COMMITTED appenders.
func TestA2NonReadCommittedAppendIsRefusedAndChainStaysGapless(t *testing.T) {
	for _, level := range []string{"repeatable read", "serializable"} {
		t.Run(level, func(t *testing.T) {
			each(t, func(t *testing.T, r *rig) {
				ctx := context.Background()
				iso, ch := r.isolatedDB(level)
				var got string
				if err := iso.WithTenant(ctx, r.id, func(ctx context.Context, tx store.Tx) error {
					return tx.QueryRow(ctx, `SELECT current_setting('transaction_isolation')`).Scan(&got)
				}); err != nil || got != level {
					t.Fatalf("isolation of the test store = %q, %v; want %q", got, err, level)
				}
				base := len(r.events(r.id))

				var wg sync.WaitGroup
				var mu sync.Mutex
				refused, committed := 0, 0
				for i := range 16 {
					wg.Add(1)
					go func() {
						defer wg.Done()
						var err error
						if i%2 == 0 {
							err = iso.WithTenant(ctx, r.id, func(ctx context.Context, tx store.Tx) error {
								return ch.Append(ctx, tx, ev(fmt.Sprintf("iso%d", i)))
							})
						} else {
							err = r.db.WithTenant(ctx, r.id, func(ctx context.Context, tx store.Tx) error {
								return r.ch.Append(ctx, tx, ev(fmt.Sprintf("rc%d", i)))
							})
						}
						mu.Lock()
						defer mu.Unlock()
						switch {
						case i%2 == 0 && errors.Is(err, audit.ErrIsolation):
							refused++
						case i%2 == 1 && err == nil:
							committed++
						default:
							t.Errorf("append %d: err = %v", i, err)
						}
					}()
				}
				wg.Wait()
				if refused != 8 || committed != 8 {
					t.Fatalf("refused %d, committed %d; want 8 and 8", refused, committed)
				}
				evs := r.events(r.id)
				if len(evs) != base+8 {
					t.Fatalf("%d events; want %d (a refused append left an event)", len(evs), base+8)
				}
				for i, e := range evs {
					if e.seq != uint64(i+1) || (i > 0 && e.at.Before(evs[i-1].at)) {
						t.Fatalf("event %d has seq %d at %v: gap or disorder", i, e.seq, e.at)
					}
				}
				if res := chain.Verify(r.export(r.id), r.pin(r.id)); res.Status != chain.OK {
					t.Fatalf("verify = %+v", res)
				}
			})
		})
	}
}

func (r *rig) personalCounts(subject string) (values, subjects int) {
	r.t.Helper()
	ctx := context.Background()
	c, err := r.d.Admin(ctx)
	if err != nil {
		r.t.Fatal(err)
	}
	defer c.Close(ctx)
	if err := c.QueryRow(ctx, `SELECT count(*) FROM public.personal_value WHERE tenant_id = $1::uuid AND subject_ref = $2`, r.id.String(), subject).Scan(&values); err != nil {
		r.t.Fatal(err)
	}
	if err := c.QueryRow(ctx, `SELECT count(*) FROM public.personal_subject WHERE tenant_id = $1::uuid AND subject_ref = $2`, r.id.String(), subject).Scan(&subjects); err != nil {
		r.t.Fatal(err)
	}
	return values, subjects
}

// T-0372 acceptance 1 (A9): a purge deletes, in its own transaction, the personal values only the purged
// events reference, and the salt of a subject left with no value; a subject still referenced by a retained
// event keeps its salt and the retained event's values.
func TestPurgeDeletesPersonalValuesOnlyPurgedEventsReference(t *testing.T) {
	each(t, func(t *testing.T, r *rig) {
		ctx := context.Background()
		cut, parts := rollover(t, r)
		owner, err := store.OpenMaintenance(ctx, store.Config{DSN: r.d.OwnerDSN()})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(owner.Close)
		purger := audit.NewPurger(owner).WithPartitions(parts)

		const otherGUID = "33333333-3333-4333-8333-333333333333"
		other := "dir:" + pConn + ":" + otherGUID
		old := personalEvent("old-both")
		old.Changes = append(old.Changes, audit.Change{Subject: other, Attribute: "title", After: []string{"Analyst"}})
		r.appendEvent(old)
		cut.cut()
		kept := personalEvent("new-one")
		kept.Changes = kept.Changes[:1]
		kept.Changes[0].Before, kept.Changes[0].After = nil, []string{"kept@example.test"}
		kept.Snapshots = nil
		kept.Target.GUID = otherGUID
		kept.Changes[0].Subject = other
		r.appendEvent(kept) // stays in the open partition, so it is not purgeable
		r.sign()

		if v, s := r.personalCounts(pSubject); v != 4 || s != 1 {
			t.Fatalf("before purge subject has %d values, %d salts; want 4, 1", v, s)
		}
		res, err := purger.Purge(ctx, r.id, audit.PurgeRequest{Before: time.Now(), WithoutArchive: true, Actor: human})
		if err != nil {
			t.Fatal(err)
		}
		if res.PersonalValues != 5 || res.PersonalSubjects != 1 {
			t.Fatalf("purge removed %d values, %d salts; want 5, 1", res.PersonalValues, res.PersonalSubjects)
		}
		if v, s := r.personalCounts(pSubject); v != 0 || s != 0 {
			t.Fatalf("purged-only subject keeps %d values, %d salts", v, s)
		}
		if v, s := r.personalCounts(other); v != 1 || s != 1 {
			t.Fatalf("subject of a retained event has %d values, %d salts; want 1, 1", v, s)
		}
	})
}

type heldRecorder struct{ got []audit.HoldBlock }

func (h *heldRecorder) RetentionHeld(_ context.Context, _ tenant.ID, b audit.HoldBlock) {
	h.got = append(h.got, b)
}

func (r *rig) setHold(on bool) {
	r.t.Helper()
	c, err := r.d.Admin(context.Background())
	if err != nil {
		r.t.Fatal(err)
	}
	defer c.Close(context.Background())
	tag, err := c.Exec(context.Background(), `UPDATE public.personal_subject SET hold = $3 WHERE tenant_id = $1::uuid AND subject_ref = $2`, r.id.String(), pSubject, on)
	if err != nil || tag.RowsAffected() != 1 {
		r.t.Fatalf("set hold: rows=%d err=%v", tag.RowsAffected(), err)
	}
}

func (r *rig) hasEvent(id string) bool {
	for _, e := range r.events(r.id) {
		if e.id == id {
			return true
		}
	}
	return false
}

// A9 (T-0576, ADR-0005 rule 11): a held subject with an event in the middle of three purgeable partitions.
// Only the earlier partition is purged; nothing from the held partition on is deleted (no event, value or
// salt); audit.retention.held is appended and PurgeResult.BlockedByHold is set; the alerter is told. After
// release the next run purges the rest. Removing the hold check in Purger.Purge makes this test fail.
func TestLegalHoldSuspendsPurgeFromHeldPartition(t *testing.T) {
	each(t, func(t *testing.T, r *rig) {
		ctx := context.Background()
		cut, parts := rollover(t, r)
		owner, err := store.OpenMaintenance(ctx, store.Config{DSN: r.d.OwnerDSN()})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(owner.Close)
		alerts := &heldRecorder{}
		purger := audit.NewPurger(owner).WithPartitions(parts).WithHoldAlerter(alerts)

		r.append(r.id, "p1a", "p1b")
		cut.cut()
		r.appendEvent(personalEvent("p2-held"))
		r.append(r.id, "p2b")
		cut.cut()
		r.append(r.id, "p3a", "p3b")
		cut.cut()
		r.append(r.id, "p4-open")
		r.sign()
		r.setHold(true)

		res, err := purger.Purge(ctx, r.id, audit.PurgeRequest{Before: time.Now(), WithoutArchive: true, Actor: human})
		if err != nil {
			t.Fatal(err)
		}
		if res.BlockedByHold == nil || res.BlockedByHold.HeldSubjects != 1 {
			t.Fatalf("BlockedByHold = %+v; want one held subject", res.BlockedByHold)
		}
		if r.hasEvent("p1a") || r.hasEvent("p1b") {
			t.Fatal("the partition before the hold was not purged")
		}
		for _, id := range []string{"p2-held", "p2b", "p3a", "p3b", "p4-open"} {
			if !r.hasEvent(id) {
				t.Fatalf("event %s from the held partition on was deleted", id)
			}
		}
		if v, s := r.personalCounts(pSubject); v == 0 || s != 1 {
			t.Fatalf("held subject has %d values, %d salts; want values kept and 1 salt", v, s)
		}
		held := 0
		for _, e := range r.events(r.id) {
			if strings.HasPrefix(e.id, "audit.retention.held.") {
				held++
			}
		}
		if held != 1 || len(alerts.got) != 1 || alerts.got[0].OldestRetainedSeq != res.BlockedByHold.OldestRetainedSeq {
			t.Fatalf("held events = %d, alerts = %+v", held, alerts.got)
		}
		b, err := audit.NewExporter(r.cp).Export(ctx, r.db, r.id, human, res.BlockedByHold.OldestRetainedSeq, 0)
		if err != nil && !errors.Is(err, audit.ErrAnchor) {
			t.Fatal(err)
		}
		if v := chain.Verify(b, r.pin(r.id)); v.Status != chain.OK {
			t.Fatalf("verify after a held purge = %+v", v)
		}

		// The hold stands: a second run purges nothing more and says so again.
		res, err = purger.Purge(ctx, r.id, audit.PurgeRequest{Before: time.Now(), WithoutArchive: true, Actor: human})
		if err != nil || res.BlockedByHold == nil || res.Events != 0 {
			t.Fatalf("second run under hold = %+v, %v", res, err)
		}
		if !r.hasEvent("p2-held") {
			t.Fatal("event deleted while the hold stands")
		}

		// Acceptance 2: released, the blocked partitions purge normally.
		r.setHold(false)
		r.sign()
		res, err = purger.Purge(ctx, r.id, audit.PurgeRequest{Before: time.Now(), WithoutArchive: true, Actor: human})
		if err != nil || res.BlockedByHold != nil || res.Events == 0 {
			t.Fatalf("run after release = %+v, %v", res, err)
		}
		if r.hasEvent("p2-held") || r.hasEvent("p3b") {
			t.Fatal("blocked partitions were not purged after release")
		}
		if v, s := r.personalCounts(pSubject); v != 0 || s != 0 {
			t.Fatalf("released subject has %d values, %d salts; want 0, 0", v, s)
		}
	})
}

// A hold on a subject in the oldest partition: nothing is purged, the held event is appended, no error.
func TestLegalHoldInOldestPartitionPurgesNothing(t *testing.T) {
	each(t, func(t *testing.T, r *rig) {
		ctx := context.Background()
		cut, parts := rollover(t, r)
		owner, err := store.OpenMaintenance(ctx, store.Config{DSN: r.d.OwnerDSN()})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(owner.Close)
		purger := audit.NewPurger(owner).WithPartitions(parts)
		r.appendEvent(personalEvent("old-held"))
		cut.cut()
		r.sign()
		r.setHold(true)
		res, err := purger.Purge(ctx, r.id, audit.PurgeRequest{Before: time.Now(), WithoutArchive: true, Actor: human})
		if err != nil || res.BlockedByHold == nil || res.Events != 0 || res.PersonalValues != 0 {
			t.Fatalf("purge = %+v, %v", res, err)
		}
		if v, s := r.personalCounts(pSubject); v == 0 || s != 1 {
			t.Fatalf("held subject has %d values, %d salts", v, s)
		}
	})
}

// Acceptance 3: an event about a directory object whose change values carry no subject is refused, so
// every person event is findable by a hold.
func TestPersonEventWithoutSubjectIsRefused(t *testing.T) {
	e := personalEvent("no-subject")
	e.Changes[0].Subject = ""
	if err := e.Validate(); !errors.Is(err, audit.ErrInvalidEvent) {
		t.Fatalf("Validate = %v; want ErrInvalidEvent", err)
	}
	if err := personalEvent("with-subject").Validate(); err != nil {
		t.Fatalf("Validate with subject = %v", err)
	}
}

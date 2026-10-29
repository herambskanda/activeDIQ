package floorpg_test

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/updateverify"
	"github.com/skenzeriq/activediq/internal/platform/updateverify/floorpg"
)

func TestMain(m *testing.M) { os.Exit(storetest.Main(m)) }

func setup(t *testing.T, s *storetest.Server) (*floorpg.Store, *storetest.Database) {
	t.Helper()
	d := s.NewDatabase(t)
	d.Migrate(t)
	db, err := store.Open(context.Background(), store.Config{DSN: d.AppDSN()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	st, err := floorpg.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	return st, d
}

var t0 = time.Date(2026, 10, 1, 12, 0, 0, 123456000, time.UTC)

func high() updateverify.Floor {
	return updateverify.Floor{Root: 3, Timestamp: 40, Snapshot: 30, Targets: 20, NewestSigning: t0, Committed: "1.10.2"}
}

func TestEmptyLoadsZero(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		st, _ := setup(t, s)
		got, err := st.Load(context.Background())
		if err != nil || got != (updateverify.Floor{}) {
			t.Fatalf("Load = %+v, %v", got, err)
		}
	})
}

// Acceptance 1: Raise with lower values lowers no stored field.
func TestRaiseNeverLowers(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		st, _ := setup(t, s)
		ctx := context.Background()
		if err := st.Raise(ctx, high()); err != nil {
			t.Fatal(err)
		}
		lowers := []updateverify.Floor{
			{Root: 1, Timestamp: 1, Snapshot: 1, Targets: 1, NewestSigning: t0.Add(-time.Hour), Committed: "1.9"},
			{}, // all zero values
			{Committed: "1.10"},
		}
		for _, l := range lowers {
			if err := st.Raise(ctx, l); err != nil {
				t.Fatalf("Raise(%+v): %v", l, err)
			}
			if got, err := st.Load(ctx); err != nil || got != high() {
				t.Fatalf("after Raise(%+v): %+v, %v; want %+v", l, got, err, high())
			}
		}
		// A mixed raise lifts only the higher fields.
		if err := st.Raise(ctx, updateverify.Floor{Root: 9, Timestamp: 2, NewestSigning: t0.Add(time.Minute), Committed: "1.11"}); err != nil {
			t.Fatal(err)
		}
		want := updateverify.Floor{Root: 9, Timestamp: 40, Snapshot: 30, Targets: 20, NewestSigning: t0.Add(time.Minute), Committed: "1.11"}
		if got, err := st.Load(ctx); err != nil || got != want {
			t.Fatalf("mixed raise: %+v, %v; want %+v", got, err, want)
		}
	})
}

func TestRaiseRefusals(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		st, _ := setup(t, s)
		ctx := context.Background()
		if err := st.Raise(ctx, updateverify.Floor{Root: 1 << 63}); err == nil {
			t.Error("out-of-range version accepted")
		}
		if err := st.Raise(ctx, updateverify.Floor{Committed: "not-a-version"}); err == nil {
			t.Error("malformed committed version accepted")
		}
		if got, _ := st.Load(ctx); got != (updateverify.Floor{}) {
			t.Errorf("a refused raise changed the floor: %+v", got)
		}
	})
}

func TestConcurrentRaisesKeepTheMaximum(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		st, _ := setup(t, s)
		ctx := context.Background()
		var wg sync.WaitGroup
		for i := 1; i <= 20; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				v := "1." + string(rune('0'+i%10)) // 1.1 .. 1.9, 1.0
				if err := st.Raise(ctx, updateverify.Floor{Root: uint64(i), Committed: v}); err != nil {
					t.Error(err)
				}
			}()
		}
		wg.Wait()
		got, err := st.Load(ctx)
		if err != nil || got.Root != 20 || got.Committed != "1.9" {
			t.Fatalf("Load = %+v, %v; want root 20, committed 1.9", got, err)
		}
	})
}

// Acceptance 2: a database half restored from an earlier backup is outvoted by the host half and healed.
func TestDualHealsRestoredDatabase(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		st, d := setup(t, s)
		ctx := context.Background()
		host := &updateverify.MemoryFloor{}
		dual := updateverify.Dual{Database: st, Host: host}
		if err := dual.Raise(ctx, high()); err != nil {
			t.Fatal(err)
		}
		// "Restore": the owner puts an earlier state back (the guard trigger is disabled as a restore would).
		if err := d.ExecOwner(ctx, `ALTER TABLE public.update_verifier_floor DISABLE TRIGGER update_verifier_floor_guard;
			UPDATE public.update_verifier_floor SET root_version = 1, timestamp_version = 1, snapshot_version = 1,
			targets_version = 1, newest_signing = NULL, committed = ''`); err != nil {
			t.Fatal(err)
		}
		if got, _ := st.Load(ctx); got.Root != 1 || got.Committed != "" {
			t.Fatalf("restore did not take: %+v", got)
		}
		got, err := dual.Load(ctx)
		if err != nil || got != high() {
			t.Fatalf("Dual.Load = %+v, %v; want %+v", got, err, high())
		}
		if healed, _ := st.Load(ctx); healed != high() {
			t.Fatalf("database half not healed: %+v", healed)
		}
	})
}

func TestDatabaseRefusesLoweringAndDeletion(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		st, d := setup(t, s)
		ctx := context.Background()
		if err := st.Raise(ctx, high()); err != nil {
			t.Fatal(err)
		}
		for _, sql := range []string{
			`UPDATE public.update_verifier_floor SET root_version = 1`,
			`UPDATE public.update_verifier_floor SET newest_signing = NULL`,
			`UPDATE public.update_verifier_floor SET committed = ''`,
		} {
			err := d.ExecOwner(ctx, sql)
			if err == nil {
				t.Errorf("%s: owner lowered the floor", sql)
			}
		}
		app, err := d.App(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer app.Close(ctx)
		for _, sql := range []string{`DELETE FROM public.update_verifier_floor`, `TRUNCATE public.update_verifier_floor`} {
			if _, err := app.Exec(ctx, sql); err == nil {
				t.Errorf("runtime role ran %s", sql)
			}
		}
		if got, _ := st.Load(ctx); got != high() {
			t.Fatalf("floor changed: %+v", got)
		}
	})
}

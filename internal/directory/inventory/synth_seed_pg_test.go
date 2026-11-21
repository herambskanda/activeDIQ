package inventory_test

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

// TestLabSyntheticLoaderIsIdempotentAndFailsClosed proves the lab loader of T-2195 (lab/seed/synth-candidates.sql):
// it inserts exactly n rows into directory_objects through the real constraints, reruns insert nothing, a second
// seed adds a disjoint set, and a bad seed or n is refused. The 500k run is the same SQL with a bigger n.
func TestLabSyntheticLoaderIsIdempotentAndFailsClosed(t *testing.T) {
	src, err := os.ReadFile("../../../lab/seed/synth-candidates.sql")
	if err != nil {
		t.Fatal(err)
	}
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		ctx := context.Background()
		if err := e.d.ExecOwner(ctx, string(src)); err != nil {
			t.Fatalf("install loader: %v", err)
		}
		const nc = "bbbbbbbb-0000-4000-8000-000000000001"
		load := func(n int, seed string) (int64, error) {
			out, err := e.d.OwnerStrings(ctx, `SELECT lab_synth.load_users($1::uuid,$2::uuid,$3::uuid,$4::bigint,$5)::text`,
				e.a.String(), string(e.adA), nc, int64(n), seed)
			if err != nil {
				return 0, err
			}
			got, err := strconv.ParseInt(out[0], 10, 64)
			return got, err
		}
		count := func() (n int64) {
			if err := e.db.WithTenant(ctx, e.a, func(ctx context.Context, tx store.Tx) error {
				return tx.QueryRow(ctx, `SELECT count(*) FROM public.directory_objects WHERE kind='user' AND observed_dsa='lab-synthetic'`).Scan(&n)
			}); err != nil {
				t.Fatal(err)
			}
			return n
		}
		if got, err := load(2000, "a"); err != nil || got != 2000 {
			t.Fatalf("first load = %d, %v; want 2000", got, err)
		}
		if got, err := load(2000, "a"); err != nil || got != 0 {
			t.Fatalf("rerun inserted %d, %v; want 0 (idempotent)", got, err)
		}
		if got, err := load(2500, "a"); err != nil || got != 500 {
			t.Fatalf("grow inserted %d, %v; want 500", got, err)
		}
		if got, err := load(100, "b"); err != nil || got != 100 {
			t.Fatalf("second seed inserted %d, %v; want 100 (disjoint)", got, err)
		}
		if n := count(); n != 2600 {
			t.Fatalf("visible synthetic users = %d, want 2600", n)
		}
		for name, c := range map[string]struct {
			n    int
			seed string
		}{"zero n": {0, "a"}, "bad seed": {5, "A;drop"}, "empty seed": {5, ""}} {
			if _, err := load(c.n, c.seed); err == nil || !strings.Contains(err.Error(), "lab_synth.load_users") {
				t.Errorf("%s: err = %v, want a refusal from the loader", name, err)
			}
		}
	})
}

// TestLabSyntheticLoaderTiming is the opt-in 500k measurement (ACTIVEDIQ_LAB_SYNTH_ROWS=500000); its output is
// quoted in the runbook. Skipped by default: it is a measurement, not a unit test.
func TestLabSyntheticLoaderTiming(t *testing.T) {
	n, _ := strconv.Atoi(os.Getenv("ACTIVEDIQ_LAB_SYNTH_ROWS"))
	if n <= 0 {
		t.Skip("needs ACTIVEDIQ_LAB_SYNTH_ROWS to measure")
	}
	src, err := os.ReadFile("../../../lab/seed/synth-candidates.sql")
	if err != nil {
		t.Fatal(err)
	}
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		ctx := context.Background()
		if err := e.d.ExecOwner(ctx, string(src)); err != nil {
			t.Fatal(err)
		}
		t0 := time.Now()
		out, err := e.d.OwnerStrings(ctx, `SELECT lab_synth.load_users($1::uuid,$2::uuid,$3::uuid,$4::bigint,'a')::text`,
			e.a.String(), string(e.adA), "bbbbbbbb-0000-4000-8000-000000000001", int64(n))
		if err != nil || out[0] != strconv.Itoa(n) {
			t.Fatalf("load = %v, %v", out, err)
		}
		t.Logf("%d synthetic users inserted in %v", n, time.Since(t0))
	})
}

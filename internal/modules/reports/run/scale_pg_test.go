package run_test

import (
	"context"
	"os"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/modules/reports/run"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

// sortP95Budget is ADR-0010's sort budget for a 1M-row stored result (T-0972 confirms or replaces it).
const sortP95Budget = 3 * time.Second

// TestSortP95OnLargeStoredResult (AC-22, T-0972 acceptance 2) samples the first page of a sort, both directions,
// ACTIVEDIQ_REPORTS_SORT_SAMPLES times (default 30) on an n-row run and fails when p95 is over the ADR-0010
// budget. n is ACTIVEDIQ_REPORTS_LARGE_ROWS (opt-in: it is a measurement; CI scale tier sets 1000000).
func TestSortP95OnLargeStoredResult(t *testing.T) {
	n, _ := strconv.Atoi(os.Getenv("ACTIVEDIQ_REPORTS_LARGE_ROWS"))
	if n <= 0 {
		t.Skip("needs ACTIVEDIQ_REPORTS_LARGE_ROWS to measure")
	}
	samples := 30
	if v, _ := strconv.Atoi(os.Getenv("ACTIVEDIQ_REPORTS_SORT_SAMPLES")); v > 0 {
		samples = v
	}
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		ctx := context.Background()
		big := storeBigRun(t, e, n)
		for _, desc := range []bool{false, true} {
			var d []time.Duration
			for range samples {
				t0 := time.Now()
				p, err := e.svc.Page(ctx, e.tid, chainOf(alice), big.ID, run.PageQuery{Limit: 50, SortBy: "sam", Desc: desc})
				if err != nil || len(p.Rows) != 50 {
					t.Fatalf("sort desc=%v: %v rows=%d", desc, err, len(p.Rows))
				}
				d = append(d, time.Since(t0))
			}
			slices.Sort(d)
			p95 := d[min(len(d)-1, (len(d)*95+99)/100-1)]
			t.Logf("sort desc=%-5v n=%d samples=%d min=%v p50=%v p95=%v max=%v", desc, n, samples, d[0], d[len(d)/2], p95, d[len(d)-1])
			if p95 > sortP95Budget {
				t.Errorf("sort desc=%v p95 %v exceeds ADR-0010 budget %v", desc, p95, sortP95Budget)
			}
		}
	})
}

// firstPageBudget is the §5 first-page budget the spec states for a 100k-object tenant (reports-2a §5, AC-22).
const firstPageBudget = 5 * time.Second

// TestRunJobAtScaleFirstPageAndCount (AC-22) runs the real run job over ACTIVEDIQ_REPORTS_SCALE_OBJECTS objects
// (opt-in; 100000 for the benchmark), then reads the first 50 rows and the row count. It times the job (the
// copy into the stored result) and the first page separately and fails above the §5 budget for the page.
// Scope: the run pipeline over the harness dataset. The shipped Users definition over a synced Samba lab is
// the part this harness cannot reach (see the T-0972 advance note).
func TestRunJobAtScaleFirstPageAndCount(t *testing.T) {
	n, _ := strconv.Atoi(os.Getenv("ACTIVEDIQ_REPORTS_SCALE_OBJECTS"))
	if n <= 0 {
		t.Skip("needs ACTIVEDIQ_REPORTS_SCALE_OBJECTS to measure")
	}
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		ctx := context.Background()
		if err := e.d.ExecOwner(ctx, `INSERT INTO public.rpt_objects (tenant_id, connection_id, object_guid, nc_guid, sam, enabled)
			SELECT $2::uuid, $3::uuid, gen_random_uuid(), $4::uuid, 'bulk' || lpad(g::text, 8, '0'), g % 5 <> 0
			FROM generate_series(1, $1::int) g`, n, e.tid.String(), report.GUIDString(conn1), report.GUIDString(nc1)); err != nil {
			t.Fatal(err)
		}
		if err := e.d.ExecOwner(ctx, `ANALYZE public.rpt_objects`); err != nil {
			t.Fatal(err)
		}
		r := e.create(alice, `{}`)
		t0 := time.Now()
		e.work()
		jobTime := time.Since(t0)
		got := e.get(r.ID)
		if got.State != run.StateSucceeded || got.RowCount == nil || *got.RowCount < int64(n) {
			t.Fatalf("run = %s / %s rows=%v (want >= %d)", got.State, got.Failure, got.RowCount, n)
		}
		t1 := time.Now()
		p, err := e.svc.Page(ctx, e.tid, chainOf(alice), r.ID, run.PageQuery{Limit: 50})
		page := time.Since(t1)
		if err != nil || len(p.Rows) != 50 || p.Run.RowCount == nil || *p.Run.RowCount != *got.RowCount {
			t.Fatalf("first page: %v rows=%d", err, len(p.Rows))
		}
		t.Logf("objects=%d rows=%d job=%v first50+count=%v", n, *got.RowCount, jobTime.Round(time.Millisecond), page.Round(time.Microsecond))
		if page > firstPageBudget {
			t.Errorf("first page %v exceeds the §5 budget %v", page, firstPageBudget)
		}
	})
}

// TestPerDCRunAtTheReadCap times a per-DC run whose candidates × DCs sit exactly at the cap (T-0972 acceptance 5,
// row P5). ACTIVEDIQ_REPORTS_PERDC_CANDIDATES objects (max 65535, the harness GUID width) × 5 DCs; the default cap
// is the PROPOSED 250,000, so 50000 is the boundary. The reader is the script of perdc_pg_test.go: the number
// measured is the run's own overhead (batching, row updates, digest), not DC latency.
func TestPerDCRunAtTheReadCap(t *testing.T) {
	n, _ := strconv.Atoi(os.Getenv("ACTIVEDIQ_REPORTS_PERDC_CANDIDATES"))
	if n <= 0 {
		t.Skip("needs ACTIVEDIQ_REPORTS_PERDC_CANDIDATES to measure")
	}
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setupWith(t, s, &pdConf{n: 1}) // object 0; the rest are bulk-inserted (serial inserts of 50k rows take minutes)
		if err := e.d.ExecOwner(context.Background(), `INSERT INTO public.rpt_objects (tenant_id, connection_id, object_guid, nc_guid, sam, enabled)
			SELECT $2::uuid, $3::uuid, ('77000000-0000-0000-0000-00000000' || lpad(to_hex(g), 4, '0'))::uuid, $4::uuid, 'u' || lpad(g::text, 3, '0'), true
			FROM generate_series(1, $1::int - 1) g`, n, e.tid.String(), report.GUIDString(conn1), report.GUIDString(nc1)); err != nil {
			t.Fatal(err)
		}
		f := &fakeDCs{dcs: []string{"dc1", "dc2", "dc3", "dc4", "dc5"},
			logon: func(i int, dc string) time.Time { return logonBase.Add(time.Duration(i) * time.Second) }}
		e.perDC(f)
		e.svc.PerDCReadCap = n * 5
		r := e.create(alice, pdColumns)
		t0 := time.Now()
		e.work()
		el := time.Since(t0)
		got := e.get(r.ID)
		if got.State != run.StateSucceeded {
			t.Fatalf("at the cap: %s / %s", got.State, got.Failure)
		}
		reads, objs, _, _ := f.snapshot()
		t.Logf("candidates=%d dcs=5 reads=%d (cap %d): %v, %d reader calls, %d objects", n, n*5, n*5, el.Round(time.Millisecond), reads, objs)
		if objs != n {
			t.Errorf("objects read = %d, want %d", objs, n)
		}
	})
}

package export_test

import (
	"context"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"os"
	"runtime"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/modules/reports/export"
	"github.com/skenzeriq/activediq/internal/modules/reports/run"
	pexport "github.com/skenzeriq/activediq/internal/platform/export"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

// TestLargeExportTimings exports a large stored result to CSV and XLSX through the real service and job and
// reports rows/s, file size and the peak heap. Opt-in (ACTIVEDIQ_REPORTS_LARGE_ROWS=<n>) like the run package's
// page timings; the advance note of T-0963 quotes it. Rows are written through the guards a run job passes,
// and the run carries the true digest of what was written, so the job's digest check is exercised too.
func TestLargeExportTimings(t *testing.T) {
	n, _ := strconv.Atoi(os.Getenv("ACTIVEDIQ_REPORTS_LARGE_ROWS"))
	if n <= 0 {
		t.Skip("needs ACTIVEDIQ_REPORTS_LARGE_ROWS to measure")
	}
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		stored := map[int]run.Run{}
		// PDF and HTML are capped far below n: they are timed at their caps, on runs of their own.
		for _, c := range []struct {
			f    export.Format
			rows int
			col  string // a run of the same columns inside the reuse window is the earlier run
		}{{export.CSV, n, "sam"}, {export.XLSX, n, "sam"}, {export.PDF, int(export.PDFCap), "enabled"}, {export.HTML, int(export.HTMLCap), "display"}} {
			f, n := c.f, c.rows
			big, ok := stored[n]
			if !ok {
				big = e.storedRun(n, c.col)
				stored[n] = big
			}
			var peak atomic.Uint64
			stop := make(chan struct{})
			done := make(chan struct{})
			go func() {
				defer close(done)
				var ms runtime.MemStats
				for {
					select {
					case <-stop:
						return
					case <-time.After(20 * time.Millisecond):
						runtime.ReadMemStats(&ms)
						if ms.HeapAlloc > peak.Load() {
							peak.Store(ms.HeapAlloc)
						}
					}
				}
			}()
			runtime.GC()
			t0 := time.Now()
			x := e.export(alice, big.ID, f)
			el := time.Since(t0)
			close(stop)
			<-done
			if x.State != export.StateSucceeded || x.RowCount == nil || *x.RowCount != int64(n) {
				t.Fatalf("%s: state %s rows %v failure %v", f, x.State, x.RowCount, x.Failure)
			}
			t.Logf("%-4s %d rows -> %d KB in %v (%.0f rows/s), peak heap %d MB", f, n, *x.ByteSize>>10, el.Round(time.Millisecond), float64(n)/el.Seconds(), peak.Load()>>20)
		}
	})
}

// storedRun finishes a run of n rows without executing it: the rows are written through the guards a run job
// passes and the run carries the true digest of what was written, so an export's digest check is exercised too.
//
// A run of the same runner, columns and scope inside the reuse window is the earlier run, so a test that needs
// several names a different column each time (sam, enabled or display).
func (e *env) storedRun(n int, col ...string) run.Run {
	column := "sam"
	if len(col) > 0 {
		column = col[0]
	}
	idx := map[string]int{"sam": 0, "enabled": 1, "display": 2}[column]
	t := e.t
	ctx := context.Background()
	sample := e.finishedRun(alice)
	_, srows := apiRows(e, alice, sample.ID)
	cell := srows[0][idx]
	cells, _ := jsonv2.Marshal([]report.Cell{cell})
	var sortKeys string
	if err := e.db.WithTenant(ctx, e.tid, func(ctx context.Context, tx store.Tx) error {
		return tx.QueryRow(ctx, `SELECT sort_keys::text FROM public.report_run_rows WHERE run_id = $1::uuid LIMIT 1`, sample.ID.String()).Scan(&sortKeys)
	}); err != nil {
		t.Fatal(err)
	}
	big, _, err := e.runs.Create(ctx, run.CreateInput{Tenant: e.tid, Chain: chainOf(alice), DefinitionID: "tst-01", Params: jsontext.Value(`{"columns":["` + column + `"]}`)})
	if err != nil {
		t.Fatal(err)
	}
	own := func(q string, args ...any) {
		t.Helper()
		if err := e.exec(q, args...); err != nil {
			t.Fatal(err)
		}
	}
	own(`UPDATE public.report_runs SET state = 'running', attempt = 1, started_at = now() WHERE id = $1::uuid`, big.ID.String())
	t0 := time.Now()
	for lo := int64(0); lo < int64(n); lo += 5000 {
		hi := min(lo+5000, int64(n))
		own(`INSERT INTO public.report_run_rows (tenant_id, run_id, row_key, ordinal, cells, sort_keys)
		SELECT NULLIF(current_setting('app.tenant_id', true), '')::uuid, $1::uuid, 'k' || g, g, $2::jsonb, $3::jsonb
		FROM generate_series($4::bigint, $5::bigint - 1) AS g`, big.ID.String(), string(cells), sortKeys, lo, hi)
	}
	t.Logf("%d rows stored in %v", n, time.Since(t0))
	d := pexport.NewDigester([]string{column})
	for range n {
		d.Row([]pexport.Typed{{Tag: cell.DigestTag(), Value: cell.DigestValue()}})
	}
	sum := d.Sum()
	own(`UPDATE public.report_runs SET state = 'succeeded', row_count = $2, digest = $3, as_of = now(), expires_at = now() + interval '1 hour',
	finished_at = now() WHERE id = $1::uuid`, big.ID.String(), int64(n), sum[:])
	return big
}

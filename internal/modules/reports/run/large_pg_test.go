package run_test

import (
	"context"
	"encoding/base64"
	jsonv2 "encoding/json/v2"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/modules/reports/run"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

// TestLargeResultPageTimings stores a large result and times the page reads (ordinal order, a sort both ways,
// a deep page). It is opt-in (ACTIVEDIQ_REPORTS_LARGE_ROWS=<n>) because it is a measurement, not a unit test;
// the advance note of T-0959 quotes its output. Rows are inserted through the same guards a job passes.
func TestLargeResultPageTimings(t *testing.T) {
	n, _ := strconv.Atoi(os.Getenv("ACTIVEDIQ_REPORTS_LARGE_ROWS"))
	if n <= 0 {
		t.Skip("needs ACTIVEDIQ_REPORTS_LARGE_ROWS to measure")
	}
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		ctx := context.Background()
		sample := e.create(alice, `{}`)
		e.work()
		first, err := e.svc.Page(ctx, e.tid, chainOf(alice), sample.ID, run.PageQuery{Limit: 1})
		if err != nil || len(first.Rows) != 1 {
			t.Fatalf("sample page: %v %+v", err, first)
		}
		cells, _ := jsonv2.Marshal(first.Rows[0].Cells)
		var sortKeys string
		if err := e.db.WithTenant(ctx, e.tid, func(ctx context.Context, tx store.Tx) error {
			return tx.QueryRow(ctx, `SELECT sort_keys::text FROM public.report_run_rows WHERE run_id = $1::uuid LIMIT 1`, sample.ID.String()).Scan(&sortKeys)
		}); err != nil {
			t.Fatal(err)
		}
		big := e.create(alice, `{"columns":["sam"]}`)
		if err := e.ownerExec(`UPDATE public.report_runs SET state = 'running', attempt = 1, started_at = now() WHERE id = $1::uuid`, big.ID.String()); err != nil {
			t.Fatal(err)
		}
		t0 := time.Now()
		for lo := int64(0); lo < int64(n); lo += 5000 { // batches, as the job writes them
			hi := min(lo+5000, int64(n))
			if err := e.ownerExec(`INSERT INTO public.report_run_rows (tenant_id, run_id, row_key, ordinal, cells, sort_keys)
				SELECT NULLIF(current_setting('app.tenant_id', true), '')::uuid, $1::uuid, 'k' || g, g, $2::jsonb,
				       jsonb_build_object('sam', lpad(((g::bigint * 7919) % $5::bigint)::text, 10, '0'))
				FROM generate_series($4::bigint, $6::bigint - 1) AS g WHERE $3 <> ''`, big.ID.String(), string(cells), sortKeys, lo, int64(n), hi); err != nil {
				t.Fatal(err)
			}
		}
		t.Logf("%d rows inserted in %v", n, time.Since(t0))
		if err := e.ownerExec(`UPDATE public.report_runs SET state = 'succeeded', row_count = $2, digest = decode(repeat('ab', 32), 'hex'),
			as_of = now(), expires_at = now() + interval '1 hour', finished_at = now() WHERE id = $1::uuid`, big.ID.String(), int64(n)); err != nil {
			t.Fatal(err)
		}
		if err := e.d.ExecOwner(ctx, `ANALYZE public.report_run_rows`); err != nil { // autovacuum does this in production
			t.Fatal(err)
		}
		time1 := func(name string, q run.PageQuery) {
			t0 := time.Now()
			p, err := e.svc.Page(ctx, e.tid, chainOf(alice), big.ID, q)
			if err != nil || len(p.Rows) == 0 {
				t.Fatalf("%s: %v rows=%d", name, err, len(p.Rows))
			}
			t.Logf("%-28s %v", name, time.Since(t0))
		}
		time1("ordinal, first page", run.PageQuery{Limit: 100})
		time1("ordinal, offset n/2", run.PageQuery{Limit: 100, Cursor: cursorAt(t, big.ID.String(), "", false, int64(n/2))})
		time1("sort asc, first page", run.PageQuery{Limit: 100, SortBy: "sam"})
		time1("sort desc, first page", run.PageQuery{Limit: 100, SortBy: "sam", Desc: true})
		time1("sort asc, offset n/2", run.PageQuery{Limit: 100, SortBy: "sam", Cursor: cursorAt(t, big.ID.String(), "sam", false, int64(n/2))})
	})
}

// cursorAt builds a page cursor the way the service does (the cursor is opaque to clients, not to this test).
func cursorAt(t *testing.T, runID, sort string, desc bool, off int64) string {
	t.Helper()
	b, err := jsonv2.Marshal(map[string]any{"v": 1, "r": runID, "s": sort, "d": desc, "o": off})
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

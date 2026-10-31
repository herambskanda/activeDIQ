package reports_test

import (
	"archive/zip"
	"bytes"
	"context"
	jsonv2 "encoding/json/v2"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/modules/reports/export"
	"github.com/skenzeriq/activediq/internal/modules/reports/run"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

// raw performs a request and returns the recorder, for a body that is not JSON (a download).
func (e *apiEnv) raw(who, method, target string) *httptest.ResponseRecorder {
	e.t.Helper()
	r := httptest.NewRequest(method, target, nil)
	r.Header.Set("X-Who", who)
	r.Header.Set("X-Tenant", e.tid.String())
	r.RemoteAddr = "203.0.113.7:4444"
	w := httptest.NewRecorder()
	e.srv.ServeHTTP(w, r)
	return w
}

// The export API end to end (AC-24, AC-28, acceptance 5 and 6): create answers 202 with a Location, the job
// writes the file, the creator downloads it with attachment headers, anyone else gets 404, a delete answers
// 204 and the file is gone, a cap refusal is a 422 problem with the count and the options.
func TestExportAPI(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := apiSetup(t, s)
		_, rn := e.do(alice, "POST", "/api/v1/reports/runs", `{"definitionId":"tst-01"}`)
		runID := rn["id"].(string)
		if code, m := e.do(alice, "POST", "/api/v1/reports/runs/"+runID+"/exports", `{"format":"csv"}`); code != 409 || errCode(m) != "run_not_ready" {
			t.Fatalf("export of a queued run: %d %v", code, m)
		}
		e.work()
		code, x := e.do(alice, "POST", "/api/v1/reports/runs/"+runID+"/exports", `{"format":"xlsx"}`)
		if code != 202 || x["state"] != "queued" || x["format"] != "xlsx" || x["fileName"] != nil {
			t.Fatalf("create: %d %v", code, x)
		}
		id := x["id"].(string)
		if w := e.raw(alice, "POST", "/api/v1/reports/runs/"+runID+"/exports"); w.Code != 415 && w.Code != 400 {
			t.Errorf("create without a body: %d", w.Code)
		}
		if code, m := e.do(alice, "POST", "/api/v1/reports/runs/"+runID+"/exports", `{"format":"pdf"}`); code != 400 || errCode(m) != "format_unavailable" {
			t.Errorf("pdf: %d %v", code, m)
		}
		if w := e.raw(alice, "GET", "/api/v1/reports/exports/"+id+"/file"); w.Code != 409 {
			t.Errorf("download before the job ran: %d", w.Code)
		}
		e.work()
		code, g := e.do(alice, "GET", "/api/v1/reports/exports/"+id, "")
		if code != 200 || g["state"] != "succeeded" || g["rowCount"] != float64(3) || !hex64.MatchString(g["digest"].(string)) || g["digest"] != rn["digest"] && rn["digest"] != nil {
			t.Fatalf("get: %d %v", code, g)
		}
		_, done := e.do(alice, "GET", "/api/v1/reports/runs/"+runID, "")
		if g["digest"] != done["digest"] {
			t.Errorf("export digest %v, run digest %v", g["digest"], done["digest"])
		}
		w := e.raw(alice, "GET", "/api/v1/reports/exports/"+id+"/file")
		cd := w.Header().Get("Content-Disposition")
		if w.Code != 200 || !strings.HasPrefix(cd, "attachment;") || !strings.Contains(cd, ".xlsx") || w.Header().Get("X-Content-Type-Options") != "nosniff" ||
			!strings.Contains(w.Header().Get("Content-Type"), "spreadsheetml") {
			t.Fatalf("download: %d %v", w.Code, w.Header())
		}
		if _, err := zip.NewReader(bytes.NewReader(w.Body.Bytes()), int64(w.Body.Len())); err != nil {
			t.Fatalf("not a workbook: %v", err)
		}
		for _, who := range []string{bob} {
			if w := e.raw(who, "GET", "/api/v1/reports/exports/"+id+"/file"); w.Code != 404 {
				t.Errorf("%s download: %d", who, w.Code)
			}
			if w := e.raw(who, "GET", "/api/v1/reports/exports/"+id); w.Code != 404 {
				t.Errorf("%s get: %d", who, w.Code)
			}
			if w := e.raw(who, "DELETE", "/api/v1/reports/exports/"+id); w.Code != 404 {
				t.Errorf("%s delete: %d", who, w.Code)
			}
		}
		if w := e.raw(alice, "GET", "/api/v1/reports/exports/not-a-uuid/file"); w.Code != 400 && w.Code != 404 {
			t.Errorf("bad id: %d", w.Code)
		}
		if w := e.raw(alice, "DELETE", "/api/v1/reports/exports/"+id); w.Code != 204 {
			t.Fatalf("delete: %d", w.Code)
		}
		if w := e.raw(alice, "GET", "/api/v1/reports/exports/"+id+"/file"); w.Code != 404 {
			t.Errorf("download after delete: %d", w.Code)
		}
		if _, g := e.do(alice, "GET", "/api/v1/reports/exports/"+id, ""); g["state"] != "deleted" {
			t.Errorf("state after delete: %v", g["state"])
		}
		// a cap refusal is a 422 problem naming the count, the cap and the other format
		e.exp.Caps = map[export.Format]int64{export.CSV: 2}
		code, p := e.do(alice, "POST", "/api/v1/reports/runs/"+runID+"/exports", `{"format":"csv"}`)
		b, _ := jsonv2.Marshal(p)
		if code != 422 || !strings.Contains(string(b), "report-row-cap-exceeded") || !strings.Contains(string(b), "This export has 3 rows. CSV allows 2.") || !strings.Contains(string(b), "XLSX") {
			t.Errorf("cap refusal: %d %s", code, b)
		}
	})
}

// count runs a single-count query as the tenant.
func (e *apiEnv) count(sql string) int {
	e.t.Helper()
	var n int
	if err := e.db.WithTenant(context.Background(), e.tid, func(ctx context.Context, tx store.Tx) error { return tx.QueryRow(ctx, sql).Scan(&n) }); err != nil {
		e.t.Fatal(err)
	}
	return n
}

// createReportExport needs reports.export (the route's) and reports.run (checked inside, before any run is
// read; security review of T-0963 F1). A caller whose role was cut back to reports.export alone is refused
// with 403 for a finished run and for an expired one: no export, no job, no audit event, and the expired
// source is not run again (a rerun would start a report the caller may no longer run). The mirror, reports.run
// without reports.export, is refused at the route.
func TestExportNeedsReportsRun(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := apiSetup(t, s)
		_, rn := e.do(alice, "POST", "/api/v1/reports/runs", `{"definitionId":"tst-01"}`)
		runID := rn["id"].(string)
		e.work()
		url := "/api/v1/reports/runs/" + runID + "/exports"
		const exports = `SELECT count(*) FROM public.report_exports`
		const runs = `SELECT count(*) FROM public.report_runs`
		baseRuns := e.count(runs)

		e.door.deny = map[string]bool{"reports.run": true}
		if code, m := e.do(alice, "POST", url, `{"format":"csv"}`); code != 403 {
			t.Fatalf("finished run without reports.run: %d %v", code, m)
		}
		if n := e.count(exports); n != 0 {
			t.Errorf("a refused export left %d report_exports rows", n)
		}
		for _, ev := range e.xsink.ev {
			t.Errorf("a refused export audited %s", ev.Kind)
		}
		e.work() // an export job, had one been queued, would run here
		if n := e.count(exports); n != 0 {
			t.Errorf("report_exports rows after work: %d", n)
		}

		// the same caller, the source run past its retention: the refusal comes before the rerun
		future := time.Now().Add(run.ResultRetention + time.Hour)
		e.svc.Now = func() time.Time { return future }
		e.exp.Now = e.svc.Now
		if code, m := e.do(alice, "POST", url, `{"format":"csv"}`); code != 403 {
			t.Fatalf("expired run without reports.run: %d %v", code, m)
		}
		if n := e.count(runs); n != baseRuns {
			t.Errorf("a refused export started a run: report_runs %d, was %d", n, baseRuns)
		}
		if n := e.count(exports); n != 0 {
			t.Errorf("report_exports rows: %d", n)
		}

		// both permissions: the export is accepted (the rerun itself is covered in package export; the reuse window reads the database clock, which this test does not move)
		e.door.deny = nil
		if code, m := e.do(alice, "POST", url, `{"format":"csv"}`); code != 202 {
			t.Fatalf("expired run with both permissions: %d %v", code, m)
		}

		// reports.run without reports.export is the route's refusal
		e.door.deny = map[string]bool{"reports.export": true}
		if code, m := e.do(alice, "POST", url, `{"format":"csv"}`); code != 403 {
			t.Errorf("without reports.export: %d %v", code, m)
		}
	})
}

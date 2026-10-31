package reports_test

import (
	"archive/zip"
	"bytes"
	jsonv2 "encoding/json/v2"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/modules/reports/export"
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

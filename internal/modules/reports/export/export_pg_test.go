package export_test

import (
	"archive/zip"
	"bytes"
	"context"
	stdcsv "encoding/csv"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode"

	"golang.org/x/net/html"

	"github.com/skenzeriq/activediq/internal/modules/reports/export"
	"github.com/skenzeriq/activediq/internal/modules/reports/run"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz/authztest"
	"github.com/skenzeriq/activediq/internal/platform/export/cellsafe"
	"github.com/skenzeriq/activediq/internal/platform/export/pdf/pdftest"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

func unzip(t *testing.T, b []byte) map[string]string {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatalf("not an xlsx: %v", err)
	}
	out := map[string]string{}
	for _, f := range zr.File {
		rc, _ := f.Open()
		x, _ := io.ReadAll(rc)
		rc.Close()
		out[f.Name] = string(x)
	}
	return out
}

type xcell struct{ ref, style, text string }

var xesc = regexp.MustCompile(`_x([0-9A-Fa-f]{4})_`)

func decodeX(s string) string {
	return xesc.ReplaceAllStringFunc(s, func(m string) string {
		var r rune
		for _, c := range strings.ToLower(m[2:6]) {
			r = r*16 + rune(strings.IndexRune("0123456789abcdef", c))
		}
		return string(r)
	})
}

// sheetCells reads a worksheet with encoding/xml, an independent parser.
func sheetCells(t *testing.T, sheet string) []xcell {
	t.Helper()
	d := xml.NewDecoder(strings.NewReader(sheet))
	var out []xcell
	var cur *xcell
	in := ""
	for {
		tok, err := d.Token()
		if err != nil {
			return out
		}
		switch e := tok.(type) {
		case xml.StartElement:
			in = e.Name.Local
			if in == "c" {
				cur = &xcell{}
				for _, a := range e.Attr {
					switch a.Name.Local {
					case "r":
						cur.ref = a.Value
					case "s":
						cur.style = a.Value
					}
				}
			}
		case xml.CharData:
			if cur != nil && (in == "t" || in == "v") {
				cur.text += string(e)
			}
		case xml.EndElement:
			if e.Name.Local == "c" && cur != nil {
				cur.text = decodeX(cur.text)
				out = append(out, *cur)
				cur = nil
			}
			in = ""
		}
	}
}

// Test_export_digest_equals_run_digest is RP5 (AC-27, AC-50): the digest the run stores, the export record,
// the About sheet and an independent recomputation from the API-visible rows are one value, and it moves
// when a value, a column, a row order or null versus empty moves.
func Test_export_digest_equals_run_digest(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		r := e.finishedRun(alice)
		cols, rows := apiRows(e, alice, r.ID)
		want := canonical(cols, rows)
		if !bytes.Equal(r.Digest, want[:]) {
			t.Fatalf("run digest %x, recomputed %x", r.Digest, want)
		}
		for _, f := range export.Formats() {
			x := e.export(alice, r.ID, f)
			if x.State != export.StateSucceeded || !bytes.Equal(x.Digest, want[:]) || x.RowCount == nil || *x.RowCount != int64(len(hostile)) {
				t.Fatalf("%s export = %+v", f, x)
			}
			body, d, err := e.download(alice, x.ID)
			if err != nil || d.Format != f || len(body) == 0 || int64(len(body)) != *x.ByteSize {
				t.Fatalf("download %s: %v", f, err)
			}
			if f == export.XLSX {
				files := unzip(t, body)
				about := files["xl/worksheets/sheet2.xml"]
				for _, w := range []string{hex.EncodeToString(want[:]), r.ID.String(), "Test accounts", "tst-01@1", "Synced", alice, "Row count"} {
					if !strings.Contains(about, w) {
						t.Errorf("About sheet lacks %q", w)
					}
				}
				if !strings.Contains(files["xl/workbook.xml"], "About") || strings.Index(files["xl/workbook.xml"], "About") > strings.Index(files["xl/workbook.xml"], "Test accounts") {
					t.Errorf("the About sheet is not the first tab: %s", files["xl/workbook.xml"])
				}
			} else if f == export.CSV && strings.Contains(string(body), hex.EncodeToString(want[:])) {
				t.Errorf("CSV carries an About block")
			}
			if f == export.PDF || f == export.HTML {
				// The About block of a PDF and an HTML page states the digest of the rows it holds, and the
				// row count: what an auditor reads is the run's own digest.
				shown := strings.Join(fileText(t, f, body), "")
				if !strings.Contains(shown, hex.EncodeToString(want[:])) {
					t.Errorf("%s: the About block does not carry the run digest", f)
				}
				if !strings.Contains(shown, "Test accounts") || !strings.Contains(shown, r.ID.String()) {
					t.Errorf("%s: the About block lacks the report name or run", f)
				}
			}
		}
		// the digest is sensitive to value, column order, row order and null versus empty
		mut := func(f func(c []string, rs [][]report.Cell) ([]string, [][]report.Cell)) [32]byte {
			c2 := append([]string(nil), cols...)
			rs2 := make([][]report.Cell, len(rows))
			for i := range rows {
				rs2[i] = append([]report.Cell(nil), rows[i]...)
			}
			c2, rs2 = f(c2, rs2)
			return canonical(c2, rs2)
		}
		for name, d := range map[string][32]byte{
			"value": mut(func(c []string, rs [][]report.Cell) ([]string, [][]report.Cell) {
				rs[0][0] = report.TextCell("zz")
				return c, rs
			}),
			"column": mut(func(c []string, rs [][]report.Cell) ([]string, [][]report.Cell) {
				c[0], c[1] = c[1], c[0]
				return c, rs
			}),
			"order": mut(func(c []string, rs [][]report.Cell) ([]string, [][]report.Cell) {
				rs[0], rs[1] = rs[1], rs[0]
				return c, rs
			}),
			"null": mut(func(c []string, rs [][]report.Cell) ([]string, [][]report.Cell) {
				rs[0][2] = report.Absent()
				return c, rs
			}),
		} {
			if d == want {
				t.Errorf("the digest does not move with %s", name)
			}
		}
	})
}

// blobFiles lists the files under the blob root: a refused export leaves none.
func blobFiles(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			out = append(out, p)
		}
		return nil
	})
	return out
}

// AC-24: an export over the cap is refused with the count, the cap and the options; no record, job or file exists.
func TestCapRefusesBeforeAnythingExists(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		r := e.finishedRun(alice)
		n := int64(len(hostile))
		for _, f := range export.Formats() {
			e.exp.Caps = map[export.Format]int64{f: n - 1}
			_, err := e.exp.Create(context.Background(), e.tid, chainOf(alice), r.ID, f)
			var ce *export.CapError
			if !errors.As(err, &ce) || ce.Rows != n || ce.Cap != n-1 || ce.Format != f {
				t.Fatalf("%s: err = %v", f, err)
			}
			var others []export.Format // every other format, which this small run fits in
			for _, o := range export.Formats() {
				if o != f {
					others = append(others, o)
				}
			}
			if !slices.Equal(ce.Alternatives, others) {
				t.Fatalf("%s: alternatives %v, want %v", f, ce.Alternatives, others)
			}
			for _, o := range others {
				if !strings.Contains(ce.Error(), strings.ToUpper(string(o))) {
					t.Fatalf("%s: message %q does not offer %s", f, ce.Error(), o)
				}
			}
		}
		if n := e.count(`SELECT count(*) FROM public.report_exports`); n != 0 {
			t.Fatalf("%d export records after refusals", n)
		}
		if slices.Contains(e.workKinds(), e.exp.Kind().Name) {
			t.Fatal("an export job was queued by a refused export")
		}
		if files := blobFiles(t, e.blobDir); len(files) != 0 {
			t.Fatalf("files after refusals: %v", files)
		}
		if len(e.sink.of(export.KindCreated)) != 0 {
			t.Fatal("a refused export was audited as created")
		}
		// config only lowers the cap
		e.exp.Caps = map[export.Format]int64{export.CSV: 5_000_000}
		for _, f := range export.Formats() {
			e.exp.Caps = map[export.Format]int64{f: 50_000_000}
			if e.exp.Cap(f) != export.HardCap(f) {
				t.Fatalf("a configured cap raised the hard cap of %s to %d", f, e.exp.Cap(f))
			}
		}
		// AC-25 (at the cap): exactly the cap succeeds with every row
		e.exp.Caps = map[export.Format]int64{export.CSV: n, export.XLSX: n}
		for _, f := range export.Formats() {
			if x := e.export(alice, r.ID, f); x.State != export.StateSucceeded || *x.RowCount != n {
				t.Fatalf("%s at the cap: %+v", f, x)
			}
		}
	})
}

// A run that grew past the cap after it was stored is refused by the job (rerun path), not truncated.
func TestJobRefusesOverCapRerun(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		r := e.finishedRun(alice)
		x, err := e.exp.Create(context.Background(), e.tid, chainOf(alice), r.ID, export.CSV)
		if err != nil {
			t.Fatal(err)
		}
		e.exp.Caps = map[export.Format]int64{export.CSV: 3}
		e.work()
		got, _ := e.exp.Get(context.Background(), e.tid, chainOf(alice), x.ID)
		if got.State != export.StateFailed || got.Failure != run.FailRowCapExceeded || got.FailureDetail["rows"] != int64(len(hostile)) || got.FailureDetail["cap"] != 3 {
			t.Fatalf("export = %+v", got)
		}
		if files := blobFiles(t, e.blobDir); len(files) != 0 {
			t.Fatalf("files: %v", files)
		}
		if len(e.sink.of(export.KindFailed)) != 1 {
			t.Fatalf("failed events: %d", len(e.sink.of(export.KindFailed)))
		}
	})
}

// AC-26: hostile values reach CSV and XLSX end to end and no cell can be read as a formula.
func TestHostileValuesAreNeutralInBothFormats(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		r := e.finishedRun(alice)
		_, rows := apiRows(e, alice, r.ID)
		var texts []string
		for _, row := range rows {
			texts = append(texts, string(row[2].DigestValue()))
		}
		csvX := e.export(alice, r.ID, export.CSV)
		body, _, err := e.download(alice, csvX.ID)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.HasPrefix(body, []byte("\xEF\xBB\xBF")) {
			t.Fatal("no UTF-8 BOM")
		}
		recs, err := stdcsv.NewReader(bytes.NewReader(bytes.TrimPrefix(body, []byte("\xEF\xBB\xBF")))).ReadAll()
		if err != nil || len(recs) != len(texts)+1 {
			t.Fatalf("csv: %d records, %v", len(recs), err)
		}
		for i, v := range texts {
			got := recs[i+1][2]
			if cellsafe.Classify(v) == cellsafe.FormulaLead {
				if !strings.HasPrefix(got, "\t") {
					t.Errorf("CSV %q is not neutralised: %q", v, got)
				}
			} else if got != v && !strings.ContainsAny(v, "\r") {
				t.Errorf("CSV changed a plain value %q to %q", v, got)
			}
		}
		xl := e.export(alice, r.ID, export.XLSX)
		xb, _, err := e.download(alice, xl.ID)
		if err != nil {
			t.Fatal(err)
		}
		files := unzip(t, xb)
		if regexp.MustCompile(`<f[ >/]`).MatchString(files["xl/worksheets/sheet1.xml"] + files["xl/worksheets/sheet2.xml"]) {
			t.Fatal("a formula element in the workbook")
		}
		byRef := map[string]xcell{}
		for _, c := range sheetCells(t, files["xl/worksheets/sheet1.xml"]) {
			byRef[c.ref] = c
		}
		for i, v := range texts {
			c, ok := byRef["C"+itoa(i+2)]
			if !ok {
				t.Fatalf("no cell for %q", v)
			}
			if c.text != v {
				t.Errorf("XLSX %q came back as %q", v, c.text)
			}
			if cellsafe.Classify(v) == cellsafe.FormulaLead && c.style != "1" {
				t.Errorf("XLSX %q is not quote-prefixed (style %q)", v, c.style)
			}
		}
	})
}

func itoa(i int) string { return strings.TrimSpace(strings.Repeat(" ", 0) + intStr(i)) }
func intStr(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for ; i > 0; i /= 10 {
		b = append([]byte{byte('0' + i%10)}, b...)
	}
	return string(b)
}

// AC-28 and acceptance 6: one created and one downloaded event with actor, format, row count and digest; an expired
// file is 410; anyone but the creator is refused and audited.
func TestAuditDownloadDenialAndExpiry(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		r := e.finishedRun(alice)
		x := e.export(alice, r.ID, export.CSV)
		if _, _, err := e.download(alice, x.ID); err != nil {
			t.Fatal(err)
		}
		cr, dl := e.sink.of(export.KindCreated), e.sink.of(export.KindDownloaded)
		if len(cr) != 1 || len(dl) != 1 {
			t.Fatalf("created %d, downloaded %d", len(cr), len(dl))
		}
		for _, ev := range append(cr, dl...) {
			if string(ev.Actor.Requester.ID) != alice || detail(ev, "format") != "csv" || detail(ev, "row_count") != intStr(len(hostile)) ||
				detail(ev, "digest") != hex.EncodeToString(r.Digest) || detail(ev, "export_id") != x.ID.String() {
				t.Errorf("%s event = %+v", ev.Kind, ev)
			}
		}
		// the same account and scope but not the creator: 404, audited with the check that failed
		if _, _, err := e.download(bob, x.ID); !errors.Is(err, export.ErrExportNotFound) {
			t.Fatalf("bob: %v", err)
		}
		if _, _, err := e.download(bob, export.NewID()); !errors.Is(err, export.ErrExportNotFound) {
			t.Fatalf("missing: %v", err)
		}
		den := e.sink.of(export.KindDownloadDenied)
		if len(den) != 2 || den[0].Reason != "creator" || den[1].Reason != "exists" || string(den[0].Actor.Requester.ID) != bob {
			t.Fatalf("denied events: %+v", den)
		}
		if _, err := e.exp.Get(context.Background(), e.tid, chainOf(bob), x.ID); !errors.Is(err, export.ErrExportNotFound) {
			t.Fatalf("bob Get: %v", err)
		}
		if _, err := e.exp.Create(context.Background(), e.tid, chainOf(bob), r.ID, export.CSV); !errors.Is(err, run.ErrRunNotFound) {
			t.Fatalf("bob Create: %v", err)
		}
		// a changed scope: 409 and audited
		e.scopes.set(alice, authztest.ReadScope(grant(conn2)))
		if _, _, err := e.download(alice, x.ID); !errors.Is(err, run.ErrScopeChanged) {
			t.Fatalf("scope change: %v", err)
		}
		if d := e.sink.of(export.KindDownloadDenied); len(d) != 3 || d[2].Reason != "scope" {
			t.Fatalf("denied after scope change: %+v", d)
		}
		e.scopes.set(alice, authztest.ReadScope(grant(conn1)))
		// past expiry: 410, audited, and the record reads expired
		*e.clock = e.clock.Add(run.ResultRetention + time.Hour)
		if _, _, err := e.download(alice, x.ID); !errors.Is(err, export.ErrExportExpired) {
			t.Fatalf("expired: %v", err)
		}
		if d := e.sink.of(export.KindDownloadDenied); d[len(d)-1].Reason != "expired" {
			t.Fatalf("expired denial: %+v", d[len(d)-1])
		}
		if got, _ := e.exp.Get(context.Background(), e.tid, chainOf(alice), x.ID); got.State != export.StateExpired {
			t.Fatalf("state %s", got.State)
		}
		if len(e.sink.of(export.KindDownloaded)) != 1 {
			t.Fatal("a refused download was audited as downloaded")
		}
	})
}

// Early delete, in-progress delete, the shared job limit and an unavailable format.
func TestDeleteAndLimits(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		ctx := context.Background()
		r := e.finishedRun(alice)
		if _, err := e.exp.Create(ctx, e.tid, chainOf(alice), r.ID, export.Format("docx")); !errors.Is(err, export.ErrFormatUnavailable) {
			t.Fatalf("docx: %v", err)
		}
		// queued exports count against the shared open-job limit
		var ids []export.ID
		for i := 0; i < run.OpenRunLimit; i++ {
			x, err := e.exp.Create(ctx, e.tid, chainOf(alice), r.ID, export.CSV)
			if err != nil {
				t.Fatalf("export %d: %v", i, err)
			}
			ids = append(ids, x.ID)
		}
		if _, err := e.exp.Create(ctx, e.tid, chainOf(alice), r.ID, export.CSV); !errors.Is(err, run.ErrTooManyJobs) {
			t.Fatalf("over the limit: %v", err)
		}
		if err := e.exp.Delete(ctx, e.tid, chainOf(alice), ids[0]); !errors.Is(err, export.ErrExportInProgress) {
			t.Fatalf("delete while queued: %v", err)
		}
		e.work()
		if err := e.exp.Delete(ctx, e.tid, chainOf(bob), ids[0]); !errors.Is(err, export.ErrExportNotFound) {
			t.Fatalf("bob delete: %v", err)
		}
		if err := e.exp.Delete(ctx, e.tid, chainOf(alice), ids[0]); err != nil {
			t.Fatal(err)
		}
		if err := e.exp.Delete(ctx, e.tid, chainOf(alice), ids[0]); err != nil {
			t.Fatalf("second delete: %v", err)
		}
		if got, _ := e.exp.Get(ctx, e.tid, chainOf(alice), ids[0]); got.State != export.StateDeleted {
			t.Fatalf("state %s", got.State)
		}
		if _, _, err := e.download(alice, ids[0]); !errors.Is(err, export.ErrExportNotFound) {
			t.Fatalf("download after delete: %v", err)
		}
		if len(e.sink.of(export.KindDeleted)) != 1 {
			t.Fatalf("deleted events: %d", len(e.sink.of(export.KindDeleted)))
		}
		if files := blobFiles(t, e.blobDir); len(files) != len(ids)-1 {
			t.Fatalf("%d files after one delete of %d: %v", len(files), len(ids), files)
		}
	})
}

// An export of an expired run follows a new run made as the caller (rerun).
func TestExpiredSourceIsRerun(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		ctx := context.Background()
		r := e.finishedRun(alice)
		*e.clock = e.clock.Add(run.ResultRetention + time.Hour)
		// the sweep has flipped the run (the reuse lookup reads the database clock, which the test does not move)
		if _, err := e.runs.Retention(ctx, e.tid, *e.clock); err != nil {
			t.Fatal(err)
		}
		x, err := e.exp.Create(ctx, e.tid, chainOf(alice), r.ID, export.XLSX)
		if err != nil {
			t.Fatal(err)
		}
		if !x.Rerun || x.RerunOf == nil || *x.RerunOf != r.ID || x.RunID == r.ID {
			t.Fatalf("export = %+v", x)
		}
		e.work()
		got, _ := e.exp.Get(ctx, e.tid, chainOf(alice), x.ID)
		if got.State != export.StateSucceeded || got.RowCount == nil || *got.RowCount != int64(len(hostile)) {
			t.Fatalf("export = %+v", got)
		}
		nr := e.run(alice, got.RunID)
		if !bytes.Equal(got.Digest, nr.Digest) || nr.RerunOf == nil || *nr.RerunOf != r.ID {
			t.Fatalf("new run = %+v", nr)
		}
		if _, _, err := e.download(alice, x.ID); err != nil {
			t.Fatal(err)
		}
	})
}

// The retention sweep flips exports past their expiry (audited by the system), then removes final records.
func TestRetentionExpiresExports(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		ctx := context.Background()
		r := e.finishedRun(alice)
		x := e.export(alice, r.ID, export.CSV)
		later := e.clock.Add(run.ResultRetention + time.Hour)
		res, err := e.runs.Retention(ctx, e.tid, later)
		if err != nil || res.ExportsExpired != 1 {
			t.Fatalf("retention = %+v, %v", res, err)
		}
		ev := e.sink.of(run.KindExportExpired)
		if len(ev) != 1 || detail(ev[0], "export_id") != x.ID.String() || string(ev[0].Actor.Requester.ID) != "reports-retention" {
			t.Fatalf("expired events: %+v", ev)
		}
		*e.clock = later
		if got, _ := e.exp.Get(ctx, e.tid, chainOf(alice), x.ID); got.State != export.StateExpired {
			t.Fatalf("state %s", got.State)
		}
		res, err = e.runs.Retention(ctx, e.tid, later.Add(run.RecordRetention+time.Hour))
		if err != nil || res.ExportRecordsDeleted != 1 {
			t.Fatalf("second sweep = %+v, %v", res, err)
		}
	})
}

// The guard trigger refuses state edges the application never takes.
func TestGuardRefusesBadEdges(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		r := e.finishedRun(alice)
		x := e.export(alice, r.ID, export.CSV)
		for name, sql := range map[string]string{
			"succeeded to running": `UPDATE public.report_exports SET state = 'running' WHERE id = $1::uuid`,
			"file edited":          `UPDATE public.report_exports SET byte_size = 1 WHERE id = $1::uuid`,
			"format changed":       `UPDATE public.report_exports SET format = 'xlsx' WHERE id = $1::uuid`,
			"live record deleted":  `DELETE FROM public.report_exports WHERE id = $1::uuid`,
			"succeeded to failed":  `UPDATE public.report_exports SET state = 'failed', failure_reason = 'internal' WHERE id = $1::uuid`,
		} {
			if err := e.exec(sql, x.ID.String()); err == nil {
				t.Errorf("%s: accepted", name)
			}
		}
	})
}

// Create checks reports.run before it reads the run (security review F1): on a finished run and on an
// expired one, where it would otherwise start a new run. With no Authorizer it fails closed.
func TestCreateNeedsReportsRun(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		ctx := context.Background()
		r := e.finishedRun(alice)
		runs := `SELECT count(*) FROM public.report_runs`
		exports := `SELECT count(*) FROM public.report_exports`
		base := e.count(runs)
		e.authz.deny["reports.run"] = true
		if _, err := e.exp.Create(ctx, e.tid, chainOf(alice), r.ID, export.CSV); !errors.Is(err, export.ErrNotPermitted) {
			t.Fatalf("finished run: %v", err)
		}
		*e.clock = e.clock.Add(run.ResultRetention + time.Hour)
		if _, err := e.exp.Create(ctx, e.tid, chainOf(alice), r.ID, export.CSV); !errors.Is(err, export.ErrNotPermitted) {
			t.Fatalf("expired run: %v", err)
		}
		if n := e.count(runs); n != base {
			t.Errorf("a refused export started a run: %d, was %d", n, base)
		}
		if n := e.count(exports); n != 0 {
			t.Errorf("report_exports rows: %d", n)
		}
		for _, ev := range e.sink.ev {
			if ev.Kind == export.KindCreated {
				t.Errorf("a refused export audited %s", ev.Kind)
			}
		}
		// AG-2 (security review F2): each refusal is one denial event naming actor and permission
		den := e.sink.of(export.KindPermissionDenied)
		if len(den) != 2 {
			t.Fatalf("denial events: %d, want 2 (finished run, expired run)", len(den))
		}
		for _, ev := range den {
			if ev.Actor.Requester.ID != authority.PrincipalID(alice) || ev.Outcome != audit.Denied || ev.Reason != "permission_denied" {
				t.Errorf("denial event: %+v", ev)
			}
			var perm string
			for _, d := range ev.Details {
				if d.Key == "permission" {
					perm = d.Value
				}
			}
			if perm != "reports.run" {
				t.Errorf("denial names permission %q", perm)
			}
		}
		e.exp.Authz = nil
		if _, err := e.exp.Create(ctx, e.tid, chainOf(alice), r.ID, export.CSV); !errors.Is(err, export.ErrNotPermitted) {
			t.Errorf("no authorizer: %v", err)
		}
	})
}

// A refusal that cannot be recorded is not a success and not a bare 403 (AG-2, security review F2): the
// caller gets ErrDenialNotRecorded, and no export row, job or run exists.
func TestRunDenialNotRecordedIsNotRefusedQuietly(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		r := e.finishedRun(alice)
		e.authz.deny["reports.run"] = true
		e.sink.fail = errors.New("audit store down")
		runs, exports := `SELECT count(*) FROM public.report_runs`, `SELECT count(*) FROM public.report_exports`
		baseRuns := e.count(runs)
		_, err := e.exp.Create(context.Background(), e.tid, chainOf(alice), r.ID, export.CSV)
		if !errors.Is(err, export.ErrDenialNotRecorded) || errors.Is(err, export.ErrNotPermitted) {
			t.Fatalf("unrecordable denial: %v", err)
		}
		if n := e.count(exports); n != 0 {
			t.Errorf("report_exports rows: %d", n)
		}
		if n := e.count(runs); n != baseRuns {
			t.Errorf("report_runs %d, was %d", n, baseRuns)
		}
		e.sink.fail = nil
		if got := len(e.sink.of(export.KindPermissionDenied)); got != 0 {
			t.Errorf("denial events recorded despite the failing sink: %d", got)
		}
	})
}

// fileText is what a reader of the file sees as text lines, read with the independent oracle of the format
// (pdftest for PDF, x/net/html for HTML). Either oracle fails t on an action, a script or a link.
func fileText(t *testing.T, f export.Format, body []byte) []string {
	t.Helper()
	switch f {
	case export.PDF:
		return pdftest.Text(t, body)
	case export.HTML:
		return htmlText(t, body)
	}
	t.Fatalf("no text oracle for %s", f)
	return nil
}

// htmlText parses the page with golang.org/x/net/html and returns the text of every cell, header cell and
// About line in document order. It fails on any element or attribute that could act: a script, a frame, an
// object, a link, a form, an image, an event handler, a style attribute or a URL-bearing attribute.
func htmlText(t *testing.T, body []byte) []string {
	t.Helper()
	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	var walk func(n *html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "script", "iframe", "frame", "object", "embed", "a", "form", "img", "link", "base", "input", "button", "svg", "math":
				t.Errorf("the page holds a <%s>", n.Data)
			case "meta":
				ok := false
				for _, a := range n.Attr {
					if a.Key == "http-equiv" && strings.EqualFold(a.Val, "Content-Security-Policy") || a.Key == "charset" || a.Key == "name" {
						ok = true
					}
				}
				if !ok {
					t.Errorf("an unexpected <meta> %v", n.Attr)
				}
			}
			for _, a := range n.Attr {
				if strings.HasPrefix(strings.ToLower(a.Key), "on") || a.Key == "href" || a.Key == "src" || a.Key == "style" || a.Key == "srcdoc" {
					t.Errorf("<%s %s=%q>", n.Data, a.Key, a.Val)
				}
			}
			if n.Data == "td" || n.Data == "th" || n.Data == "dd" || n.Data == "dt" || n.Data == "h1" {
				var b strings.Builder
				var text func(*html.Node)
				text = func(c *html.Node) {
					if c.Type == html.TextNode {
						b.WriteString(c.Data)
					}
					for k := c.FirstChild; k != nil; k = k.NextSibling {
						text(k)
					}
				}
				text(n)
				out = append(out, b.String())
				return
			}
		}
		for k := n.FirstChild; k != nil; k = k.NextSibling {
			walk(k)
		}
	}
	walk(doc)
	return out
}

// shown is how a PDF or an HTML page draws a value: CRLF is one line break, and a control character is the
// visible token <U+XXXX>. The PDF also tokenises format characters (the bidi override), because it has no <bdi>.
func shown(v string, pdf bool) string {
	var b strings.Builder
	rs := []rune(v)
	for i, r := range rs {
		switch {
		case r == '\n' || (r == '\t' && !pdf):
			b.WriteRune(r)
		case r == '\r' && i+1 < len(rs) && rs[i+1] == '\n':
		case unicode.Is(unicode.Cc, r) || pdf && (unicode.Is(unicode.Cf, r) || r == 0x2028 || r == 0x2029):
			fmt.Fprintf(&b, "\u27e8U+%04X\u27e9", r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// AC-3 (FF-SP10): the hostile values of the run reach PDF and HTML end to end, in order, escaped and inert:
// the oracle of each format reads them back as the text they are, and finds no action, script or link.
func TestHostileValuesAreInertInPDFAndHTML(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		r := e.finishedRun(alice)
		_, rows := apiRows(e, alice, r.ID)
		for _, f := range []export.Format{export.PDF, export.HTML} {
			x := e.export(alice, r.ID, f)
			if x.State != export.StateSucceeded {
				t.Fatalf("%s: %+v", f, x)
			}
			body, _, err := e.download(alice, x.ID)
			if err != nil {
				t.Fatal(err)
			}
			lines := fileText(t, f, body) // fails the test on an action, script or link
			// every hostile value appears, in row order, as the text the page shows: an HTML cell is one text
			// node, a PDF cell is drawn a line at a time.
			at := 0
			next := func(want string) bool {
				for ; at < len(lines); at++ {
					if lines[at] == want {
						at++
						return true
					}
				}
				return false
			}
			for i, row := range rows {
				v := string(row[2].DigestValue())
				wants := []string{shown(v, false)}
				if f == export.PDF {
					wants = strings.Split(shown(v, true), "\n")
				}
				for _, want := range wants {
					if want != "" && !next(want) {
						t.Fatalf("%s: row %d value %q (shown %q) not found in order", f, i, v, want)
					}
				}
			}
		}
	})
}

// AC-2 (AC-24): the hard caps of the page formats refuse a larger result with the count, the cap and the
// formats that would take it; nothing is written. A result inside the cap is exported, digest and all.
func TestPageFormatCapsRefuse(t *testing.T) {
	if export.HardCap(export.PDF) != 5_000 || export.HardCap(export.HTML) != 20_000 || export.HardCap(export.CSV) != 1_000_000 || export.HardCap(export.XLSX) != 1_000_000 {
		t.Fatalf("hard caps: pdf %d html %d csv %d xlsx %d", export.HardCap(export.PDF), export.HardCap(export.HTML), export.HardCap(export.CSV), export.HardCap(export.XLSX))
	}
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		ctx := context.Background()
		over := e.storedRun(export.PDFCap + 1)
		var ce *export.CapError
		_, err := e.exp.Create(ctx, e.tid, chainOf(alice), over.ID, export.PDF)
		if !errors.As(err, &ce) || ce.Rows != 5_001 || ce.Cap != 5_000 || ce.Format != export.PDF ||
			!slices.Equal(ce.Alternatives, []export.Format{export.CSV, export.XLSX, export.HTML}) {
			t.Fatalf("pdf over its cap: %v (%+v)", err, ce)
		}
		if msg := ce.Error(); !strings.Contains(msg, "5001 rows") || !strings.Contains(msg, "PDF allows 5000") {
			t.Fatalf("message %q", msg)
		}
		if n := e.count(`SELECT count(*) FROM public.report_exports`); n != 0 || len(blobFiles(t, e.blobDir)) != 0 {
			t.Fatalf("a refused PDF left %d records and files %v", n, blobFiles(t, e.blobDir))
		}
		if slices.Contains(e.workKinds(), e.exp.Kind().Name) {
			t.Fatal("a refused PDF queued a job")
		}
		// the same result is fine as HTML, with its digest
		x := e.export(alice, over.ID, export.HTML)
		if x.State != export.StateSucceeded || *x.RowCount != 5_001 || !bytes.Equal(x.Digest, e.run(alice, over.ID).Digest) {
			t.Fatalf("html at 5001 rows: %+v", x)
		}
		// exactly at the PDF cap succeeds and reproduces the digest
		at := e.storedRun(export.PDFCap, "enabled")
		x = e.export(alice, at.ID, export.PDF)
		if x.State != export.StateSucceeded || *x.RowCount != 5_000 || !bytes.Equal(x.Digest, e.run(alice, at.ID).Digest) {
			t.Fatalf("pdf at its cap: %+v", x)
		}
		// above the HTML cap
		huge := e.storedRun(export.HTMLCap+1, "display")
		_, err = e.exp.Create(ctx, e.tid, chainOf(alice), huge.ID, export.HTML)
		if !errors.As(err, &ce) || ce.Rows != 20_001 || ce.Cap != 20_000 || ce.Format != export.HTML ||
			!slices.Equal(ce.Alternatives, []export.Format{export.CSV, export.XLSX}) {
			t.Fatalf("html over its cap: %v (%+v)", err, ce)
		}
		if _, err = e.exp.Create(ctx, e.tid, chainOf(alice), huge.ID, export.PDF); !errors.As(err, &ce) || ce.Cap != 5_000 {
			t.Fatalf("pdf over html's cap: %v", err)
		}
		if n := e.count(`SELECT count(*) FROM public.report_exports WHERE row_count > 5000 AND format = 'pdf' OR row_count > 20000`); n != 0 {
			t.Fatalf("%d export records for refused exports", n)
		}
	})
}

// A table wider than a PDF page lays out is offered every format but PDF, and a PDF of it is refused.
func TestFormatsForWideTables(t *testing.T) {
	if got := export.FormatsFor(24); !slices.Equal(got, export.Formats()) {
		t.Errorf("24 columns: %v", got)
	}
	if got := export.FormatsFor(25); !slices.Equal(got, []export.Format{export.CSV, export.XLSX, export.HTML}) {
		t.Errorf("25 columns: %v", got)
	}
}

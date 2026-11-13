package run_test

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/modules/reports/run"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

// pdOID is the GUID of the i-th seeded per-DC object.
func pdOID(i int) authz.ObjectID {
	var o authz.ObjectID
	o[0], o[14], o[15] = 0x77, byte(i>>8), byte(i)
	return o
}

// pdIndex is the inverse of pdOID.
func pdIndex(o authz.ObjectID) int { return int(o[14])<<8 | int(o[15]) }

var logonBase = time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

// fakeDCs is both ports of the per-DC path: the reader answers from a script and counts its reads; the counter
// says how many DCs are in scope. Nothing here is a mock of the run: the run's SQL, rows and digest are real.
type fakeDCs struct {
	mu          sync.Mutex
	dcs         []string
	down        map[string]string // DC -> fixed error code returned for every object
	logon       func(obj int, dc string) time.Time
	failCount   func(obj int, dc string) (when time.Time, n int64)
	reads       int // Read calls
	objectReads int // objects asked, summed over calls
	inflight    int
	maxInflight int
	batches     []int
	onRead      func(call int)
	countErr    error
}

func (f *fakeDCs) DCsInScope(_ context.Context, _, _ authz.ObjectID, _ report.PerDCScope) (int, error) {
	if f.countErr != nil {
		return 0, f.countErr
	}
	return len(f.dcs), nil
}

func (f *fakeDCs) Read(_ context.Context, _, _ authz.ObjectID, objs []authz.ObjectID, attrs []report.PerDCAttr, _ report.PerDCScope) ([]report.PerDCObject, report.PerDCSummary, error) {
	f.mu.Lock()
	f.reads++
	call := f.reads
	f.objectReads += len(objs)
	f.batches = append(f.batches, len(objs))
	f.inflight++
	f.maxInflight = max(f.maxInflight, f.inflight)
	hook := f.onRead
	f.mu.Unlock()
	if hook != nil {
		hook(call)
	}
	defer func() { f.mu.Lock(); f.inflight--; f.mu.Unlock() }()
	var out []report.PerDCObject
	sum := report.PerDCSummary{DCsInScope: uint32(len(f.dcs)), Coverage: report.CoverageComplete}
	answered := 0
	for _, dc := range f.dcs {
		if f.down[dc] == "" {
			answered++
		} else {
			sum.Coverage = report.CoveragePartial
		}
	}
	sum.DCsAnswered = uint32(answered)
	for _, o := range objs {
		i := pdIndex(o)
		po := report.PerDCObject{Object: o}
		for _, dc := range f.dcs {
			if code := f.down[dc]; code != "" {
				po.Results = append(po.Results, report.PerDCResult{DC: dc, Err: code})
				continue
			}
			r := report.PerDCResult{DC: dc}
			if f.logon != nil && slices.Contains(attrs, report.PerDCLastLogon) {
				r.Values = append(r.Values, report.PerDCValue{Attr: report.PerDCLastLogon, Time: f.logon(i, dc)})
			}
			if f.failCount != nil {
				when, n := f.failCount(i, dc)
				r.Values = append(r.Values, report.PerDCValue{Attr: report.PerDCBadPasswordTime, Time: when},
					report.PerDCValue{Attr: report.PerDCBadPwdCount, Int: n})
			}
			po.Results = append(po.Results, r)
		}
		out = append(out, po)
	}
	return out, sum, nil
}

func (f *fakeDCs) snapshot() (reads, objectReads, maxInflight int, batches []int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reads, f.objectReads, f.maxInflight, slices.Clone(f.batches)
}

func (e *env) perDC(f *fakeDCs) {
	e.svc.PerDC, e.svc.PerDCDCs = f, f
}

// pdRows reads every stored row of a run, keyed by the account name (column "sam" is shown first).
func (e *env) pdRows(id run.ID) (cols []string, rows map[string][]report.Cell, order []string) {
	e.t.Helper()
	rows = map[string][]report.Cell{}
	cursor := ""
	for {
		pg, err := e.svc.Page(context.Background(), e.tid, chainOf(alice), id, run.PageQuery{Limit: run.MaxPageSize, Cursor: cursor})
		if err != nil {
			e.t.Fatalf("Page: %v", err)
		}
		if cols == nil {
			for _, c := range pg.Columns {
				cols = append(cols, string(c.ID))
			}
		}
		for _, r := range pg.Rows {
			k := r.Cells[0].Text()
			rows[k] = r.Cells
			order = append(order, k)
		}
		if pg.Next == "" {
			return
		}
		cursor = pg.Next
	}
}

func colIdx(t *testing.T, cols []string, id string) int {
	t.Helper()
	i := slices.Index(cols, id)
	if i < 0 {
		t.Fatalf("column %s not in %v", id, cols)
	}
	return i
}

const pdColumns = `{"columns":["sam","real_last_logon","real_logon_dc","dc_coverage","failures_on_dc"]}`

// AC-39: the real last logon is the maximum over the DCs, the cell names the DC it came from, coverage is complete.
func TestPerDCRunTakesTheMaximumOverDCsAndNamesTheDC(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setupWith(t, s, &pdConf{n: 3})
		f := &fakeDCs{dcs: []string{"dc1", "dc2", "dc3"},
			logon: func(obj int, dc string) time.Time {
				switch {
				case obj == 0 && dc == "dc3": // the latest logon is on a DC that is not first
					return logonBase.Add(48 * time.Hour)
				case obj == 0:
					return logonBase
				case obj == 1 && dc == "dc2":
					return logonBase.Add(time.Hour)
				}
				return time.Time{} // obj 2 never logged on anywhere
			},
			failCount: func(obj int, dc string) (time.Time, int64) {
				if obj == 0 && dc == "dc2" {
					return logonBase.Add(time.Hour), 4
				}
				if obj == 0 && dc == "dc1" {
					return logonBase, 9 // an older failure on another DC: not the one reported
				}
				return time.Time{}, 0
			}}
		e.perDC(f)
		r := e.create(alice, pdColumns)
		e.work()
		got := e.get(r.ID)
		if got.State != run.StateSucceeded || got.RowCount == nil || *got.RowCount != 3 {
			t.Fatalf("run = %+v", got)
		}
		if got.PerDC == nil || !got.PerDC.Complete || got.PerDC.DCsInScope != 3 || got.PerDC.DCsAnswered != 3 || got.PerDC.AtLeast() || len(got.PerDC.Unreachable) != 0 {
			t.Fatalf("per_dc = %+v", got.PerDC)
		}
		cols, rows, _ := e.pdRows(r.ID)
		a := rows["u000"]
		if g := a[colIdx(t, cols, "real_last_logon")].Time(); !g.Equal(logonBase.Add(48 * time.Hour)) {
			t.Fatalf("real last logon = %v, want the maximum over the DCs", g)
		}
		if g := a[colIdx(t, cols, "real_logon_dc")].Text(); g != "dc3" {
			t.Fatalf("DC = %q", g)
		}
		if g := a[colIdx(t, cols, "dc_coverage")].Text(); g != "3 of 3 DCs" {
			t.Fatalf("coverage = %q", g)
		}
		if g := a[colIdx(t, cols, "failures_on_dc")].Int(); g != 4 {
			t.Fatalf("failures = %d, want the count at the DC of the latest failure (4), never a sum", g)
		}
		// complete coverage: unset everywhere is a fact, "never"
		if k := rows["u002"][colIdx(t, cols, "real_last_logon")].Kind(); k != report.Never().Kind() {
			t.Fatalf("never logged on: cell kind %v", k)
		}
		if got.PerDC.CoverageText() == "" {
			t.Fatal("no coverage text")
		}
	})
}

// AC-40: one DC down. The label says "2 of 3 DCs", the column header says "(at least)", a user no answering DC
// has seen reads "Not confirmed" (not "never"), and the run names the DC with its error.
func TestPerDCRunWithADCDownIsLabelledPartial(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setupWith(t, s, &pdConf{n: 3})
		f := &fakeDCs{dcs: []string{"dc1", "dc2", "dc3"}, down: map[string]string{"dc3": "dc_unreachable"},
			logon: func(obj int, dc string) time.Time {
				if obj == 0 && dc == "dc2" {
					return logonBase
				}
				return time.Time{}
			}}
		e.perDC(f)
		r := e.create(alice, pdColumns)
		e.work()
		got := e.get(r.ID)
		if got.State != run.StateSucceeded || got.PerDC == nil {
			t.Fatalf("run = %+v", got)
		}
		pd := got.PerDC
		if pd.Complete || !pd.AtLeast() || pd.DCsInScope != 3 || pd.DCsAnswered != 2 {
			t.Fatalf("per_dc = %+v", pd)
		}
		if len(pd.Unreachable) != 1 || pd.Unreachable[0].DC != "dc3" || pd.Unreachable[0].Error != "dc_unreachable" {
			t.Fatalf("unreachable = %+v", pd.Unreachable)
		}
		if txt := pd.CoverageText(); !strings.Contains(txt, "2 of 3 DCs") || !strings.Contains(txt, "dc3") || !strings.Contains(txt, "dc_unreachable") {
			t.Fatalf("coverage text %q", txt)
		}
		pg, err := e.svc.Page(context.Background(), e.tid, chainOf(alice), r.ID, run.PageQuery{Limit: 10})
		if err != nil {
			t.Fatal(err)
		}
		var header string
		for _, c := range pg.Columns {
			if c.ID == "real_last_logon" {
				header = got.ColumnLabel(c)
			}
		}
		if !strings.HasSuffix(header, "(at least)") {
			t.Fatalf("header %q", header)
		}
		cols, rows, _ := e.pdRows(r.ID)
		if g := rows["u000"][colIdx(t, cols, "dc_coverage")].Text(); g != "2 of 3 DCs" {
			t.Fatalf("row coverage = %q", g)
		}
		if c := rows["u000"][colIdx(t, cols, "real_last_logon")]; !c.Time().Equal(logonBase) {
			t.Fatalf("the value at the answering DC is a lower bound, still shown: %v", c)
		}
		if c := rows["u001"][colIdx(t, cols, "real_last_logon")]; c.Text() != report.NotConfirmedText {
			t.Fatalf("no answering DC holds a value: cell = %q, want %q", c.Text(), report.NotConfirmedText)
		}
	})
}

// AC-41: candidates × DCs over the cap is refused before any DC is read; the reader's counter stays 0.
func TestPerDCRunOverTheReadCapIsRefusedBeforeAnyRead(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setupWith(t, s, &pdConf{n: 10})
		f := &fakeDCs{dcs: []string{"dc1", "dc2", "dc3"}}
		e.perDC(f)
		e.svc.PerDCReadCap = 29 // 10 candidates × 3 DCs = 30
		r := e.create(alice, pdColumns)
		e.work()
		got := e.get(r.ID)
		if got.State != run.StateFailed || got.Failure != run.FailPerDCReadCapExceeded {
			t.Fatalf("run = %s / %s", got.State, got.Failure)
		}
		if d := got.ScopeApplied.Detail; d["candidates"] != 10 || d["dcs"] != 3 || d["reads"] != 30 || d["cap"] != 29 {
			t.Fatalf("detail = %v", d)
		}
		if reads, objs, _, _ := f.snapshot(); reads != 0 || objs != 0 {
			t.Fatalf("DC reads made before the refusal: %d calls, %d objects", reads, objs)
		}
		if _, _, order := e.pdRowsOrNone(r.ID); len(order) != 0 {
			t.Fatalf("rows left after a refused run: %v", order)
		}
		// exactly at the cap runs
		e.svc.PerDCReadCap = 30
		r2 := e.create(alice, pdColumns)
		e.work()
		if got := e.get(r2.ID); got.State != run.StateSucceeded {
			t.Fatalf("at the cap: %s / %s", got.State, got.Failure)
		}
	})
}

// pdRowsOrNone is pdRows for a run that may have no readable rows.
func (e *env) pdRowsOrNone(id run.ID) ([]string, map[string][]report.Cell, []string) {
	pg, err := e.svc.Page(context.Background(), e.tid, chainOf(alice), id, run.PageQuery{Limit: run.MaxPageSize})
	if err != nil {
		return nil, nil, nil
	}
	var order []string
	for _, r := range pg.Rows {
		order = append(order, r.Key)
	}
	return nil, nil, order
}

// Bounded reads: one reader call in flight at a time, no batch above report.PerDCBatchSize, progress visible
// between batches.
func TestPerDCRunReadsInBoundedBatchesAndShowsProgress(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		const n = 450
		e := setupWith(t, s, &pdConf{n: n})
		f := &fakeDCs{dcs: []string{"dc1", "dc2"}, logon: func(obj int, dc string) time.Time {
			return logonBase.Add(time.Duration(obj) * time.Minute)
		}}
		var seen []int64
		f.onRead = func(call int) {
			if call == 1 {
				return
			}
			// between batches: the run is running and its progress shows the batches already stored
			if r := e.getAny(); r.PerDC != nil && r.State == run.StateRunning {
				seen = append(seen, r.PerDC.Read)
			}
		}
		e.perDC(f)
		r := e.create(alice, `{"columns":["sam","real_last_logon","dc_coverage"]}`)
		e.runID = r.ID
		e.work()
		got := e.get(r.ID)
		if got.State != run.StateSucceeded || *got.RowCount != n {
			t.Fatalf("run = %s / %s rows %v", got.State, got.Failure, got.RowCount)
		}
		reads, objs, maxIn, batches := f.snapshot()
		if maxIn != 1 || objs != n || reads != 3 || !slices.Equal(batches, []int{200, 200, 50}) {
			t.Fatalf("reads %d objects %d max in flight %d batches %v", reads, objs, maxIn, batches)
		}
		if !slices.Equal(seen, []int64{200, 400}) {
			t.Fatalf("progress seen between batches = %v", seen)
		}
		if got.PerDC.Read != n || got.PerDC.Total != n {
			t.Fatalf("final per_dc %+v", got.PerDC)
		}
	})
}

// getAny reads the env's run without the requester's page rules (progress is part of the record).
func (e *env) getAny() run.Run { return e.get(e.runID) }

// Cancel in the middle of the reads: no further read is made and no rows are left.
func TestPerDCRunCancelStopsReading(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setupWith(t, s, &pdConf{n: 450})
		f := &fakeDCs{dcs: []string{"dc1"}, logon: func(int, string) time.Time { return logonBase }}
		f.onRead = func(call int) {
			if call == 2 {
				if _, err := e.svc.Cancel(context.Background(), e.tid, chainOf(alice), e.runID); err != nil {
					t.Errorf("Cancel: %v", err)
				}
			}
		}
		e.perDC(f)
		r := e.create(alice, pdColumns)
		e.runID = r.ID
		e.work()
		if got := e.get(r.ID); got.State != run.StateCancelled {
			t.Fatalf("state %s", got.State)
		}
		if reads, _, _, _ := f.snapshot(); reads != 2 {
			t.Fatalf("reads after cancel: %d, want 2", reads)
		}
		if _, _, order := e.pdRowsOrNone(r.ID); len(order) != 0 {
			t.Fatalf("rows left after cancel: %d", len(order))
		}
	})
}

// PWD-03 style: PerDCWhere drops rows during the reads; the survivors are renumbered and the count and
// digest are those of the survivors.
func TestPerDCRunFiltersAndSortsOnPerDCColumns(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setupWith(t, s, &pdConf{n: 6})
		f := &fakeDCs{dcs: []string{"dc1", "dc2"},
			logon: func(obj int, dc string) time.Time { return logonBase.Add(time.Duration((obj*7)%6) * time.Hour) },
			failCount: func(obj int, dc string) (time.Time, int64) {
				if dc == "dc2" {
					return logonBase, int64(obj) // 0..5; keep >= 2
				}
				return time.Time{}, 0
			}}
		e.perDC(f)
		r := e.create(alice, `{"columns":["sam","real_last_logon","failures_on_dc"],"sort":[{"Col":"real_last_logon","Dir":"desc"}],"minFailures":2}`)
		e.work()
		got := e.get(r.ID)
		if got.State != run.StateSucceeded || *got.RowCount != 4 {
			t.Fatalf("run = %s / %s rows %v", got.State, got.Failure, got.RowCount)
		}
		cols, rows, order := e.pdRows(r.ID)
		// objects 2..5 survive; real last logon = base + (obj*7 % 6)h = 2:2h 3:3h 4:4h 5:5h; newest first
		if want := []string{"u005", "u004", "u003", "u002"}; !slices.Equal(order, want) {
			t.Fatalf("order %v, want %v", order, want)
		}
		for k, c := range rows {
			if c[colIdx(t, cols, "failures_on_dc")].Int() < 2 {
				t.Fatalf("%s kept with %d failures", k, c[colIdx(t, cols, "failures_on_dc")].Int())
			}
		}
		pg, err := e.svc.Page(context.Background(), e.tid, chainOf(alice), r.ID, run.PageQuery{Limit: 10})
		if err != nil {
			t.Fatal(err)
		}
		for i, row := range pg.Rows {
			if row.Ordinal != int64(i) {
				t.Fatalf("ordinal %d at position %d", row.Ordinal, i)
			}
		}
		if len(got.Digest) != 32 {
			t.Fatalf("digest %x", got.Digest)
		}
	})
}

// With no reader wired the run says it cannot read DCs here; it neither guesses nor reads stale data.
func TestPerDCRunWithoutAReaderFailsConnectionUnavailable(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setupWith(t, s, &pdConf{n: 2})
		r := e.create(alice, pdColumns)
		e.work()
		if got := e.get(r.ID); got.State != run.StateFailed || got.Failure != run.FailConnectionUnavailable {
			t.Fatalf("run = %s / %s", got.State, got.Failure)
		}
	})
}

var _ = fmt.Sprintf

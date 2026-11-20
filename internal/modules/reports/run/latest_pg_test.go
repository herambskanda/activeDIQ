package run_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/modules/reports/run"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/authz/authztest"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

// withWidget gives the test definition a table widget over its sam column.
func withWidget(e *env) {
	rd, _ := e.svc.Catalog.Definition("tst-01", 0)
	rd.Def.Widget = &report.WidgetProfile{Views: []report.WidgetView{report.WidgetTable}, TableColumns: []report.ColumnID{"sam"}}
	e.svc.Catalog = catalog{rd}
}

func (e *env) latest(who string, rows int) run.Latest {
	e.t.Helper()
	l, err := e.svc.Latest(context.Background(), e.tid, chainOf(who), "tst-01", "", rows)
	if err != nil {
		e.t.Fatalf("Latest(%s, %d): %v", who, rows, err)
	}
	return l
}

// Acceptance 1: another account's run, such as one a schedule owned by B makes for delivery to A, is never
// A's candidate: A sees never_run, then A's own rows once A has run it.
func Test_latest_is_the_callers_own_run_only(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		withWidget(e)
		e.create(bob, `{}`) // B's run (B holds the same scope, a wider one in the real probe)
		e.work()
		l := e.latest(alice, 10)
		if l.State != run.LatestNeverRun || l.Run != nil || l.InFlight != nil || l.Rows != nil || l.Serves {
			t.Fatalf("A with only B's run: %+v", l)
		}
		if b := e.latest(bob, 0); b.State != run.LatestCurrent || b.Run == nil || b.Run.RowCount == nil || *b.Run.RowCount != 3 {
			t.Fatalf("B: %+v", b)
		}
		e.create(alice, `{}`)
		e.work()
		l = e.latest(alice, 10)
		if l.State != run.LatestCurrent || !l.Serves || *l.Run.RowCount != 3 || l.Run.Runner != alice {
			t.Fatalf("A after running: %+v", l)
		}
		if len(l.Columns) != 1 || l.Columns[0].ID != "sam" || len(l.Rows) != 3 || len(l.Rows[0].Cells) != 1 {
			t.Fatalf("table = %v / %d rows", l.Columns, len(l.Rows))
		}
		// header only: no rows are read
		if h := e.latest(alice, 0); h.State != run.LatestCurrent || h.Rows != nil || h.Columns != nil {
			t.Fatalf("rows=0: %+v", h)
		}
	})
}

// Acceptance 2: A's scope narrowed since the run: scope_changed, no count, no rows.
func Test_latest_scope_changed_serves_nothing(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		withWidget(e)
		e.create(alice, `{}`)
		e.work()
		e.scopes.set(alice, authztest.ReadScope(authz.ScopeGrant{Include: []authz.ScopeTerm{{Kind: authz.TermSubtree, Connection: conn1, Root: oid(0x11)}}}))
		for _, rows := range []int{0, 10} {
			l := e.latest(alice, rows)
			if l.State != run.LatestScopeChanged || l.Serves || l.Rows != nil || l.Columns != nil {
				t.Fatalf("rows=%d: %+v", rows, l)
			}
		}
		// Run now under the narrower scope makes it current again
		e.create(alice, `{"columns":["sam"]}`)
		e.work()
		if l := e.latest(alice, 10); l.State != run.LatestCurrent || !l.Serves {
			t.Fatalf("after a new run: %+v", l)
		}
	})
}

// Acceptance 3: a stale freshness run carries as_of and the freshness record that names what is stale.
func Test_latest_stale_data_carries_as_of_and_freshness(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		e.svc.Fresh = fresh{at: e.clock.Add(-3 * time.Hour)}
		e.create(alice, `{}`)
		e.work()
		l := e.latest(alice, 0)
		if l.State != run.LatestStaleData || l.Run.AsOf == nil || l.Run.Freshness == nil || l.Run.Freshness.State != "stale" || len(l.Run.Freshness.Stale) == 0 {
			t.Fatalf("stale: %+v / %+v", l, l.Run.Freshness)
		}
		if !l.Run.AsOf.Equal(e.clock.Add(-3 * time.Hour)) {
			t.Fatalf("as_of = %v", l.Run.AsOf)
		}
	})
}

func Test_latest_in_flight_failed_and_expired(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		withWidget(e)
		// a run that is only queued: running, no data
		r := e.create(alice, `{}`)
		if l := e.latest(alice, 10); l.State != run.LatestRunning || l.Serves || l.Rows != nil || l.Run.ID != r.ID {
			t.Fatalf("queued only: %+v", l)
		}
		e.work()
		// a refresh in flight keeps the previous current result
		*e.clock = e.clock.Add(2 * time.Minute) // out of the 60 s reuse window
		fl := e.create(alice, `{"columns":["sam"]}`)
		l := e.latest(alice, 10)
		if l.State != run.LatestRunning || l.InFlight == nil || l.InFlight.ID != fl.ID || !l.Serves || l.Run.ID != r.ID || len(l.Rows) != 3 {
			t.Fatalf("refreshing: %+v", l)
		}
		e.work()
		// a failed newer run does not hide the earlier current one
		e.svc.RowCap = 2
		*e.clock = e.clock.Add(2 * time.Minute)
		e.create(alice, `{"columns":["sam","enabled"]}`)
		e.work()
		e.svc.RowCap = 0
		if l := e.latest(alice, 0); l.State != run.LatestCurrent || l.Run.State != run.StateSucceeded {
			t.Fatalf("failed after success: %+v", l)
		}
		// past expiry: expired, no rows, no count
		*e.clock = e.clock.Add(8 * 24 * time.Hour)
		if l := e.latest(alice, 10); l.State != run.LatestExpired || l.Serves || l.Rows != nil {
			t.Fatalf("expired: %+v", l)
		}
	})
}

func Test_latest_failed_without_a_current_run(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		e.svc.RowCap = 2
		e.create(alice, `{}`)
		e.work()
		l := e.latest(alice, 0)
		if l.State != run.LatestFailed || l.Run.Failure != run.FailRowCapExceeded || l.Serves {
			t.Fatalf("failed: %+v", l)
		}
	})
}

func Test_latest_refuses_what_the_profile_does_not_offer(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		ctx := context.Background()
		if _, err := e.svc.Latest(ctx, e.tid, chainOf(alice), "tst-01", "", 10); !errors.Is(err, run.ErrNoTableView) {
			t.Fatalf("no profile, rows=10: %v", err)
		}
		withWidget(e)
		if _, err := e.svc.Latest(ctx, e.tid, chainOf(alice), "tst-01", "", 7); !errors.Is(err, run.ErrBadLimit) {
			t.Fatalf("rows=7: %v", err)
		}
		for _, c := range []struct{ def, preset string }{{"nope-01", ""}, {"tst-01", "missing"}} {
			l, err := e.svc.Latest(ctx, e.tid, chainOf(alice), c.def, c.preset, 0)
			if err != nil || l.State != run.LatestUnavailable || l.Run != nil {
				t.Fatalf("%v: %+v, %v", c, l, err)
			}
		}
	})
}

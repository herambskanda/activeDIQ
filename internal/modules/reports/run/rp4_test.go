package run_test

// The clauses of the RP4 fitness check (ADR-0010 § Fitness function) beyond the page, retention and row-trigger
// probes of Test_expired_run_is_not_served. Each function here is a subtest of that bound test, so they run
// on every storetest version and a skip or failure fails RP4.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/modules/reports/export"
	"github.com/skenzeriq/activediq/internal/modules/reports/run"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/blob"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// allowAll is the export service's authorizer: every requester holds reports.run.
type allowAll struct{}

func (allowAll) Allow(context.Context, tenant.ID, authority.Chain, authz.Permission) (bool, error) {
	return true, nil
}

// rp4ExportOfExpiredRunReruns: an export request for an expired run creates a new run made as the caller,
// bound to the expired one by RerunOf (clause 2).
func rp4ExportOfExpiredRunReruns(t *testing.T, s *storetest.Server) {
	e := setup(t, s)
	ctx := context.Background()
	*e.clock = e.clock.Add(-8 * 24 * time.Hour)
	r := e.create(alice, `{}`)
	e.work()
	*e.clock = e.clock.Add(8 * 24 * time.Hour)
	// the sweep flips the run (the reuse lookup reads the database clock, which the test does not move)
	if res, err := e.svc.Retention(ctx, e.tid, *e.clock); err != nil || res.Expired != 1 {
		t.Fatalf("retention = %+v, %v", res, err)
	}
	if got := e.get(r.ID); got.State != run.StateExpired {
		t.Fatalf("source state %s, want expired", got.State)
	}
	bs, err := blob.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	exp := &export.Service{DB: e.db, Jobs: e.reg, Runs: e.svc, Blob: bs, Audit: e.sink, Authz: allowAll{}, Now: func() time.Time { return *e.clock }}
	if err := e.reg.Register(exp.Kind()); err != nil {
		t.Fatal(err)
	}
	x, err := exp.Create(ctx, e.tid, chainOf(alice), r.ID, export.CSV)
	if err != nil {
		t.Fatalf("export of an expired run: %v", err)
	}
	if !x.Rerun || x.RerunOf == nil || *x.RerunOf != r.ID || x.RunID == r.ID {
		t.Fatalf("export = %+v, want a rerun of %s on a different run", x, r.ID)
	}
	nr := e.get(x.RunID)
	if nr.RerunOf == nil || *nr.RerunOf != r.ID || nr.ID == r.ID || nr.State != run.StateQueued {
		t.Fatalf("new run = %+v, want a queued run with RerunOf %s", nr, r.ID)
	}
	// the expired record is untouched
	if got := e.get(r.ID); got.State != run.StateExpired {
		t.Fatalf("source state after the export %s", got.State)
	}
}

// checkViolation reports whether err is a violation of one of report_runs' table-level CHECKs (SQLSTATE 23514,
// raised before any AFTER trigger runs), and the SQLSTATE found otherwise. 0064 leaves the constraint
// unnamed, so PostgreSQL names it report_runs_check<n>.
func checkViolation(err error) (bool, string) {
	code, table, constraint := store.SQLConstraint(err)
	if code == "" {
		return false, ""
	}
	return code == "23514" && table == "report_runs" && strings.HasPrefix(constraint, "report_runs_check"), code + " " + constraint
}

// rp4SucceededNeedsExpiry: a run cannot be written as succeeded without expires_at; the refusing guard is the
// 0064 CHECK (check_violation), not the AD403 guard triggers (clause 4). Each probe has a control that differs
// only in expires_at and is refused by a trigger (insert) or accepted (update), so the CHECK is the one
// thing the NULL changes.
func rp4SucceededNeedsExpiry(t *testing.T, s *storetest.Server) {
	e := setup(t, s)
	r := e.create(alice, `{}`)
	const cols = `tenant_id, id, definition_id, definition_version, definition_sha256, preset, params, query_hash,
		scope_fingerprint, runner_account, chain, columns`
	insert := func(expires string) error {
		return e.ownerExec(`INSERT INTO public.report_runs (`+cols+`, state, attempt, row_count, digest, as_of, expires_at)
			SELECT `+cols+`, 'succeeded', 0, 5, decode(repeat('ab', 32), 'hex'), now(), `+expires+` FROM (SELECT tenant_id, gen_random_uuid() AS id,
			definition_id, definition_version, definition_sha256, preset, params, query_hash, scope_fingerprint, runner_account, chain, columns
			FROM public.report_runs WHERE id = $1::uuid) x`, r.ID.String())
	}
	if ok, got := checkViolation(insert(`NULL`)); !ok {
		t.Errorf("insert of a succeeded run with NULL expires_at: %q, want the report_runs CHECK", got)
	}
	// control: with expires_at the same insert reaches the insert trigger, which refuses it
	if got := store.SQLState(insert(`now() + interval '1 day'`)); got != "AD403" {
		t.Errorf("control insert: SQLSTATE %q, want AD403 (the insert guard)", got)
	}

	// update: a running run becomes succeeded with every result column but expires_at
	if err := e.ownerExec(`UPDATE public.report_runs SET state = 'running', attempt = 1, started_at = now() WHERE id = $1::uuid`, r.ID.String()); err != nil {
		t.Fatal(err)
	}
	finish := func(expires string) error {
		return e.ownerExec(`UPDATE public.report_runs SET state = 'succeeded', row_count = 0, digest = decode(repeat('ab', 32), 'hex'),
			as_of = now(), expires_at = `+expires+` WHERE id = $1::uuid`, r.ID.String())
	}
	if ok, got := checkViolation(finish(`NULL`)); !ok {
		t.Errorf("update to succeeded with NULL expires_at: %q, want the report_runs CHECK", got)
	}
	if got := e.get(r.ID); got.State != run.StateRunning {
		t.Fatalf("the refused update changed the run to %s", got.State)
	}
	// control: the same update with an expiry is accepted, so the NULL was the only thing the CHECK refused
	if err := finish(`now() + interval '1 day'`); err != nil {
		t.Fatalf("control update: %v", err)
	}
	// and a succeeded run cannot lose its expiry afterwards: the CHECK (before the trigger's own refusal)
	if ok, got := checkViolation(e.ownerExec(`UPDATE public.report_runs SET expires_at = NULL WHERE id = $1::uuid`, r.ID.String())); !ok {
		t.Errorf("clearing expires_at of a succeeded run: %q, want the report_runs CHECK", got)
	}
}

var errRollBack = errors.New("roll back the probe")

// probeEdge reports the SQLSTATE ("" when accepted) of moving a run from one state to another by an
// owner-role UPDATE. The run is first walked to `from` along the legal edges, then the one UPDATE under test
// runs; the transaction is rolled back, so every pair starts from the same queued run. The UPDATE sets the
// columns the table's CHECKs tie to the target state (a result for succeeded, a reason for failed, none for
// the rest) and nothing else, so the state trigger is the only guard left to judge the edge.
func (e *env) probeEdge(id run.ID, from, to run.State) (sqlstate string) {
	e.t.Helper()
	const result = `row_count = 0, digest = decode(repeat('ab', 32), 'hex'), as_of = now(), expires_at = now() + interval '1 day'`
	setup := map[run.State][]string{
		run.StateQueued:    nil,
		run.StateRunning:   {`state = 'running', attempt = 1, started_at = now()`},
		run.StateSucceeded: {`state = 'running', attempt = 1, started_at = now()`, `state = 'succeeded', ` + result},
		run.StateFailed:    {`state = 'failed', failure_reason = 'internal'`},
		run.StateCancelled: {`state = 'cancelled'`},
		run.StateExpired:   {`state = 'running', attempt = 1, started_at = now()`, `state = 'succeeded', ` + result, `state = 'expired'`},
	}
	set := fmt.Sprintf(`state = '%s'`, to)
	if to == run.StateSucceeded && from != run.StateSucceeded {
		set += `, ` + result
	}
	if to == run.StateFailed && from != run.StateFailed {
		set += `, failure_reason = 'internal'`
	}
	if to != run.StateFailed && from == run.StateFailed {
		set += `, failure_reason = NULL`
	}
	err := e.db.WithTenant(context.Background(), e.tid, func(ctx context.Context, tx store.Tx) error {
		for _, step := range setup[from] {
			if _, err := tx.Exec(ctx, `UPDATE public.report_runs SET `+step+` WHERE id = $1::uuid`, id.String()); err != nil {
				e.t.Fatalf("reaching %s (%s): %v", from, step, err)
			}
		}
		_, err := tx.Exec(ctx, `UPDATE public.report_runs SET `+set+` WHERE id = $1::uuid`, id.String())
		sqlstate = store.SQLState(err)
		if err != nil && sqlstate == "" {
			e.t.Fatalf("%s -> %s: not a database refusal: %v", from, to, err)
		}
		return errRollBack
	})
	if !errors.Is(err, errRollBack) {
		e.t.Fatalf("%s -> %s: %v", from, to, err)
	}
	return sqlstate
}

// rp4StateEdgesAtTheTrigger: for every pair of states, an owner-role UPDATE of state is refused by the
// report_runs_guard trigger (AD403) exactly when !from.CanMoveTo(to), the matrix of reports.md §6.2 that
// TestStateEdges checks against the Go type (clause 6). A pair from a state to itself is no edge: the trigger
// leaves a queued or running run's no-op UPDATE alone and refuses it only where a run is final or succeeded.
func rp4StateEdgesAtTheTrigger(t *testing.T, s *storetest.Server) {
	e := setup(t, s)
	r := e.create(alice, `{}`)
	var pairs, refused int
	for _, from := range run.States {
		for _, to := range run.States {
			pairs++
			got := e.probeEdge(r.ID, from, to)
			wantRefused := !from.CanMoveTo(to)
			if from == to {
				wantRefused = from == run.StateSucceeded || from.Final()
			}
			if wantRefused {
				refused++
			}
			switch {
			case wantRefused && got != "AD403":
				t.Errorf("%s -> %s: SQLSTATE %q, want AD403 from the trigger", from, to, got)
			case !wantRefused && got != "":
				t.Errorf("%s -> %s: refused with %q, the edge is in §6.2", from, to, got)
			}
		}
	}
	if want := len(run.States) * len(run.States); pairs != want || refused == 0 {
		t.Fatalf("probed %d of %d pairs, %d refused", pairs, want, refused)
	}
	if got := e.get(r.ID); got.State != run.StateQueued {
		t.Fatalf("the probes left the run %s", got.State)
	}
}

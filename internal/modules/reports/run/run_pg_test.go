package run_test

import (
	"context"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/modules/reports/run"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/authz/authztest"
	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/reportsql"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

func TestMain(m *testing.M) { os.Exit(storetest.Main(m)) }

const ddl = `
CREATE TABLE public.rpt_objects (
  tenant_id uuid NOT NULL, connection_id uuid NOT NULL, object_guid uuid NOT NULL, nc_guid uuid, parent_guid uuid,
  ancestry uuid[] NOT NULL DEFAULT '{}', ancestry_complete boolean NOT NULL DEFAULT true,
  sam text NOT NULL, enabled boolean, display text NOT NULL DEFAULT '',
  PRIMARY KEY (tenant_id, connection_id, object_guid));
GRANT SELECT ON public.rpt_objects TO activediq_app;
ALTER TABLE public.rpt_objects ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.rpt_objects FORCE ROW LEVEL SECURITY;
CREATE POLICY rpt_t ON public.rpt_objects FOR SELECT USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
CREATE POLICY rpt_w ON public.rpt_objects FOR INSERT WITH CHECK (true);`

func oid(b byte) authz.ObjectID { var o authz.ObjectID; o[15] = b; return o }

var (
	conn1, conn2, nc1 = oid(1), oid(2), oid(0x10)
	alice, bob        = "00000000-0000-4000-8000-0000000000a1", "00000000-0000-4000-8000-0000000000b2"
)

func chainOf(id string) authority.Chain {
	return authority.Chain{Requester: authority.Principal{ID: authority.PrincipalID(id), Kind: authority.Human}}
}

func grant(conn authz.ObjectID) authz.ScopeGrant {
	return authz.ScopeGrant{Include: []authz.ScopeTerm{{Kind: authz.TermNamingContext, Connection: conn, Root: nc1}}}
}

// fakeScopes answers per requester; err, when set, is returned instead.
type fakeScopes struct {
	mu sync.Mutex
	m  map[string]authz.ReadScope
	e  map[string]error
}

func (f *fakeScopes) set(id string, s authz.ReadScope) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.m[id] = s
	delete(f.e, id)
}
func (f *fakeScopes) fail(id string, err error) { f.mu.Lock(); defer f.mu.Unlock(); f.e[id] = err }
func (f *fakeScopes) For(_ context.Context, _ store.Tx, _ tenant.ID, c authority.Chain, _ authz.Permission) (authz.ReadScope, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := string(c.Requester.ID)
	if err := f.e[id]; err != nil {
		return authz.ReadScope{}, err
	}
	return f.m[id], nil
}

type recSink struct {
	mu sync.Mutex
	ev []audit.Event
}

func (r *recSink) Append(_ context.Context, _ store.Tx, e audit.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := e.Validate(); err != nil {
		return err
	}
	r.ev = append(r.ev, e)
	return nil
}
func (r *recSink) kinds() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, e := range r.ev {
		out = append(out, string(e.Kind)+":"+e.Reason)
	}
	return out
}

type catalog struct{ d run.Definition }

func (c catalog) Definition(id string, _ int) (run.Definition, bool) {
	return c.d, id == string(c.d.Def.ID)
}

// codec reads {"columns":[...]}.
type codec struct{}

func (codec) Decode(raw jsontext.Value, _ report.Definition) (report.RunParams, error) {
	var v struct {
		Columns []string `json:"columns"`
	}
	if err := jsonv2.Unmarshal(raw, &v); err != nil {
		return report.RunParams{}, err
	}
	var p report.RunParams
	for _, c := range v.Columns {
		p.Columns = append(p.Columns, report.ColumnID(c))
	}
	return p, nil
}

type fresh struct{ at time.Time }

func (f fresh) Freshness(_ context.Context, _ tenant.ID, cs []authz.ObjectID, now time.Time) (report.Freshness, time.Duration, error) {
	var ws []report.NCWatermark
	for _, c := range cs {
		ws = append(ws, report.NCWatermark{Connection: c, NC: nc1, LastPassAt: f.at, State: report.NCOK})
	}
	return report.Label(ws, time.Hour, now), time.Hour, nil
}

type env struct {
	t      *testing.T
	db     *store.DB
	d      *storetest.Database
	tid    tenant.ID
	svc    *run.Service
	reg    *jobs.Registry
	scopes *fakeScopes
	sink   *recSink
	clock  *time.Time
}

func dataset() report.Dataset {
	anchor := report.Anchor{ID: "t", Table: "rpt_objects", Mode: report.RowAnchor, Project: []report.Ident{"object_guid"},
		Connection: "connection_id", NC: "nc_guid", Object: "object_guid", Parent: "parent_guid", Ancestry: "ancestry", Complete: "ancestry_complete"}
	return report.Dataset{
		ID: "tst.objects", Base: report.Relation{Table: "rpt_objects"}, RowKey: report.SQL("{t}.object_guid"),
		Anchors: []report.Anchor{anchor},
		Columns: []report.Column{
			{ID: "sam", Label: "Account", Type: report.TypeText, Source: report.Attr{Col: "sam"}, Sortable: true, Default: true},
			{ID: "enabled", Label: "Enabled", Type: report.TypeBool, Source: report.Attr{Col: "enabled"}, Default: true},
			{ID: "display", Label: "Display", Type: report.TypeText, Source: report.Attr{Col: "display"}},
		},
		Freshness: report.FreshNCWatermark, Tables: []string{"rpt_objects"},
	}
}

func setup(t *testing.T, s *storetest.Server) *env {
	t.Helper()
	ctx := context.Background()
	d := s.NewDatabase(t)
	d.Migrate(t)
	if err := d.ExecOwner(ctx, ddl); err != nil {
		t.Fatal(err)
	}
	tid := tenanttest.Seed(t, d.ExecOwner, "t")
	for i, r := range []struct {
		conn authz.ObjectID
		sam  string
	}{{conn1, "ann"}, {conn1, "cat"}, {conn1, "bob"}, {conn2, "dan"}} {
		if err := d.ExecOwner(ctx, `INSERT INTO public.rpt_objects (tenant_id, connection_id, object_guid, nc_guid, sam, enabled)
			VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5, true)`, tid.String(), report.GUIDString(r.conn), report.GUIDString(oid(byte(0x30+i))), report.GUIDString(nc1), r.sam); err != nil {
			t.Fatal(err)
		}
	}
	db, err := store.Open(ctx, store.Config{DSN: d.AppDSN()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	src := dataset()
	var reg *reportsql.Registry
	if err := db.WithTenant(ctx, tid, func(ctx context.Context, tx store.Tx) error {
		sc, err := reportsql.CatalogSchema(ctx, tx)
		if err != nil {
			return err
		}
		reg, err = reportsql.NewRegistry(reportsql.Options{Schema: sc, SecretKey: func(string) bool { return false }}, src)
		return err
	}); err != nil {
		t.Fatalf("registry: %v", err)
	}
	sqlDS, _ := reg.Dataset(src.ID)
	def := report.Definition{ID: "tst-01", Version: 1, Category: report.CategoryUsers, Title: "Test", Dataset: src.ID,
		Columns: []report.ColumnID{"sam", "enabled"}, Sort: []report.SortKey{{Column: "sam", Dir: report.Asc}},
		Presets: []report.Preset{{ID: "all"}}}
	now := time.Now().UTC().Truncate(time.Second)
	e := &env{t: t, db: db, d: d, tid: tid, reg: jobs.NewRegistry(), sink: &recSink{}, clock: &now,
		scopes: &fakeScopes{m: map[string]authz.ReadScope{alice: authztest.ReadScope(grant(conn1)), bob: authztest.ReadScope(grant(conn1))}, e: map[string]error{}}}
	e.svc = &run.Service{DB: db, Jobs: e.reg, Scopes: e.scopes, Audit: e.sink, Catalog: catalog{run.Definition{Def: def, SHA256: [32]byte{1}, Dataset: src, SQL: sqlDS}},
		Codec: codec{}, Fresh: fresh{at: now.Add(-time.Minute)}, Now: func() time.Time { return *e.clock }}
	for _, k := range []jobs.Kind{e.svc.Kind(), e.svc.RetentionKind()} {
		if err := e.reg.Register(k); err != nil {
			t.Fatal(err)
		}
	}
	return e
}

func (e *env) create(who, params string) run.Run {
	e.t.Helper()
	r, _, err := e.svc.Create(context.Background(), run.CreateInput{Tenant: e.tid, Chain: chainOf(who), DefinitionID: "tst-01", Params: jsontext.Value(params)})
	if err != nil {
		e.t.Fatalf("Create: %v", err)
	}
	return r
}

// work claims and executes every available reports.run job.
func (e *env) work() {
	e.t.Helper()
	ctx := context.Background()
	cl, err := jobs.Claim(ctx, e.db, e.reg.TenantLeases(), 20)
	if err != nil {
		e.t.Fatal(err)
	}
	for _, c := range cl {
		if c.Kind != run.JobKind {
			continue
		}
		if _, err := jobs.NewRunner(e.db, e.reg).Execute(ctx, c); err != nil {
			e.t.Fatalf("Execute: %v", err)
		}
	}
}

func (e *env) get(id run.ID) run.Run {
	e.t.Helper()
	var r run.Run
	err := e.svc.Read(context.Background(), e.tid, id, chainOf(alice), run.ForGet, func(_ context.Context, _ store.Tx, got run.Run) error {
		r = got
		return nil
	})
	if err != nil {
		e.t.Fatalf("get: %v", err)
	}
	return r
}

// ownerExec runs sql as the application role inside the tenant (FORCE RLS shows the owner connection
// no rows, so an owner UPDATE or DELETE by id would match nothing and "succeed"). The guard triggers
// do not depend on the role.
func (e *env) ownerExec(sql string, args ...any) error {
	return e.db.WithTenant(context.Background(), e.tid, func(ctx context.Context, tx store.Tx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	})
}

func sams(p run.Page) []string {
	var out []string
	for _, r := range p.Rows {
		out = append(out, r.Key)
	}
	return out
}

func TestRunStoresRowsFreshnessAndPages(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		ctx := context.Background()
		r := e.create(alice, `{}`)
		if r.State != run.StateQueued {
			t.Fatalf("state %s", r.State)
		}
		e.work()
		got := e.get(r.ID)
		fp := authztest.ReadScope(grant(conn1)).Fingerprint()
		if got.State != run.StateSucceeded || got.RowCount == nil || *got.RowCount != 3 || got.AsOf == nil || got.Freshness == nil ||
			got.Freshness.State != "synced" || got.ScopeFingerprint != fp || len(got.Digest) != 32 || got.DefinitionVer != 1 {
			t.Fatalf("header = %+v", got)
		}
		if !got.AsOf.Equal(e.svc.Fresh.(fresh).at) {
			t.Fatalf("as_of %v, want the oldest last pass", got.AsOf)
		}
		if got.ObjectsChecked == nil || *got.ObjectsChecked != 3 {
			t.Fatalf("objects checked %v", got.ObjectsChecked)
		}
		// pages: same run, same as_of, sorted both ways; the total is row_count
		pg := func(q run.PageQuery) run.Page {
			p, err := e.svc.Page(ctx, e.tid, chainOf(alice), r.ID, q)
			if err != nil {
				t.Fatalf("Page %+v: %v", q, err)
			}
			return p
		}
		asc, desc := pg(run.PageQuery{SortBy: "sam"}), pg(run.PageQuery{SortBy: "sam", Desc: true})
		var a, d []string
		for _, x := range asc.Rows {
			a = append(a, string(x.Cells[0].DigestValue()))
		}
		for _, x := range desc.Rows {
			d = append(d, string(x.Cells[0].DigestValue()))
		}
		if !slices.Equal(a, []string{"ann", "bob", "cat"}) || !slices.Equal(d, []string{"cat", "bob", "ann"}) {
			t.Fatalf("sorted %v / %v", a, d)
		}
		first := pg(run.PageQuery{Limit: 2})
		if len(first.Rows) != 2 || first.Next == "" {
			t.Fatalf("first page %+v", first)
		}
		second := pg(run.PageQuery{Limit: 2, Cursor: first.Next})
		if len(second.Rows) != 1 || second.Next != "" || second.Run.AsOf == nil || !second.Run.AsOf.Equal(*got.AsOf) {
			t.Fatalf("second page %+v", second)
		}
		if _, err := e.svc.Page(ctx, e.tid, chainOf(alice), r.ID, run.PageQuery{Limit: 2, Cursor: first.Next, SortBy: "sam"}); !errors.Is(err, run.ErrBadCursor) {
			t.Fatalf("cursor reused across a sort: %v", err)
		}
		if _, err := e.svc.Page(ctx, e.tid, chainOf(alice), r.ID, run.PageQuery{SortBy: "display"}); !errors.Is(err, run.ErrBadSort) {
			t.Fatalf("unsortable column: %v", err)
		}
		// a filter (here: a column change) is a new run; the same request inside 60 s is the same run
		r2 := e.create(alice, `{"columns":["sam"]}`)
		if r2.ID == r.ID {
			t.Fatal("a changed query must create a new run")
		}
		again, reused, err := e.svc.Create(ctx, run.CreateInput{Tenant: e.tid, Chain: chainOf(alice), DefinitionID: "tst-01", Params: jsontext.Value(`{"columns":["sam"]}`)})
		if err != nil || !reused || again.ID != r2.ID {
			t.Fatalf("reuse = %v %v %v", again.ID, reused, err)
		}
		if k := e.sink.kinds(); !slices.Contains(k, "reports.run.completed:") {
			t.Fatalf("audit %v", k)
		}
	})
}

func Test_run_read_bound_to_runner_and_scope(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		ctx := context.Background()
		r := e.create(alice, `{}`)
		e.work()
		read := func(who string, checks run.Check) error {
			return e.svc.Read(ctx, e.tid, r.ID, chainOf(who), checks, nil)
		}
		// a second account with the same scope: 404 on get and page, by ID
		for _, c := range []run.Check{run.ForGet, run.ForPage} {
			if err := read(bob, c); !errors.Is(err, run.ErrRunNotFound) {
				t.Fatalf("other account, checks %d: %v", c, err)
			}
		}
		if _, err := e.svc.Page(ctx, e.tid, chainOf(bob), r.ID, run.PageQuery{}); !errors.Is(err, run.ErrRunNotFound) {
			t.Fatalf("other account page: %v", err)
		}
		if err := read(alice, run.ForPage); err != nil {
			t.Fatalf("the runner: %v", err)
		}
		// the runner's assignment is narrowed: 409
		e.scopes.set(alice, authztest.ReadScope(authz.ScopeGrant{Include: []authz.ScopeTerm{{Kind: authz.TermSubtree, Connection: conn1, Root: oid(0x11)}}}))
		for _, c := range []run.Check{run.ForGet, run.ForPage} {
			if err := read(alice, c); !errors.Is(err, run.ErrScopeChanged) {
				t.Fatalf("narrowed assignment, checks %d: %v", c, err)
			}
		}
		// the runner through a token narrower than the session that made the run: 409
		e.scopes.set(alice, authztest.ReadScopeWithToken(authz.TokenLayer{Include: []authz.ScopeTerm{{Kind: authz.TermSubtree, Connection: conn1, Root: oid(0x11)}}}, grant(conn1)))
		if err := read(alice, run.ForPage); !errors.Is(err, run.ErrScopeChanged) {
			t.Fatalf("narrower token: %v", err)
		}
		// back to the original scope the rows were trimmed with: readable again
		e.scopes.set(alice, authztest.ReadScope(grant(conn1)))
		if err := read(alice, run.ForPage); err != nil {
			t.Fatalf("restored scope: %v", err)
		}
		// every refusal left a read_denied event
		n := 0
		for _, k := range e.sink.kinds() {
			if len(k) > 22 && k[:23] == "reports.run.read_denied" {
				n++
			}
		}
		if n != 6 { // bob: get, page, Page (3); alice: narrowed get and page (2); narrower token (1)
			t.Fatalf("read_denied events = %d, want one per refusal (6): %v", n, e.sink.kinds())
		}
	})
}

func Test_expired_run_is_not_served(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		ctx := context.Background()
		*e.clock = e.clock.Add(-8 * 24 * time.Hour) // the run is made 8 days ago, so it expired 1 day ago
		r := e.create(alice, `{}`)
		e.work()
		*e.clock = e.clock.Add(8 * 24 * time.Hour)
		if _, err := e.svc.Page(ctx, e.tid, chainOf(alice), r.ID, run.PageQuery{}); !errors.Is(err, run.ErrRunExpired) {
			t.Fatalf("page of an expired run: %v", err)
		}
		// the record is still readable and says expired
		if got := e.get(r.ID); got.EffectiveState(*e.clock) != run.StateExpired || got.RowCount == nil {
			t.Fatalf("record = %+v", got)
		}
		// the triggers refuse every write to a succeeded run
		for name, sql := range map[string]string{
			"result changes":  `UPDATE public.report_runs SET row_count = 99 WHERE id = $1::uuid`,
			"bad edge":        `UPDATE public.report_runs SET state = 'queued' WHERE id = $1::uuid`,
			"row insert":      `INSERT INTO public.report_run_rows (tenant_id, run_id, row_key, ordinal, cells, sort_keys) SELECT tenant_id, id, 'x', 99, '[]', '{}' FROM public.report_runs WHERE id = $1::uuid`,
			"row update":      `UPDATE public.report_run_rows SET cells = '[]' WHERE run_id = $1::uuid`,
			"row delete":      `DELETE FROM public.report_run_rows WHERE run_id = $1::uuid`,
			"record delete":   `DELETE FROM public.report_runs WHERE id = $1::uuid`,
			"what it is over": `UPDATE public.report_runs SET preset = 'other' WHERE id = $1::uuid`,
		} {
			if err := e.ownerExec(sql, r.ID.String()); err == nil {
				t.Errorf("%s: the write was accepted", name)
			}
		}
		// retention flips it, deletes its rows, and later the record
		res, err := e.svc.Retention(ctx, e.tid, *e.clock)
		if err != nil || res.Expired != 1 || res.RowsDeleted != 3 {
			t.Fatalf("retention = %+v, %v", res, err)
		}
		got := e.get(r.ID)
		if got.State != run.StateExpired {
			t.Fatalf("state after sweep %s", got.State)
		}
		out, _ := e.d.OwnerStrings(ctx, `SELECT count(*)::text FROM public.report_run_rows`)
		if len(out) != 1 || out[0] != "0" {
			t.Fatalf("rows left: %v", out)
		}
		if _, err := e.svc.Page(ctx, e.tid, chainOf(alice), r.ID, run.PageQuery{}); !errors.Is(err, run.ErrRunExpired) {
			t.Fatalf("page after the sweep: %v", err)
		}
		if err := e.ownerExec(`UPDATE public.report_runs SET state = 'succeeded' WHERE id = $1::uuid`, r.ID.String()); err == nil {
			t.Error("an expired run is final")
		}
		if res, err = e.svc.Retention(ctx, e.tid, e.clock.Add(40*24*time.Hour)); err != nil || res.RecordsDeleted != 1 {
			t.Fatalf("record sweep = %+v, %v", res, err)
		}
		if err := e.svc.Read(ctx, e.tid, r.ID, chainOf(alice), run.ForGet, nil); !errors.Is(err, run.ErrRunNotFound) {
			t.Fatalf("after the record is deleted: %v", err)
		}
	})
}

func TestJobFindingRunningFailsInterruptedNeverResumes(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		r := e.create(alice, `{}`)
		// a crashed first delivery: the run is running and a row exists
		if err := e.ownerExec(`UPDATE public.report_runs SET state = 'running', attempt = 1, started_at = now() WHERE id = $1::uuid`, r.ID.String()); err != nil {
			t.Fatal(err)
		}
		if err := e.ownerExec(`INSERT INTO public.report_run_rows (tenant_id, run_id, row_key, ordinal, cells, sort_keys) SELECT tenant_id, id, 'x', 0, '[]', '{}' FROM public.report_runs WHERE id = $1::uuid`, r.ID.String()); err != nil {
			t.Fatal(err)
		}
		e.work()
		got := e.get(r.ID)
		if got.State != run.StateFailed || got.Failure != run.FailInterrupted {
			t.Fatalf("run = %s/%s", got.State, got.Failure)
		}
		out, _ := e.d.OwnerStrings(context.Background(), `SELECT count(*)::text FROM public.report_run_rows`)
		if out[0] != "0" {
			t.Fatalf("rows left %v", out)
		}
		if k := e.sink.kinds(); !slices.Contains(k, "reports.run.failed:interrupted") {
			t.Fatalf("audit %v", k)
		}
	})
}

func TestFailuresAreNamedAndLeaveNoRows(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		ctx := context.Background()
		// row cap: 3 rows, cap 2
		e.svc.RowCap = 2
		r := e.create(alice, `{}`)
		e.work()
		got := e.get(r.ID)
		if got.State != run.StateFailed || got.Failure != run.FailRowCapExceeded || got.ScopeApplied.Detail["rows"] != 3 || got.ScopeApplied.Detail["cap"] != 2 {
			t.Fatalf("cap: %s/%s %+v", got.State, got.Failure, got.ScopeApplied)
		}
		e.svc.RowCap = 0
		// the runner became inactive between create and run
		r2 := e.create(alice, `{"columns":["sam"]}`)
		e.scopes.fail(alice, authz.ErrOwnerDead)
		e.work()
		e.scopes.set(alice, authztest.ReadScope(grant(conn1)))
		if got := e.get(r2.ID); got.State != run.StateFailed || got.Failure != run.FailRunnerInactive {
			t.Fatalf("inactive: %s/%s", got.State, got.Failure)
		}
		out, _ := e.d.OwnerStrings(ctx, `SELECT count(*)::text FROM public.report_run_rows`)
		if out[0] != "0" {
			t.Fatalf("rows left %v", out)
		}
		// a failed run's page answers run_failed with the reason
		_, err := e.svc.Page(ctx, e.tid, chainOf(alice), r2.ID, run.PageQuery{})
		var fe *run.FailedError
		if !errors.As(err, &fe) || fe.Reason != run.FailRunnerInactive {
			t.Fatalf("page of a failed run: %v", err)
		}
	})
}

func TestReuseCapCancelAndRetry(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		ctx := context.Background()
		var ids []run.ID
		for _, p := range []string{`{"columns":["sam"]}`, `{"columns":["enabled"]}`, `{"columns":["display"]}`, `{"columns":["sam","enabled"]}`} {
			ids = append(ids, e.create(alice, p).ID)
		}
		_, _, err := e.svc.Create(ctx, run.CreateInput{Tenant: e.tid, Chain: chainOf(alice), DefinitionID: "tst-01", Params: jsontext.Value(`{"columns":["enabled","sam"]}`)})
		if !errors.Is(err, run.ErrTooManyJobs) {
			t.Fatalf("fifth open run: %v", err)
		}
		// cancel a queued run: it is cancelled, the job later finds that and stops
		c, err := e.svc.Cancel(ctx, e.tid, chainOf(alice), ids[0])
		if err != nil || c.State != run.StateCancelled {
			t.Fatalf("cancel = %v %v", c.State, err)
		}
		if _, err := e.svc.Cancel(ctx, e.tid, chainOf(bob), ids[1]); !errors.Is(err, run.ErrRunNotFound) {
			t.Fatalf("cancel by another account: %v", err)
		}
		if _, err := e.svc.Cancel(ctx, e.tid, chainOf(alice), ids[0]); !errors.Is(err, run.ErrNotCancellable) {
			t.Fatalf("cancel twice: %v", err)
		}
		e.work()
		if got := e.get(ids[0]); got.State != run.StateCancelled {
			t.Fatalf("cancelled run ran: %s", got.State)
		}
		if got := e.get(ids[1]); got.State != run.StateSucceeded {
			t.Fatalf("other run: %s", got.State)
		}
		// retry of a cancelled run: a new run that names its source; a running source is refused
		re, _, err := e.svc.Retry(ctx, e.tid, chainOf(alice), ids[0])
		if err != nil || re.ID == ids[0] || re.RerunOf == nil || *re.RerunOf != ids[0] {
			t.Fatalf("retry = %+v %v", re, err)
		}
		if _, _, err := e.svc.Retry(ctx, e.tid, chainOf(alice), re.ID); !errors.Is(err, run.ErrRunInProgress) {
			t.Fatalf("retry of a queued run: %v", err)
		}
		if _, _, err := e.svc.Retry(ctx, e.tid, chainOf(bob), ids[0]); !errors.Is(err, run.ErrRunNotFound) {
			t.Fatalf("retry by another account: %v", err)
		}
		// history: the caller's runs only, with scopeCurrent
		items, _, err := e.svc.List(ctx, e.tid, chainOf(alice), run.ListFilter{})
		if err != nil || len(items) != 5 {
			t.Fatalf("list = %d %v", len(items), err)
		}
		for _, it := range items {
			if !it.ScopeCurrent {
				t.Fatalf("scopeCurrent false for %s", it.Run.ID)
			}
		}
		if other, _, _ := e.svc.List(ctx, e.tid, chainOf(bob), run.ListFilter{}); len(other) != 0 {
			t.Fatalf("another account sees %d runs", len(other))
		}
	})
}

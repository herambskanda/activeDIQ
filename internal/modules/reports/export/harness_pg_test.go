package export_test

import (
	"context"
	"crypto/sha256"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/modules/reports/export"
	"github.com/skenzeriq/activediq/internal/modules/reports/run"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/authz/authztest"
	"github.com/skenzeriq/activediq/internal/platform/blob"
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

// hostile are the display values of the seeded rows: every lead the P7 corpus names, in half and full
// width, plus tab, CR and LF leads and plain controls (AC-26).
var hostile = []string{"=1+1", "+cmd", "-2", "@SUM(A1)", "\tx", "\rx", "\nx", "＝1+1", "＋1", "－1", "＠x", " =1", "plain", "a=b", "é‮=", "x\ny"}

func chainOf(id string) authority.Chain {
	return authority.Chain{Requester: authority.Principal{ID: authority.PrincipalID(id), Kind: authority.Human}}
}

func grant(conn authz.ObjectID) authz.ScopeGrant {
	return authz.ScopeGrant{Include: []authz.ScopeTerm{{Kind: authz.TermNamingContext, Connection: conn, Root: nc1}}}
}

type fakeScopes struct {
	mu sync.Mutex
	m  map[string]authz.ReadScope
}

func (f *fakeScopes) set(id string, s authz.ReadScope) { f.mu.Lock(); defer f.mu.Unlock(); f.m[id] = s }
func (f *fakeScopes) For(_ context.Context, _ store.Tx, _ tenant.ID, c authority.Chain, _ authz.Permission) (authz.ReadScope, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.m[string(c.Requester.ID)], nil
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

func (r *recSink) of(kind audit.Kind) []audit.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []audit.Event
	for _, e := range r.ev {
		if e.Kind == kind {
			out = append(out, e)
		}
	}
	return out
}

func detail(e audit.Event, k string) string {
	for _, d := range e.Details {
		if d.Key == k {
			return d.Value
		}
	}
	return ""
}

type catalog struct{ d run.Definition }

func (c catalog) Definition(id string, _ int) (run.Definition, bool) {
	return c.d, id == string(c.d.Def.ID)
}

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
	t       *testing.T
	db      *store.DB
	tid     tenant.ID
	runs    *run.Service
	exp     *export.Service
	reg     *jobs.Registry
	scopes  *fakeScopes
	sink    *recSink
	clock   *time.Time
	blobDir string
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
			{ID: "display", Label: "Display", Type: report.TypeText, Source: report.Attr{Col: "display"}, Default: true},
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
	for i, v := range hostile {
		if err := d.ExecOwner(ctx, `INSERT INTO public.rpt_objects (tenant_id, connection_id, object_guid, nc_guid, sam, enabled, display)
			VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5, true, $6)`, tid.String(), report.GUIDString(conn1), report.GUIDString(oid(byte(0x30+i))),
			report.GUIDString(nc1), "u"+string(rune('a'+i)), v); err != nil {
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
	def := report.Definition{ID: "tst-01", Version: 1, Category: report.CategoryUsers, Title: "Test accounts", Dataset: src.ID,
		Columns: []report.ColumnID{"sam", "enabled", "display"}, Sort: []report.SortKey{{Column: "sam", Dir: report.Asc}},
		Presets: []report.Preset{{ID: "all"}}}
	now := time.Now().UTC().Truncate(time.Second)
	dir := t.TempDir()
	bs, err := blob.NewFS(dir, blob.WithClock(func() time.Time { return time.Now() }))
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, db: db, tid: tid, reg: jobs.NewRegistry(), sink: &recSink{}, clock: &now, blobDir: dir,
		scopes: &fakeScopes{m: map[string]authz.ReadScope{alice: authztest.ReadScope(grant(conn1)), bob: authztest.ReadScope(grant(conn1))}}}
	clock := func() time.Time { return *e.clock }
	e.runs = &run.Service{DB: db, Jobs: e.reg, Scopes: e.scopes, Audit: e.sink, Catalog: catalog{run.Definition{Def: def, SHA256: [32]byte{1}, Dataset: src, SQL: sqlDS}},
		Codec: codec{}, Fresh: fresh{at: now.Add(-time.Minute)}, Now: clock}
	e.exp = &export.Service{DB: db, Jobs: e.reg, Runs: e.runs, Blob: bs, Audit: e.sink, Now: clock}
	for _, k := range []jobs.Kind{e.runs.Kind(), e.runs.RetentionKind(), e.exp.Kind()} {
		if err := e.reg.Register(k); err != nil {
			t.Fatal(err)
		}
	}
	return e
}

// work claims and executes every available job of the run and export kinds.
func (e *env) work() { e.t.Helper(); e.workKinds() }

// workKinds is work, reporting the kinds it executed (so a test can show that no export job was queued
// without reading the jobs table, which only internal/platform/jobs may name).
func (e *env) workKinds() []string {
	e.t.Helper()
	var ran []string
	ctx := context.Background()
	cl, err := jobs.Claim(ctx, e.db, e.reg.TenantLeases(), 20)
	if err != nil {
		e.t.Fatal(err)
	}
	for _, c := range cl {
		if _, err := jobs.NewRunner(e.db, e.reg).Execute(ctx, c); err != nil {
			e.t.Fatalf("Execute %s: %v", c.Kind, err)
		}
		ran = append(ran, c.Kind)
	}
	return ran
}

// finishedRun creates a run for who and executes it.
func (e *env) finishedRun(who string) run.Run {
	e.t.Helper()
	r, _, err := e.runs.Create(context.Background(), run.CreateInput{Tenant: e.tid, Chain: chainOf(who), DefinitionID: "tst-01", Params: jsontext.Value(`{}`)})
	if err != nil {
		e.t.Fatalf("Create run: %v", err)
	}
	e.work()
	return e.run(who, r.ID)
}

func (e *env) run(who string, id run.ID) run.Run {
	e.t.Helper()
	var r run.Run
	if err := e.runs.Read(context.Background(), e.tid, id, chainOf(who), run.ForGet, func(_ context.Context, _ store.Tx, got run.Run) error { r = got; return nil }); err != nil {
		e.t.Fatalf("read run: %v", err)
	}
	return r
}

// export creates an export and executes its job; it returns the record afterwards.
func (e *env) export(who string, id run.ID, f export.Format) export.Export {
	e.t.Helper()
	x, err := e.exp.Create(context.Background(), e.tid, chainOf(who), id, f)
	if err != nil {
		e.t.Fatalf("Create export: %v", err)
	}
	e.work()
	got, err := e.exp.Get(context.Background(), e.tid, chainOf(who), x.ID)
	if err != nil {
		e.t.Fatal(err)
	}
	return got
}

func (e *env) download(who string, id export.ID) ([]byte, *export.Download, error) {
	d, err := e.exp.Download(context.Background(), e.tid, chainOf(who), id)
	if err != nil {
		return nil, nil, err
	}
	defer d.Reader.Close()
	b, err := io.ReadAll(d.Reader)
	if err != nil {
		e.t.Fatal(err)
	}
	return b, d, nil
}

func (e *env) count(sql string) int {
	e.t.Helper()
	var n int
	if err := e.db.WithTenant(context.Background(), e.tid, func(ctx context.Context, tx store.Tx) error { return tx.QueryRow(ctx, sql).Scan(&n) }); err != nil {
		e.t.Fatal(err)
	}
	return n
}

func (e *env) exec(sql string, args ...any) error {
	return e.db.WithTenant(context.Background(), e.tid, func(ctx context.Context, tx store.Tx) error { _, err := tx.Exec(ctx, sql, args...); return err })
}

// canonical recomputes the digest of the API-visible rows with an encoder that shares no code with the product's:
// four bytes of column count, each column ID framed with tag 0xFF, then each cell as tag, 4-byte length, value.
func canonical(cols []string, rows [][]report.Cell) [32]byte {
	b := []byte{0, 0, 0, byte(len(cols))}
	fr := func(tag byte, v string) {
		b = append(b, tag, byte(len(v)>>24), byte(len(v)>>16), byte(len(v)>>8), byte(len(v)))
		b = append(b, v...)
	}
	for _, c := range cols {
		fr(0xFF, c)
	}
	for _, r := range rows {
		for _, c := range r {
			fr(c.DigestTag(), string(c.DigestValue()))
		}
	}
	return sha256.Sum256(b)
}

func apiRows(e *env, who string, id run.ID) (cols []string, rows [][]report.Cell) {
	e.t.Helper()
	cur := ""
	for {
		pg, err := e.runs.Page(context.Background(), e.tid, chainOf(who), id, run.PageQuery{Limit: 500, Cursor: cur})
		if err != nil {
			e.t.Fatal(err)
		}
		if cols == nil {
			for _, c := range pg.Columns {
				cols = append(cols, string(c.ID))
			}
		}
		for _, r := range pg.Rows {
			rows = append(rows, r.Cells)
		}
		if pg.Next == "" {
			return
		}
		cur = pg.Next
	}
}

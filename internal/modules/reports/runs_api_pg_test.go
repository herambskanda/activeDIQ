package reports_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/modules/reports"
	"github.com/skenzeriq/activediq/internal/modules/reports/run"
	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/apihost/apitest"
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

const objectsDDL = `
CREATE TABLE public.rpt_objects (
  tenant_id uuid NOT NULL, connection_id uuid NOT NULL, object_guid uuid NOT NULL, nc_guid uuid, parent_guid uuid,
  ancestry uuid[] NOT NULL DEFAULT '{}', ancestry_complete boolean NOT NULL DEFAULT true,
  sam text NOT NULL, display text NOT NULL DEFAULT '',
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

// staticScopes gives every requester the same grant on conn1.
type staticScopes struct{}

func (staticScopes) For(context.Context, store.Tx, tenant.ID, authority.Chain, authz.Permission) (authz.ReadScope, error) {
	return authztest.ReadScope(authz.ScopeGrant{Include: []authz.ScopeTerm{{Kind: authz.TermNamingContext, Connection: conn1, Root: nc1}}}), nil
}

type sink struct {
	mu sync.Mutex
	ev []audit.Event
}

func (s *sink) Append(_ context.Context, _ store.Tx, e audit.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ev = append(s.ev, e)
	return nil
}

type library struct{ d run.Definition }

func (l library) Definition(id string, _ int) (run.Definition, bool) {
	return l.d, id == string(l.d.Def.ID)
}

type freshAt struct{ at time.Time }

func (f freshAt) Freshness(_ context.Context, _ tenant.ID, cs []authz.ObjectID, now time.Time) (report.Freshness, time.Duration, error) {
	var ws []report.NCWatermark
	for _, c := range cs {
		ws = append(ws, report.NCWatermark{Connection: c, NC: nc1, LastPassAt: f.at, State: report.NCOK})
	}
	return report.Label(ws, time.Hour, now), time.Hour, nil
}

// door is the test's authenticator and authorizer: the principal is chosen by the X-Who header.
type door struct{ allow bool }

func (d *door) Authenticate(r *http.Request) (apihost.Principal, error) {
	p := apihost.Principal{ID: r.Header.Get("X-Who"), Tenant: r.Header.Get("X-Tenant"), Kind: apihost.KindSession, SessionID: "s"}
	if r.Header.Get("X-Kind") == "token" {
		p.Kind = apihost.KindToken
		p.SessionID = ""
	}
	return p, nil
}
func (*door) CheckCSRF(*http.Request, apihost.Principal) error { return nil }
func (d *door) Allow(context.Context, apihost.Principal, string, string) (bool, error) {
	return d.allow, nil
}
func (*door) AllowIP(context.Context, string, string) (apihost.Decision, error) {
	return apihost.Decision{Allowed: true}, nil
}
func (*door) AllowPrincipal(context.Context, string, apihost.Principal) (apihost.Decision, error) {
	return apihost.Decision{Allowed: true}, nil
}
func (*door) Fresh(context.Context, apihost.Principal) (bool, error) { return true, nil }

type apiEnv struct {
	t    *testing.T
	db   *store.DB
	tid  tenant.ID
	svc  *run.Service
	reg  *jobs.Registry
	door *door
	srv  http.Handler
}

func apiSetup(t *testing.T, s *storetest.Server) *apiEnv {
	t.Helper()
	ctx := context.Background()
	d := s.NewDatabase(t)
	d.Migrate(t)
	if err := d.ExecOwner(ctx, objectsDDL); err != nil {
		t.Fatal(err)
	}
	tid := tenanttest.Seed(t, d.ExecOwner, "t")
	for i, r := range []struct {
		conn authz.ObjectID
		sam  string
	}{{conn1, "ann"}, {conn1, "cat"}, {conn1, "bob"}, {conn2, "dan"}} {
		if err := d.ExecOwner(ctx, `INSERT INTO public.rpt_objects (tenant_id, connection_id, object_guid, nc_guid, sam)
			VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5)`, tid.String(), report.GUIDString(r.conn), report.GUIDString(oid(byte(0x30+i))), report.GUIDString(nc1), r.sam); err != nil {
			t.Fatal(err)
		}
	}
	db, err := store.Open(ctx, store.Config{DSN: d.AppDSN()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	anchor := report.Anchor{ID: "t", Table: "rpt_objects", Mode: report.RowAnchor, Project: []report.Ident{"object_guid"},
		Connection: "connection_id", NC: "nc_guid", Object: "object_guid", Parent: "parent_guid", Ancestry: "ancestry", Complete: "ancestry_complete"}
	src := report.Dataset{
		ID: "tst.objects", Base: report.Relation{Table: "rpt_objects"}, RowKey: report.SQL("{t}.object_guid"), Anchors: []report.Anchor{anchor},
		Columns: []report.Column{
			{ID: "name", Label: "Account", Type: report.TypeText, Source: report.Attr{Col: "sam"}, Sortable: true, Default: true,
				Filter: []report.Op{report.OpEq, report.OpContains, report.OpPrefix}},
			{ID: "logon_name", Label: "Display", Type: report.TypeText, Source: report.Attr{Col: "display"}, Default: true},
		},
		Freshness: report.FreshNCWatermark, Tables: []string{"rpt_objects"},
	}
	var reg *reportsql.Registry
	if err := db.WithTenant(ctx, tid, func(ctx context.Context, tx store.Tx) error {
		sc, err := reportsql.CatalogSchema(ctx, tx)
		if err != nil {
			return err
		}
		reg, err = reportsql.NewRegistry(reportsql.Options{Schema: sc, SecretKey: func(string) bool { return false }}, src)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	sqlDS, _ := reg.Dataset(src.ID)
	def := report.Definition{ID: "tst-01", Version: 1, Category: report.CategoryUsers, Title: "Test", Dataset: src.ID,
		Columns: []report.ColumnID{"name", "logon_name"}, Sort: []report.SortKey{{Column: "name", Dir: report.Asc}}, Presets: []report.Preset{{ID: "all"}}}
	e := &apiEnv{t: t, db: db, tid: tid, reg: jobs.NewRegistry(), door: &door{allow: true}}
	e.svc = &run.Service{DB: db, Jobs: e.reg, Scopes: staticScopes{}, Audit: &sink{}, Catalog: library{run.Definition{Def: def, SHA256: [32]byte{1}, Dataset: src, SQL: sqlDS}},
		Codec: reports.Codec{}, Fresh: freshAt{at: time.Now().Add(-time.Minute)}}
	for _, k := range []jobs.Kind{e.svc.Kind(), e.svc.RetentionKind()} {
		if err := e.reg.Register(k); err != nil {
			t.Fatal(err)
		}
	}
	h := &reports.Handlers{Runs: e.svc}
	doc, err := apihost.LoadDocument()
	if err != nil {
		t.Fatal(err)
	}
	pol, err := apihost.LoadPolicy()
	if err != nil {
		t.Fatal(err)
	}
	var rec apitest.Recorder
	perms := apihost.Permissions{"reports.deliver.external", "reports.export", "reports.run", "reports.schedule", "reports.schedule.manage_all",
		"directory.read", "connections.takeover.attest", "siem.destination.manage", "siem.destination.read"}
	e.srv, err = apihost.Build(doc, apitest.Conform(&rec, h.Bind()), pol, perms, apihost.Ports{Authn: e.door, Authz: e.door, Limits: e.door, StepUp: e.door})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if v := rec.All(); len(v) > 0 {
			t.Errorf("response conformance: %v", v)
		}
	})
	return e
}

// work claims and executes every available reports.run job.
func (e *apiEnv) work() {
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

func (e *apiEnv) do(who, method, target, body string, hdr ...string) (int, map[string]any) {
	e.t.Helper()
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	r.Header.Set("X-Who", who)
	r.Header.Set("X-Tenant", e.tid.String())
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	r.RemoteAddr = "203.0.113.7:4444"
	w := httptest.NewRecorder()
	e.srv.ServeHTTP(w, r)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func errCode(m map[string]any) string {
	es, _ := m["errors"].([]any)
	if len(es) == 0 {
		return ""
	}
	c, _ := es[0].(map[string]any)["code"].(string)
	return c
}

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

func names(m map[string]any) []string {
	var out []string
	for _, r := range m["rows"].([]any) {
		c := r.(map[string]any)["cells"].([]any)[0].(map[string]any)
		out = append(out, c["value"].(string))
	}
	return out
}

// AC-08: a completed run carries as_of, the freshness label, the definition version, the digest and the
// state. AC-48: paging and sorting read the same run (same id and as_of); a changed filter is a new run.
func TestRunHeaderPagingAndFilterChange(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := apiSetup(t, s)
		code, created := e.do(alice, "POST", "/api/v1/reports/runs", `{"definitionId":"tst-01","parameters":{"columns":["name"]}}`)
		if code != 202 {
			t.Fatalf("create: %d %v", code, created)
		}
		id := created["id"].(string)
		if created["state"] != "queued" {
			t.Fatalf("a new run is queued: %v", created["state"])
		}
		// the same request inside the reuse window answers the same run
		if _, again := e.do(alice, "POST", "/api/v1/reports/runs", `{"definitionId":"tst-01","parameters":{"columns":["name"]}}`); again["id"] != id {
			t.Errorf("identical create inside the reuse window made a new run: %v vs %v", again["id"], id)
		}
		e.work()

		code, got := e.do(alice, "GET", "/api/v1/reports/runs/"+id, "")
		if code != 200 || got["state"] != "succeeded" {
			t.Fatalf("get: %d %v", code, got)
		}
		fr := got["freshness"].(map[string]any)
		if got["asOf"] == nil || fr["label"] == "" || fr["state"] != "synced" || got["definitionVersion"] != float64(1) ||
			got["rowCount"] != float64(3) || got["objectsChecked"] != float64(3) {
			t.Errorf("header fields: %v", got)
		}
		if d, _ := got["digest"].(string); !hex64.MatchString(d) {
			t.Errorf("digest = %v", got["digest"])
		}
		asOf := got["asOf"]

		code, p1 := e.do(alice, "GET", "/api/v1/reports/runs/"+id+"/rows?sortBy=name&order=desc&limit=2", "")
		if code != 200 || p1["runId"] != id {
			t.Fatalf("page 1: %d %v", code, p1)
		}
		if g := names(p1); strings.Join(g, ",") != "cat,bob" {
			t.Fatalf("page 1 rows = %v, want cat,bob", g)
		}
		next, _ := p1["page"].(map[string]any)["nextCursor"].(string)
		if next == "" {
			t.Fatal("page 1 has no next cursor")
		}
		_, p2 := e.do(alice, "GET", "/api/v1/reports/runs/"+id+"/rows?sortBy=name&order=desc&limit=2&cursor="+next, "")
		if g := names(p2); strings.Join(g, ",") != "ann" || p2["page"].(map[string]any)["nextCursor"] != nil {
			t.Fatalf("page 2 rows = %v", g)
		}
		if code, _ := e.do(alice, "GET", "/api/v1/reports/runs/"+id+"/rows?sortBy=logon_name&limit=2", ""); code != 400 {
			t.Errorf("sorting by a column that is not sortable: %d, want 400", code)
		}
		if code, bad := e.do(alice, "GET", "/api/v1/reports/runs/"+id+"/rows?sortBy=name&limit=2&cursor="+next, ""); code != 400 || errCode(bad) != "bad_cursor" {
			t.Errorf("a cursor from another sort: %d %v", code, bad)
		}
		_, again := e.do(alice, "GET", "/api/v1/reports/runs/"+id, "")
		if again["id"] != id || again["asOf"] != asOf {
			t.Errorf("paging changed the run: %v", again)
		}

		// a filter change is a new run with its own rows
		code, c2 := e.do(alice, "POST", "/api/v1/reports/runs",
			`{"definitionId":"tst-01","parameters":{"columns":["name"],"filters":[{"kind":"compare","column":"name","operator":"equals","value":{"kind":"text","value":"ann"}}]}}`)
		if code != 202 || c2["id"] == id {
			t.Fatalf("filter change: %d id %v (first %v)", code, c2["id"], id)
		}
		e.work()
		_, r2 := e.do(alice, "GET", "/api/v1/reports/runs/"+c2["id"].(string)+"/rows", "")
		if g := names(r2); strings.Join(g, ",") != "ann" || r2["rowCount"] != float64(1) {
			t.Errorf("filtered run rows = %v", g)
		}
		_, params := e.do(alice, "GET", "/api/v1/reports/runs/"+c2["id"].(string), "")
		if fs := params["parameters"].(map[string]any)["filters"].([]any); len(fs) != 1 || fs[0].(map[string]any)["kind"] != "condition" {
			t.Errorf("parameters view = %v", params["parameters"])
		}
		// the history lists both, newest first
		code, list := e.do(alice, "GET", "/api/v1/reports/runs?state=succeeded", "")
		if items, _ := list["items"].([]any); code != 200 || len(items) != 2 || items[0].(map[string]any)["id"] != c2["id"] {
			t.Errorf("history: %d %v", code, list)
		}
	})
}

// RP9 at the door: another account meets 404 run_not_found on every read of the run, and its history
// does not list it.
func TestOtherAccountMeetsNotFound(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := apiSetup(t, s)
		_, c := e.do(alice, "POST", "/api/v1/reports/runs", `{"definitionId":"tst-01"}`)
		id := c["id"].(string)
		e.work()
		for _, target := range []string{"/api/v1/reports/runs/" + id, "/api/v1/reports/runs/" + id + "/rows"} {
			if code, m := e.do(bob, "GET", target, ""); code != 404 || errCode(m) != "run_not_found" {
				t.Errorf("bob %s: %d %v", target, code, m)
			}
		}
		for _, target := range []string{"/api/v1/reports/runs/" + id + "/cancel", "/api/v1/reports/runs/" + id + "/retry"} {
			if code, m := e.do(bob, "POST", target, ""); code != 404 {
				t.Errorf("bob %s: %d %v", target, code, m)
			}
		}
		if _, l := e.do(bob, "GET", "/api/v1/reports/runs", ""); len(l["items"].([]any)) != 0 {
			t.Errorf("bob's history lists alice's run: %v", l)
		}
		if code, _ := e.do(alice, "GET", "/api/v1/reports/runs/"+id+"/rows", ""); code != 200 {
			t.Errorf("the runner reads her own rows: %d", code)
		}
	})
}

// AC-42: without reports.run every operation of the run path is forbidden, and a token principal is too.
func TestForbiddenWithoutPermissionAndForTokens(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := apiSetup(t, s)
		_, c := e.do(alice, "POST", "/api/v1/reports/runs", `{"definitionId":"tst-01"}`)
		id := c["id"].(string)
		e.work()
		ops := []struct{ method, target, body string }{
			{"POST", "/api/v1/reports/runs", `{"definitionId":"tst-01"}`},
			{"GET", "/api/v1/reports/runs/" + id, ""},
			{"POST", "/api/v1/reports/runs/" + id + "/cancel", ""},
			{"POST", "/api/v1/reports/runs/" + id + "/retry", ""},
			{"GET", "/api/v1/reports/runs", ""},
			{"GET", "/api/v1/reports/runs/" + id + "/rows", ""},
		}
		e.door.allow = false
		for _, o := range ops {
			if code, m := e.do(alice, o.method, o.target, o.body); code != 403 {
				t.Errorf("no permission, %s %s: %d %v", o.method, o.target, code, m)
			}
		}
		e.door.allow = true
		for _, o := range ops {
			if code, m := e.do(alice, o.method, o.target, o.body, "X-Kind", "token"); code != 403 {
				t.Errorf("token, %s %s: %d %v", o.method, o.target, code, m)
			}
		}
	})
}

// A run that has not finished answers run_not_ready on its rows; cancel then retry give a new run.
func TestNotReadyCancelAndRetry(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := apiSetup(t, s)
		_, c := e.do(alice, "POST", "/api/v1/reports/runs", `{"definitionId":"tst-01"}`)
		id := c["id"].(string)
		if code, m := e.do(alice, "GET", "/api/v1/reports/runs/"+id+"/rows", ""); code != 409 || errCode(m) != "run_not_ready" {
			t.Errorf("rows of a queued run: %d %v", code, m)
		}
		if code, m := e.do(alice, "POST", "/api/v1/reports/runs/"+id+"/retry", ""); code != 409 || errCode(m) != "run_in_progress" {
			t.Errorf("retry of a queued run: %d %v", code, m)
		}
		if code, m := e.do(alice, "POST", "/api/v1/reports/runs/"+id+"/cancel", ""); code != 200 || m["state"] != "cancelled" {
			t.Fatalf("cancel: %d %v", code, m)
		}
		if code, m := e.do(alice, "GET", "/api/v1/reports/runs/"+id+"/rows", ""); code != 409 || errCode(m) != "run_failed" {
			t.Errorf("rows of a cancelled run: %d %v", code, m)
		}
		code, r := e.do(alice, "POST", "/api/v1/reports/runs/"+id+"/retry", "")
		if code != 202 || r["id"] == id || r["rerunOf"] != id {
			t.Errorf("retry: %d %v", code, r)
		}
		if code, m := e.do(alice, "POST", "/api/v1/reports/runs", `{"definitionId":"nope-01"}`); code != 404 || errCode(m) != "definition_not_found" {
			t.Errorf("unknown definition: %d %v", code, m)
		}
	})
}

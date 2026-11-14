//go:build lab

package server

// reportsRig is the composed lab server the T-1192 and T-1480 lab tests share: the Samba lab connection,
// the sync.full job kind, the reports run path behind the real apihost router, and a Postgres per test.
// Nothing is seeded by test code into inventory; the first sync job fills it.

import (
	"bytes"
	"context"
	jsonv2 "encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/compose/config"
	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/directory/inventory"
	dsync "github.com/skenzeriq/activediq/internal/directory/sync"
	"github.com/skenzeriq/activediq/internal/modules/reports/run"
	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/authz/authztest"
	"github.com/skenzeriq/activediq/internal/platform/capability"
	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/keys"
	"github.com/skenzeriq/activediq/internal/platform/secret"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/owners"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/testlab"
)

type reportsRig struct {
	t     *testing.T
	le    *testlab.Env
	d     *storetest.Database
	db    *store.DB
	ctx   context.Context
	conns *connection.Registry
	svc   *connection.Service
	tid   tenant.ID
	jreg  *jobs.Registry
	runs  *run.Service
	seed  labSeeder
	scope authz.ReadScope
	srv   http.Handler
}

func newReportsRig(t *testing.T, s *storetest.Server) *reportsRig {
	t.Helper()
	r := &reportsRig{t: t, le: testlab.Load(t)}
	r.d = s.NewDatabase(t)
	r.d.Migrate(t)
	var err error
	r.db, err = store.Open(context.Background(), store.Config{DSN: r.d.AppDSN()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.db.Close)
	var cancel context.CancelFunc
	r.ctx, cancel = context.WithTimeout(context.Background(), 10*time.Minute)
	t.Cleanup(cancel)
	ctx, db, le := r.ctx, r.db, r.le

	env := envOf(map[string]string{"LAB_LDAPS_PORT": le.Port, "LAB_SVC_PASSWORD": le.Values["LAB_SVC_PASSWORD"], "LAB_CA": le.CAPath})
	r.conns = connection.NewRegistry(db)
	var next client.ConnectorSource
	src, seed, closeFn, err := labBootstrap(ctx, env, next)
	if err != nil {
		t.Fatalf("labBootstrap: %v", err)
	}
	r.seed = seed
	t.Cleanup(closeFn)
	kek, err := keys.NewLocalProvider("test-kek", secret.FromBytes(bytes.Repeat([]byte{7}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	ch := audit.NewChainer(db)
	r.jreg = jobs.NewRegistry()
	r.tid, err = bootstrapTenant(ctx, config.Config{InstanceID: "node-1"}, db, ch, kek, r.jreg)
	if err != nil {
		t.Fatal(err)
	}
	vopts, err := verifyOptions(src)
	if err != nil {
		t.Fatal(err)
	}
	// The composition under test: sync.full over the lab's in-process connector, queued by the
	// activation hook of the connection service.
	sk, err := buildSync(db, r.conns, src, r.jreg, "node-1", time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	r.svc, err = connection.NewService(r.conns, client.New(vopts...), ch, connection.WithActivationHook(sk.Jobs))
	if err != nil {
		t.Fatal(err)
	}

	// Reports over the real router, scoped to the lab connection's domain NC (set after the seed).
	_, host, err := bootReport(ctx, capability.NewSet(), directoryServices(db), owners.Lookup)
	if err != nil {
		t.Fatal(err)
	}
	var tag apihost.TagHandlers
	r.runs, tag, err = buildReports(ctx, db, host, r.jreg, ch, inventory.NewReader(db, nil), lazyScope{func() authz.ReadScope { return r.scope }}, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := apihost.LoadDocument()
	if err != nil {
		t.Fatal(err)
	}
	pol, err := apihost.LoadPolicy()
	if err != nil {
		t.Fatal(err)
	}
	door := rptDoor{}
	r.srv, err = apihost.Build(doc, []apihost.TagHandlers{tag}, pol, apihost.Permissions{"reports.run", "reports.export", "reports.schedule",
		"reports.schedule.manage_all", "reports.deliver.external", "directory.read", "connections.takeover.attest", "siem.destination.manage",
		"siem.destination.read"}, apihost.Ports{Authn: door, Authz: door, Limits: door, StepUp: door})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// do calls the real router as the test console user.
func (r *reportsRig) do(method, target, body string) (int, map[string]any) {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Header.Set("X-Who", "00000000-0000-4000-8000-0000000000a1")
	req.Header.Set("X-Tenant", r.tid.String())
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.RemoteAddr = "203.0.113.7:4444"
	w := httptest.NewRecorder()
	r.srv.ServeHTTP(w, req)
	var out map[string]any
	_ = jsonv2.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// runKinds executes every queued job of the given kinds, like the worker does.
func (r *reportsRig) runKinds(kinds ...string) {
	r.t.Helper()
	var offered []jobs.KindLease
	for _, kl := range r.jreg.TenantLeases() {
		for _, k := range kinds {
			if kl.Kind == k {
				offered = append(offered, kl)
			}
		}
	}
	cl, err := jobs.Claim(r.ctx, r.db, offered, 20)
	if err != nil {
		r.t.Fatal(err)
	}
	for _, c := range cl {
		if res, err := jobs.NewRunner(r.db, r.jreg).Execute(r.ctx, c); err != nil || res != jobs.Completed {
			r.t.Fatalf("job %s: %v %v", c.Kind, res, err)
		}
	}
}

// report runs a shipped report (preset empty: the definition's default) and returns the finished run.
func (r *reportsRig) report(definition, preset string) map[string]any {
	r.t.Helper()
	body := `{"definitionId":"` + definition + `"`
	if preset != "" {
		body += `,"presetId":"` + preset + `"`
	}
	return r.reportBody(body + "}")
}

// reportBody runs the report a create body asks for. An identical create within the run path's 60 s reuse
// window (service.ReuseWindow, spec 6.1) returns the earlier run, so a test that needs a fresh run of the
// same report after a sync changes the body (for example the columns).
func (r *reportsRig) reportBody(body string) map[string]any {
	r.t.Helper()
	code, created := r.do("POST", "/api/v1/reports/runs", body)
	if code != http.StatusAccepted {
		r.t.Fatalf("create %s: %d %v", body, code, created)
	}
	id, _ := created["id"].(string)
	r.runKinds(r.runs.Kind().Name)
	code, got := r.do("GET", "/api/v1/reports/runs/"+id, "")
	if code != http.StatusOK || got["state"] != "succeeded" {
		r.t.Fatalf("get run %s: %d %v", body, code, got)
	}
	return got
}

// activate runs the lab seed (the real activation path, which queues sync.full), scopes the reports to the
// connection's domain NC and runs the first sync. It returns the connection id.
func (r *reportsRig) activateAndSync() inventory.ConnectionID {
	r.t.Helper()
	if err := r.seed(r.ctx, r.conns, r.svc, r.tid); err != nil {
		r.t.Fatalf("seed: %v", err)
	}
	all, err := r.conns.List(r.ctx, r.tid, false)
	if err != nil || len(all) != 1 || all[0].State != connection.StateActive {
		r.t.Fatalf("connections after the seed: %v %v", all, err)
	}
	cid := inventory.ConnectionID(all[0].ID)
	connID, _ := authz.ParseObjectID(string(cid))
	ncID, _ := authz.ParseObjectID(strings.ToLower(string(all[0].DirectoryIdentity)))
	r.scope = authztest.ReadScope(authz.ScopeGrant{Include: []authz.ScopeTerm{{Kind: authz.TermNamingContext, Connection: connID, Root: ncID}}})
	r.runKinds(dsync.JobFull)
	return cid
}

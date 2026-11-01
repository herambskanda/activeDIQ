package server

// Composition test for the reports wiring (T-1104): the sealed host over inventory.Datasets(), the SQL
// registry compiled against the migrated schema, and the shipped library as run.Catalog, driven through
// the run API over a seeded PostgreSQL. It lives here because only compose wires these together.

import (
	"context"
	jsonv2 "encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/authz/authztest"
	"github.com/skenzeriq/activediq/internal/platform/capability"
	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/owners"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

const (
	rptDom  = "dddddddd-0000-4000-8000-000000000001"
	rptOU   = "dddddddd-0000-4000-8000-000000000002"
	rptCred = "11111111-1111-4111-8111-111111111111"
)

// rptScopes grants every requester the whole naming context of one connection.
type rptScopes struct{ scope authz.ReadScope }

func (s rptScopes) For(context.Context, store.Tx, tenant.ID, authority.Chain, authz.Permission) (authz.ReadScope, error) {
	return s.scope, nil
}

type rptSink struct{}

func (rptSink) Append(context.Context, store.Tx, audit.Event) error { return nil }

// rptDoor authenticates the principal named by X-Who and allows everything.
type rptDoor struct{}

func (rptDoor) Authenticate(r *http.Request) (apihost.Principal, error) {
	return apihost.Principal{ID: r.Header.Get("X-Who"), Tenant: r.Header.Get("X-Tenant"), Kind: apihost.KindSession, SessionID: "s"}, nil
}
func (rptDoor) CheckCSRF(*http.Request, apihost.Principal) error { return nil }
func (rptDoor) Allow(context.Context, apihost.Principal, string, string) (bool, error) {
	return true, nil
}
func (rptDoor) AllowIP(context.Context, string, string) (apihost.Decision, error) {
	return apihost.Decision{Allowed: true}, nil
}
func (rptDoor) AllowPrincipal(context.Context, string, apihost.Principal) (apihost.Decision, error) {
	return apihost.Decision{Allowed: true}, nil
}
func (rptDoor) Fresh(context.Context, apihost.Principal) (bool, error) { return true, nil }

func TestReportsCatalogServesShippedLibrary(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		ctx := context.Background()
		d := s.NewDatabase(t)
		d.Migrate(t)
		tid := tenanttest.Seed(t, d.ExecOwner, "A")
		db, err := store.Open(ctx, store.Config{DSN: d.AppDSN()})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(db.Close)

		conn, err := connection.NewRegistry(db).Create(ctx, tid,
			connection.New{Kind: connection.KindADForest, DisplayName: "corp", CredentialID: rptCred, Transport: connection.TransportLDAPS})
		if err != nil {
			t.Fatal(err)
		}
		cid := inventory.ConnectionID(conn.ID)
		at := time.Now().UTC().Add(-time.Hour)
		obs := []inventory.Observation{
			{Object: inventory.GUID(rptDom), NC: inventory.GUID(rptDom), Kind: inventory.KindOther, Class: "domainDNS", State: inventory.ObjLive},
			{Object: inventory.GUID(rptOU), NC: inventory.GUID(rptDom), Kind: inventory.KindOU, Class: "organizationalUnit", State: inventory.ObjLive,
				Parent: inventory.GUID(rptDom), Ancestry: []inventory.GUID{inventory.GUID(rptDom)}},
		}
		for i, sam := range []string{"ann", "bob", "cat"} {
			en := true
			obs = append(obs, inventory.Observation{Object: inventory.GUID("aa000000-0000-4000-8000-00000000000" + string(rune('1'+i))),
				NC: inventory.GUID(rptDom), Kind: inventory.KindUser, Class: "user", State: inventory.ObjLive,
				Parent: inventory.GUID(rptOU), Ancestry: []inventory.GUID{inventory.GUID(rptOU), inventory.GUID(rptDom)},
				DN: "CN=" + sam + ",OU=People,DC=example,DC=test", RDN: "CN=" + sam, SAMAccountName: sam, DisplayName: sam + " Display",
				Enabled: &en, WhenCreated: at.Add(-24 * time.Hour)})
		}
		if err := db.WithTenant(ctx, tid, func(ctx context.Context, tx store.Tx) error {
			_, err := inventory.Populator{}.Populate(ctx, tx, cid, at, obs)
			return err
		}); err != nil {
			t.Fatal(err)
		}

		_, host, err := bootReport(ctx, capability.NewSet(), directoryServices(db), owners.Lookup)
		if err != nil {
			t.Fatalf("bootReport: %v", err)
		}
		connID, err := authz.ParseObjectID(string(cid))
		if err != nil {
			t.Fatal(err)
		}
		domID, err := authz.ParseObjectID(rptDom)
		if err != nil {
			t.Fatal(err)
		}
		scope := authztest.ReadScope(authz.ScopeGrant{Include: []authz.ScopeTerm{{Kind: authz.TermNamingContext, Connection: connID, Root: domID}}})
		jreg := jobs.NewRegistry()
		svc, tag, err := buildReports(ctx, db, host, jreg, rptSink{}, inventory.NewReader(db, nil), rptScopes{scope}, nil, "")
		if err != nil {
			t.Fatalf("buildReports: %v", err)
		}
		doc, err := apihost.LoadDocument()
		if err != nil {
			t.Fatal(err)
		}
		pol, err := apihost.LoadPolicy()
		if err != nil {
			t.Fatal(err)
		}
		perms := apihost.Permissions{"reports.run", "reports.export", "reports.schedule", "reports.schedule.manage_all",
			"reports.deliver.external", "directory.read", "connections.takeover.attest", "siem.destination.manage", "siem.destination.read"}
		door := rptDoor{}
		srv, err := apihost.Build(doc, []apihost.TagHandlers{tag}, pol, perms, apihost.Ports{Authn: door, Authz: door, Limits: door, StepUp: door})
		if err != nil {
			t.Fatal(err)
		}
		do := func(method, target, body string) (int, map[string]any) {
			r := httptest.NewRequest(method, target, strings.NewReader(body))
			r.Header.Set("X-Who", "00000000-0000-4000-8000-0000000000a1")
			r.Header.Set("X-Tenant", tid.String())
			if body != "" {
				r.Header.Set("Content-Type", "application/json")
			}
			r.RemoteAddr = "203.0.113.7:4444"
			w := httptest.NewRecorder()
			srv.ServeHTTP(w, r)
			var out map[string]any
			_ = jsonv2.Unmarshal(w.Body.Bytes(), &out)
			return w.Code, out
		}

		code, created := do("POST", "/api/v1/reports/runs", `{"definitionId":"usr-01"}`)
		if code != http.StatusAccepted {
			t.Fatalf("create usr-01: %d %v", code, created)
		}
		id, _ := created["id"].(string)
		cl, err := jobs.Claim(ctx, db, jreg.TenantLeases(), 20)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range cl {
			if c.Kind != svc.Kind().Name {
				continue
			}
			if _, err := jobs.NewRunner(db, jreg).Execute(ctx, c); err != nil {
				t.Fatalf("Execute: %v", err)
			}
		}
		code, got := do("GET", "/api/v1/reports/runs/"+id, "")
		if code != http.StatusOK || got["state"] != "succeeded" || got["rowCount"] != float64(3) {
			t.Fatalf("get run: %d %v", code, got)
		}

		code, bad := do("POST", "/api/v1/reports/runs", `{"definitionId":"usr-99"}`)
		es, _ := bad["errors"].([]any)
		var errCode string
		if len(es) > 0 {
			errCode, _ = es[0].(map[string]any)["code"].(string)
		}
		if code != http.StatusNotFound || errCode != "definition_not_found" {
			t.Fatalf("unknown definition: %d %v", code, bad)
		}
	})
}

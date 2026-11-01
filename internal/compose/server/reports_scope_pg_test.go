package server

// T-1151: the report run path over the composed rbac.ReadScopes (T-0916), not a stub producer. Two naming
// contexts of one connection hold users; an account assigned one of them runs a shipped library report and
// reads only that context's rows; an account with no assignment gets 403 (run.Service surfaces
// authz.ErrOwnerDead for an owner with nothing to read, T-0959), never the other context's rows.

import (
	"context"
	jsonv2 "encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/capability"
	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/rbac"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/owners"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

const (
	scpDomA   = "dddddddd-0000-4000-8000-0000000000a1"
	scpDomB   = "dddddddd-0000-4000-8000-0000000000b1"
	scpRunner = "c0000000-0000-4000-8000-000000000001" // assigned the naming context of scpDomA
	scpNobody = "c0000000-0000-4000-8000-000000000002" // an active account with no assignment
)

func TestReportsRunOverComposedReadScopes(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		ctx := context.Background()
		e := bkSetup(t, s)

		// Inventory: three users in domain A, two in domain B, both naming contexts of the AD connection.
		at := time.Now().UTC().Add(-time.Hour)
		en := true
		var obs []inventory.Observation
		users := map[string][]string{scpDomA: {"ann", "bob", "cat"}, scpDomB: {"dan", "eve"}}
		n := 0
		for _, dom := range []string{scpDomA, scpDomB} {
			obs = append(obs, inventory.Observation{Object: inventory.GUID(dom), NC: inventory.GUID(dom), Kind: inventory.KindOther, Class: "domainDNS", State: inventory.ObjLive})
			for _, sam := range users[dom] {
				n++
				obs = append(obs, inventory.Observation{Object: inventory.GUID("aa000000-0000-4000-8000-00000000000" + string(rune('0'+n))),
					NC: inventory.GUID(dom), Kind: inventory.KindUser, Class: "user", State: inventory.ObjLive,
					Parent: inventory.GUID(dom), Ancestry: []inventory.GUID{inventory.GUID(dom)},
					DN: "CN=" + sam + ",DC=example,DC=test", RDN: "CN=" + sam, SAMAccountName: sam, DisplayName: sam + " Display",
					Enabled: &en, WhenCreated: at.Add(-24 * time.Hour)})
			}
		}
		if err := e.db.WithTenant(ctx, e.ten, func(ctx context.Context, tx store.Tx) error {
			_, err := inventory.Populator{}.Populate(ctx, tx, inventory.ConnectionID(e.ad), at, obs)
			return err
		}); err != nil {
			t.Fatal(err)
		}

		// Accounts and the grant: a role holding reports.run, assigned over domain A's naming context.
		e.local(t, scpRunner, "active")
		e.local(t, scpNobody, "active")
		e.exec(t, `INSERT INTO public.authz_roles (tenant_id, role_name, tier) VALUES ($1::uuid, 'report-runner', 2)`, e.ten.String())
		e.exec(t, `INSERT INTO public.authz_role_permissions (tenant_id, role_id, permission)
			SELECT $1::uuid, r.id, 'reports.run' FROM public.authz_roles r WHERE r.tenant_id = $1::uuid AND r.role_name = 'report-runner'`, e.ten.String())
		e.exec(t, `INSERT INTO public.authz_assignments (tenant_id, account_id, role_id, valid_from, granted_by, assignment_state)
			SELECT $1::uuid, $2::uuid, r.id, now() - interval '2 hours', 'test', 'active' FROM public.authz_roles r WHERE r.tenant_id = $1::uuid AND r.role_name = 'report-runner'`, e.ten.String(), scpRunner)
		e.exec(t, `INSERT INTO public.authz_assignment_roots (tenant_id, assignment_id, ordinal, is_exclude, root_kind, connection_id, root_guid)
			SELECT $1::uuid, a.id, 0, false, $3, $4::uuid, $5::uuid FROM public.authz_assignments a WHERE a.tenant_id = $1::uuid AND a.account_id = $2::uuid`,
			e.ten.String(), scpRunner, string(rbac.NamingContext), e.ad, scpDomA)

		// The composition under test: the booted contributions, the authorizer, buildReadScopes, buildReports.
		contrib, host, err := bootReport(ctx, capability.NewSet(capability.DirectoryAD, capability.DirectoryEntra, capability.TenantProvisioning), directoryServices(e.db), owners.Lookup)
		if err != nil {
			t.Fatalf("bootReport: %v", err)
		}
		az, err := rbacAuthorizer(e.db, noFacts{})
		if err != nil {
			t.Fatal(err)
		}
		rs, err := buildReadScopes(az, contrib)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := buildReports(ctx, e.db, host, jobs.NewRegistry(), rptSink{}, inventory.NewReader(e.db, nil), nil, nil, ""); err == nil {
			t.Fatal("buildReports accepted a nil read-scope producer")
		}
		jreg := jobs.NewRegistry()
		svc, tag, err := buildReports(ctx, e.db, host, jreg, rptSink{}, inventory.NewReader(e.db, nil), rs, nil, "")
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
		do := func(who, method, target, body string) (int, map[string]any) {
			r := httptest.NewRequest(method, target, strings.NewReader(body))
			r.Header.Set("X-Who", who)
			r.Header.Set("X-Tenant", e.ten.String())
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

		// An account with no assignment: refused, and no run is created.
		if code, body := do(scpNobody, "POST", "/api/v1/reports/runs", `{"definitionId":"usr-01"}`); code != http.StatusForbidden {
			t.Fatalf("unassigned account: %d %v; want 403", code, body)
		}

		// The assigned account: the run is created (not 503) and reads domain A only.
		code, created := do(scpRunner, "POST", "/api/v1/reports/runs", `{"definitionId":"usr-01"}`)
		if code != http.StatusAccepted {
			t.Fatalf("create usr-01: %d %v; want 202", code, created)
		}
		id, _ := created["id"].(string)
		cl, err := jobs.Claim(ctx, e.db, jreg.TenantLeases(), 20)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range cl {
			if c.Kind != svc.Kind().Name {
				continue
			}
			if _, err := jobs.NewRunner(e.db, jreg).Execute(ctx, c); err != nil {
				t.Fatalf("Execute: %v", err)
			}
		}
		code, got := do(scpRunner, "GET", "/api/v1/reports/runs/"+id, "")
		if code != http.StatusOK || got["state"] != "succeeded" || got["rowCount"] != float64(3) {
			t.Fatalf("get run: %d %v; want succeeded with 3 rows", code, got)
		}
		code, page := do(scpRunner, "GET", "/api/v1/reports/runs/"+id+"/rows", "")
		if code != http.StatusOK {
			t.Fatalf("rows: %d %v", code, page)
		}
		raw, _ := jsonv2.Marshal(page)
		for _, sam := range users[scpDomA] {
			if !strings.Contains(string(raw), sam) {
				t.Errorf("domain A user %q missing from %s", sam, raw)
			}
		}
		for _, sam := range users[scpDomB] {
			if strings.Contains(string(raw), sam) {
				t.Errorf("domain B user %q leaked into %s", sam, raw)
			}
		}

		// Another account cannot read the run either.
		if code, _ := do(scpNobody, "GET", "/api/v1/reports/runs/"+id+"/rows", ""); code == http.StatusOK {
			t.Errorf("an unassigned account read another account's run rows")
		}
	})
}

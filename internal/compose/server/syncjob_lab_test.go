//go:build lab

package server

// T-1192 acceptance 1 and 2 on the Samba lab, through the composed server path: the lab seed activates the
// connection, the activation hook queues sync.full, the job runs the T-1191 engine over the in-process
// connector under the platform leases, and the inventory the reports read holds the lab with no test-seeded
// object. The report call goes through the real apihost router.

import (
	"bytes"
	"context"
	jsonv2 "encoding/json/v2"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/compose/config"
	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/directory/ldapfilter"
	dsync "github.com/skenzeriq/activediq/internal/directory/sync"
	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
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

// lazyScope grants the whole naming context of the lab connection, known only after the lab seed.
type lazyScope struct{ get func() authz.ReadScope }

func (s lazyScope) For(context.Context, store.Tx, tenant.ID, authority.Chain, authz.Permission) (authz.ReadScope, error) {
	return s.get(), nil
}

// ldapCount counts the entries under base that match f, by a direct LDAPS search of the lab.
// placeableCount counts what the connector can deliver: entries with an identity (objectGUID) and a
// classification (instanceType) whose parent is itself deliverable, since an entry whose parent the
// bound account cannot read is withheld rather than delivered with a guessed ancestry (Samba's partial
// system containers, e.g. CN=MicrosoftDNS, are such parents).
func placeableCount(t *testing.T, sess *ad.Session, base dn.ObjectRef, an, guidAttr, itAttr ldapfilter.AttrName) int {
	t.Helper()
	complete := ldapfilter.And(ldapfilter.Present(an), ldapfilter.Present(guidAttr), ldapfilter.Present(itAttr))
	var parents []dn.DN
	var all []dn.DN
	collect := func(dst *[]dn.DN, f ldapfilter.Filter) {
		err := sess.Search(context.Background(), ad.SearchRequest{Base: base, Scope: ad.ScopeSubtree, Filter: f, Attributes: []string{"objectGUID"}},
			func(e *ad.Entry) error {
				d, err := dn.Parse(e.DN, dn.Strict)
				if err != nil {
					return err
				}
				*dst = append(*dst, d)
				return nil
			})
		if err != nil {
			t.Fatalf("direct LDAP listing: code %s", ad.CodeOf(err))
		}
	}
	collect(&all, complete)
	collect(&parents, ldapfilter.And(ldapfilter.Present(an), ldapfilter.Not(complete)))
	n := 0
	for _, d := range all {
		p := d.Parent()
		withheldParent := false
		for _, w := range parents {
			if dn.Equal(p, w) {
				withheldParent = true
				break
			}
		}
		if !withheldParent {
			n++
		}
	}
	return n
}

func ldapCount(t *testing.T, sess *ad.Session, base dn.ObjectRef, f ldapfilter.Filter) int {
	t.Helper()
	n := 0
	err := sess.Search(context.Background(), ad.SearchRequest{Base: base, Scope: ad.ScopeSubtree, Filter: f, Attributes: []string{"objectGUID"}},
		func(*ad.Entry) error { n++; return nil })
	if err != nil {
		t.Fatalf("direct LDAP count: code %s", ad.CodeOf(err))
	}
	return n
}

func TestLabFirstSyncFillsInventoryAndReportsRunOnIt(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		le := testlab.Load(t)
		d := s.NewDatabase(t)
		d.Migrate(t)
		db, err := store.Open(context.Background(), store.Config{DSN: d.AppDSN()})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(db.Close)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		t.Cleanup(cancel)

		env := envOf(map[string]string{"LAB_LDAPS_PORT": le.Port, "LAB_SVC_PASSWORD": le.Values["LAB_SVC_PASSWORD"], "LAB_CA": le.CAPath})
		conns := connection.NewRegistry(db)
		var next client.ConnectorSource
		src, seed, closeFn, err := labBootstrap(ctx, env, next)
		if err != nil {
			t.Fatalf("labBootstrap: %v", err)
		}
		t.Cleanup(closeFn)
		kek, err := keys.NewLocalProvider("test-kek", secret.FromBytes(bytes.Repeat([]byte{7}, 32)))
		if err != nil {
			t.Fatal(err)
		}
		ch := audit.NewChainer(db)
		jreg := jobs.NewRegistry()
		tid, err := bootstrapTenant(ctx, config.Config{InstanceID: "node-1"}, db, ch, kek, jreg)
		if err != nil {
			t.Fatal(err)
		}
		vopts, err := verifyOptions(src)
		if err != nil {
			t.Fatal(err)
		}
		// The composition under test: sync.full over the lab's in-process connector, queued by the
		// activation hook of the connection service.
		sk, err := buildSync(db, conns, src, jreg, "node-1", time.Hour, 0)
		if err != nil {
			t.Fatal(err)
		}
		svc, err := connection.NewService(conns, client.New(vopts...), ch, connection.WithActivationHook(sk.Jobs))
		if err != nil {
			t.Fatal(err)
		}

		// Reports over the real router, scoped to the lab connection's domain NC.
		var scope authz.ReadScope
		_, host, err := bootReport(ctx, capability.NewSet(), directoryServices(db), owners.Lookup)
		if err != nil {
			t.Fatal(err)
		}
		runs, tag, err := buildReports(ctx, db, host, jreg, ch, inventory.NewReader(db, nil), lazyScope{func() authz.ReadScope { return scope }}, nil, "")
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
		srv, err := apihost.Build(doc, []apihost.TagHandlers{tag}, pol, apihost.Permissions{"reports.run", "reports.export", "reports.schedule",
			"reports.schedule.manage_all", "reports.deliver.external", "directory.read", "connections.takeover.attest", "siem.destination.manage",
			"siem.destination.read"}, apihost.Ports{Authn: door, Authz: door, Limits: door, StepUp: door})
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
		// runKinds executes every queued job of the given kinds, like the worker does.
		runKinds := func(kinds ...string) {
			t.Helper()
			var offered []jobs.KindLease
			for _, kl := range jreg.TenantLeases() {
				for _, k := range kinds {
					if kl.Kind == k {
						offered = append(offered, kl)
					}
				}
			}
			cl, err := jobs.Claim(ctx, db, offered, 20)
			if err != nil {
				t.Fatal(err)
			}
			for _, c := range cl {
				if res, err := jobs.NewRunner(db, jreg).Execute(ctx, c); err != nil || res != jobs.Completed {
					t.Fatalf("job %s: %v %v", c.Kind, res, err)
				}
			}
		}
		report := func() map[string]any {
			t.Helper()
			code, created := do("POST", "/api/v1/reports/runs", `{"definitionId":"usr-01"}`)
			if code != http.StatusAccepted {
				t.Fatalf("create usr-01: %d %v", code, created)
			}
			id, _ := created["id"].(string)
			runKinds(runs.Kind().Name)
			code, got := do("GET", "/api/v1/reports/runs/"+id, "")
			if code != http.StatusOK || got["state"] != "succeeded" {
				t.Fatalf("get run: %d %v", code, got)
			}
			return got
		}

		// The lab seed activates the connection through the real activation path; the hook queues the sync.
		if err := seed(ctx, conns, svc, tid); err != nil {
			t.Fatalf("seed: %v", err)
		}
		all, err := conns.List(ctx, tid, false)
		if err != nil || len(all) != 1 || all[0].State != connection.StateActive {
			t.Fatalf("connections after the seed: %v %v", all, err)
		}
		cid := inventory.ConnectionID(all[0].ID)
		connID, _ := authz.ParseObjectID(string(cid))
		ncID, _ := authz.ParseObjectID(strings.ToLower(string(all[0].DirectoryIdentity)))
		scope = authztest.ReadScope(authz.ScopeGrant{Include: []authz.ScopeTerm{{Kind: authz.TermNamingContext, Connection: connID, Root: ncID}}})
		queued, err := d.OwnerStrings(ctx, `SELECT count(*)::text FROM public.jobs WHERE kind = $1 AND state = 'available'`, dsync.JobFull)
		if err != nil || len(queued) != 1 || queued[0] != "1" {
			t.Fatalf("the activation must have queued exactly one sync.full: %v %v", queued, err)
		}
		if n := countRows(t, db, tid, ctx, `SELECT count(*) FROM public.directory_objects`); n != 0 {
			t.Fatalf("inventory holds %d objects before the first sync", n)
		}

		// Acceptance 2, before the sync: the run answers 'not synced yet', not an empty success.
		before := report()
		fr, _ := before["freshness"].(map[string]any)
		if fr["state"] != "not_synced_yet" || before["rowCount"] != float64(0) {
			t.Fatalf("before the sync: freshness %v rowCount %v", fr, before["rowCount"])
		}
		t.Logf("before the sync: freshness=%v rowCount=%v skipped=%v", fr["label"], before["rowCount"], before["skippedConnections"])

		// Acceptance 1: the first sync job completes.
		runKinds(dsync.JobFull)

		// Direct LDAP counts of the lab, by a separate session.
		pem := le.CAPath
		sess := openCountSession(t, ctx, le, pem)
		base := sess.base
		cls := func(c string) ldapfilter.Filter {
			an, err := ldapfilter.ParseAttrName("objectClass", ad.DefaultSchema())
			if err != nil {
				t.Fatal(err)
			}
			return ldapfilter.Eq(an, ldapfilter.String(c))
		}
		an, _ := ldapfilter.ParseAttrName("objectClass", ad.DefaultSchema())
		guidAttr, _ := ldapfilter.ParseAttrName("objectGUID", ad.DefaultSchema())
		itAttr, _ := ldapfilter.ParseAttrName("instanceType", ad.DefaultSchema())
		want := map[string]int{
			// The connector withholds an entry the bound account sees without its identity (objectGUID) or
			// classification (instanceType): Samba's partial system containers. Count what it can deliver.
			"all":      placeableCount(t, sess.s, base, an, guidAttr, itAttr),
			"user":     ldapCount(t, sess.s, base, ldapfilter.And(cls("user"), ldapfilter.Not(cls("computer")))),
			"group":    ldapCount(t, sess.s, base, cls("group")),
			"ou":       ldapCount(t, sess.s, base, cls("organizationalUnit")),
			"computer": ldapCount(t, sess.s, base, cls("computer")),
		}
		got := map[string]int{
			"all":      countRows(t, db, tid, ctx, `SELECT count(*) FROM public.directory_objects WHERE connection_id = $1::uuid`, string(cid)),
			"user":     countRows(t, db, tid, ctx, `SELECT count(*) FROM public.directory_objects WHERE connection_id = $1::uuid AND kind = 'user'`, string(cid)),
			"group":    countRows(t, db, tid, ctx, `SELECT count(*) FROM public.directory_objects WHERE connection_id = $1::uuid AND kind = 'group'`, string(cid)),
			"ou":       countRows(t, db, tid, ctx, `SELECT count(*) FROM public.directory_objects WHERE connection_id = $1::uuid AND kind = 'ou'`, string(cid)),
			"computer": countRows(t, db, tid, ctx, `SELECT count(*) FROM public.directory_objects WHERE connection_id = $1::uuid AND kind = 'computer'`, string(cid)),
		}
		t.Logf("lab LDAP counts %v; inventory counts %v", want, got)
		for k, w := range want {
			if got[k] != w {
				t.Errorf("%s: inventory %d, direct LDAP %d", k, got[k], w)
			}
		}
		if got["user"] == 0 || got["group"] == 0 || got["ou"] == 0 {
			t.Fatalf("the lab's users, groups and OUs are not all in inventory: %v", got)
		}
		res, err := inventory.NewReader(db, nil).Freshness(ctx, tid, inventory.FreshnessQuery{Connections: []inventory.ConnectionID{cid}, Now: time.Now()})
		if err != nil || res.Label.AsOf.IsZero() || len(res.Watermarks) != 1 {
			t.Fatalf("freshness after the first sync: %+v %v", res, err)
		}
		t.Logf("freshness: state=%s data_as_of=%s watermarks=%d", res.Label.State, res.Label.AsOf.Format(time.RFC3339), len(res.Watermarks))

		// Acceptance 2, after: the users report has the lab users as rows.
		after := report()
		fr, _ = after["freshness"].(map[string]any)
		if fr["state"] != "synced" || after["rowCount"] != float64(got["user"]) {
			t.Fatalf("after the sync: freshness %v rowCount %v, want synced and %d", fr, after["rowCount"], got["user"])
		}
		t.Logf("after the sync: freshness=%v rowCount=%v", fr["label"], after["rowCount"])

		if strings.Contains(fmt.Sprint(res), le.Values["LAB_SVC_PASSWORD"]) {
			t.Fatal("service password in the freshness result")
		}
	})
}

func countRows(t *testing.T, db *store.DB, tid tenant.ID, ctx context.Context, q string, args ...any) int {
	t.Helper()
	var n int
	// Inventory tables are row-level secured by tenant: the count runs as the tenant, like the engine's writes.
	if err := db.WithTenant(ctx, tid, func(ctx context.Context, tx store.Tx) error {
		return tx.QueryRow(ctx, q, args...).Scan(&n)
	}); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return n
}

type countSession struct {
	s    *ad.Session
	base dn.ObjectRef
}

// openCountSession opens its own LDAPS session to the lab, apart from the server's, for the direct counts.
func openCountSession(t *testing.T, ctx context.Context, le *testlab.Env, _ string) countSession {
	t.Helper()
	sess, err := ad.Open(ctx, ad.Config{Servers: []string{"localhost:" + le.Port}, RootCAs: le.Pool, PageSize: 500,
		Credential: ad.Credential{BindName: sambaLabBind, Password: secret.FromBytes([]byte(le.Values["LAB_SVC_PASSWORD"]))}})
	if err != nil {
		t.Fatalf("open count session: code %s", ad.CodeOf(err))
	}
	t.Cleanup(func() { _ = sess.Close() })
	rd, err := sess.RootDSE(ctx)
	if err != nil {
		t.Fatalf("rootDSE: code %s", ad.CodeOf(err))
	}
	base, err := dn.ParseObjectRef(rd.DefaultNamingContext)
	if err != nil {
		t.Fatal("default naming context is not a DN")
	}
	return countSession{s: sess, base: base}
}

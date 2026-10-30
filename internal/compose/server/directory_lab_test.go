//go:build lab

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/compose/config"
	"github.com/skenzeriq/activediq/internal/connector/labadmin"
	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/modules/directory"
	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/keys"
	"github.com/skenzeriq/activediq/internal/platform/secret"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/testlab"
)

// labPorts authenticates every request as one session principal of the install's tenant and allows it.
type labPorts struct{ tenant string }

func (p labPorts) Authenticate(*http.Request) (apihost.Principal, error) {
	return apihost.Principal{ID: "admin", Tenant: p.tenant, Kind: apihost.KindSession, SessionID: "s"}, nil
}
func (labPorts) CheckCSRF(*http.Request, apihost.Principal) error { return nil }
func (labPorts) Allow(context.Context, apihost.Principal, string, string) (bool, error) {
	return true, nil
}
func (labPorts) AllowPrincipal(context.Context, string, apihost.Principal) (apihost.Decision, error) {
	return apihost.Decision{Allowed: true}, nil
}
func (labPorts) AllowIP(context.Context, string, string) (apihost.Decision, error) {
	return apihost.Decision{Allowed: true}, nil
}
func (labPorts) Fresh(context.Context, apihost.Principal) (bool, error) { return true, nil }

// T-0669 acceptance 1 and 4 against the Samba lab, through the whole server path: a booted lab server's
// connection (seeded and verified by the lab bootstrap) -> GET /api/v1/directory/users through the real
// apihost pipeline -> client.UserSearch -> in-process connector -> LDAPS as svc-activediq (never a Domain
// Admin; the verified connection's rights check gates the search). The user is returned with only the
// allowed fields, filter metacharacters are refused, and the service password is in no log line or body.
// The Windows lab (VM 119, signing + channel binding on dc1) takes the same path with WIN_LAB_* (T-0671).
func TestLabDirectoryUsersSearchEndToEnd(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		le := testlab.Load(t)
		d := s.NewDatabase(t)
		d.Migrate(t)
		db, err := store.Open(context.Background(), store.Config{DSN: d.AppDSN()})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(db.Close)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		var logs syncBuf
		old := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
		t.Cleanup(func() { slog.SetDefault(old) })

		admin := labadmin.Dial(t, le.Port, le.Pool, "Administrator@lab.activediq.test", le.Values["LAB_ADMIN_PASSWORD"])
		const sam = "t0669-lab-user-01"
		admin.CreateUser(sam, "CN=Users,"+labDom)

		pw := le.Values["LAB_SVC_PASSWORD"]
		env := envOf(map[string]string{"LAB_LDAPS_PORT": le.Port, "LAB_SVC_PASSWORD": pw, "LAB_CA": le.CAPath})
		conns := connection.NewRegistry(db)
		var next client.ConnectorSource
		src, seed, closeFn, err := labBootstrap(ctx, env, next)
		if err != nil {
			t.Fatalf("labBootstrap: %v", err)
		}
		defer closeFn()
		kek, err := keys.NewLocalProvider("test-kek", secret.FromBytes(bytes.Repeat([]byte{7}, 32)))
		if err != nil {
			t.Fatal(err)
		}
		ch := audit.NewChainer(db)
		tid, err := bootstrapTenant(ctx, config.Config{InstanceID: "node-1"}, db, ch, kek, jobs.NewRegistry())
		if err != nil {
			t.Fatal(err)
		}
		vopts, err := verifyOptions(src)
		if err != nil {
			t.Fatal(err)
		}
		svc, err := connection.NewService(conns, client.New(vopts...), ch)
		if err != nil {
			t.Fatal(err)
		}
		if err := seed(ctx, conns, svc, tid); err != nil {
			t.Fatalf("seed: %v", err)
		}

		tag, err := buildDirectory(conns, src)
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
		lp := labPorts{tenant: tid.String()}
		srv, err := apihost.Build(doc, []apihost.TagHandlers{tag}, pol, apihost.Permissions{string(directory.ReadPermission), "connections.takeover.attest", "siem.destination.manage", "siem.destination.read"},
			apihost.Ports{Authn: lp, Authz: lp, Limits: lp, StepUp: lp})
		if err != nil {
			t.Fatal(err)
		}
		get := func(q string) *httptest.ResponseRecorder {
			r := httptest.NewRequest("GET", "/api/v1/directory/users?q="+q, nil)
			r.RemoteAddr = "203.0.113.7:4444"
			w := httptest.NewRecorder()
			srv.ServeHTTP(w, r)
			return w
		}

		w := get(sam)
		if w.Code != 200 {
			t.Fatalf("search %q = %d %s", sam, w.Code, w.Body)
		}
		var body struct {
			Items []map[string]any `json:"items"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if len(body.Items) != 1 || body.Items[0]["samAccountName"] != sam {
			t.Fatalf("items = %v, want exactly the %s user", body.Items, sam)
		}
		allowed := map[string]bool{"objectGuid": true, "displayName": true, "samAccountName": true, "userPrincipalName": true, "enabled": true}
		for k := range body.Items[0] {
			if !allowed[k] {
				t.Errorf("response carries field %q outside the allowed set", k)
			}
		}

		// Filter metacharacters are refused by the contract's pattern before any directory query exists
		// (the filter builder's own escaping is covered by the client and connector tests).
		if inj := get("%2A%29%28objectClass%3D%2A"); inj.Code != 400 || strings.Contains(inj.Body.String(), `"objectGuid"`) {
			t.Errorf("injection text answered %d %s, want 400", inj.Code, inj.Body)
		}
		// Text that is valid for the contract but matches nobody answers an empty list, not an error.
		if none := get("t0669-no-such-user-zz"); none.Code != 200 || strings.Contains(none.Body.String(), `"objectGuid"`) {
			t.Errorf("no-match search answered %d %s, want 200 and no user", none.Code, none.Body)
		}

		if pw == "" || strings.Contains(logs.String(), pw) || strings.Contains(w.Body.String(), pw) {
			t.Errorf("service password empty or present in logs or the response")
		}
	})
}

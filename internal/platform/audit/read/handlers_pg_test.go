package read_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/apihost/apitest"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/audit/chain"
	"github.com/skenzeriq/activediq/internal/platform/audit/read"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/keys"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

func TestMain(m *testing.M) { os.Exit(storetest.Main(m)) }

type fixedKeys struct{}

func (fixedKeys) DEK(context.Context, store.Tx, tenant.ID, uint32) (keys.DEK, error) {
	return keys.DEKFromBytes(1, bytes.Repeat([]byte{9}, keys.DEKSize))
}

type noAnchor struct{}

func (noAnchor) Anchor(context.Context, chain.Checkpoint) error { return nil }

type ports struct{ tenant string }

func (p ports) Authenticate(*http.Request) (apihost.Principal, error) {
	return apihost.Principal{ID: "auditor", Tenant: p.tenant, Kind: apihost.KindToken}, nil
}
func (ports) CheckCSRF(*http.Request, apihost.Principal) error { return nil }
func (ports) Allow(context.Context, apihost.Principal, string, string) (bool, error) {
	return true, nil
}
func (ports) AllowIP(context.Context, string, string) (apihost.Decision, error) {
	return apihost.Decision{Allowed: true}, nil
}
func (ports) AllowPrincipal(context.Context, string, apihost.Principal) (apihost.Decision, error) {
	return apihost.Decision{Allowed: true}, nil
}
func (ports) Fresh(context.Context, apihost.Principal) (bool, error) { return true, nil }

const (
	guidA = "aaaaaaaa-0000-4000-8000-00000000000a"
	guidB = "bbbbbbbb-0000-4000-8000-00000000000b"
)

func TestListAuditEvents(t *testing.T) {
	storetest.EachVersion(t, listAuditEvents)
}

func listAuditEvents(t *testing.T, s *storetest.Server) {
	d := s.NewDatabase(t)
	d.Migrate(t)
	ctx := context.Background()
	db, err := store.Open(ctx, store.Config{DSN: d.AppDSN()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	ch := audit.NewChainer(db)
	cp := audit.NewCheckpointer(ch, fixedKeys{}, noAnchor{})
	tid := tenanttest.Seed(t, d.ExecOwner, "A")
	other := tenanttest.Seed(t, d.ExecOwner, "B")
	for _, id := range []tenant.ID{tid, other} {
		if err := db.WithTenant(ctx, id, func(ctx context.Context, tx store.Tx) error { return cp.InitTenant(ctx, tx, id) }); err != nil {
			t.Fatal(err)
		}
	}
	base := time.Now().Add(-time.Hour).Truncate(time.Second) // the events' own At; the chain stamps its own commit time
	chainStart := time.Now().Add(-time.Second)
	tech := authority.Chain{Requester: authority.Principal{ID: "tech-alice", Kind: authority.Human},
		Via: []authority.Principal{{ID: "tok-1", Kind: authority.APIToken}}}
	step := func(id string, at time.Time, guid, dc, cred string, t2 tenant.ID) {
		err := db.WithTenant(ctx, t2, func(ctx context.Context, tx store.Tx) error {
			return ch.Append(ctx, tx, audit.Event{ID: id, Kind: "operation.step.applied", At: at, Actor: tech, Component: "operation", Outcome: audit.Success,
				Target: authority.TargetRef{Connection: "c1", GUID: guid, Class: "user"}, PlanHash: "ph",
				Details: []audit.Detail{{Key: "credential_id", Value: cred}, {Key: "dc", Value: dc}}})
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	step("e1", base, guidA, "dc1.lab.test", "cred-1", tid)
	time.Sleep(50 * time.Millisecond)
	afterE1 := time.Now()
	time.Sleep(50 * time.Millisecond)
	step("e2", base.Add(time.Minute), guidA, "dc2.lab.test", "cred-1", tid)
	step("e3", base.Add(2*time.Minute), guidB, "dc1.lab.test", "cred-2", tid)
	step("e4", base.Add(3*time.Minute), guidA, "dc1.lab.test", "cred-1", tid)
	step("x1", base, guidA, "dc1.lab.test", "cred-1", other) // another tenant, same values

	h := read.Handlers{DB: db, Sink: ch}
	get := func(q url.Values) (int, map[string]any) {
		doc, _ := apihost.LoadDocument()
		pol, _ := apihost.LoadPolicy()
		srv, err := apihost.Build(doc, []apihost.TagHandlers{h.Bind()}, pol, apitest.Catalogue(doc),
			apihost.Ports{Authn: ports{tid.String()}, Authz: ports{}, Limits: ports{}, StepUp: ports{}})
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("GET", "/api/v1/audit/events?"+q.Encode(), nil)
		r.RemoteAddr = "203.0.113.7:4444"
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, r)
		var m map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &m)
		return w.Code, m
	}
	items := func(m map[string]any) []map[string]any {
		var out []map[string]any
		for _, i := range m["items"].([]any) {
			out = append(out, i.(map[string]any))
		}
		return out
	}

	t.Run("AC1 dc + credential + target + time returns the event with Requester and Via", func(t *testing.T) {
		code, m := get(url.Values{"dc": {"DC1.lab.test"}, "credentialId": {"cred-1"}, "target": {guidA},
			"from": {chainStart.Format(time.RFC3339Nano)}, "to": {afterE1.Format(time.RFC3339Nano)}})
		if code != 200 {
			t.Fatalf("%d %v", code, m)
		}
		it := items(m)
		if len(it) != 1 || it[0]["eventId"] != "e1" || it[0]["dc"] != "dc1.lab.test" || it[0]["credentialId"] != "cred-1" || it[0]["target"] != guidA {
			t.Fatalf("got %v", it)
		}
		req := it[0]["requester"].(map[string]any)
		via := it[0]["via"].([]any)[0].(map[string]any)
		if req["id"] != "tech-alice" || via["id"] != "tok-1" {
			t.Fatalf("requester/via: %v %v", req, via)
		}
		if m["nextCursor"] != nil {
			t.Fatalf("cursor on the last page: %v", m["nextCursor"])
		}
	})
	t.Run("filters narrow, other tenants stay invisible", func(t *testing.T) {
		_, m := get(url.Values{"credentialId": {"cred-1"}, "target": {guidA}})
		if n := len(items(m)); n != 3 {
			t.Fatalf("want 3 got %d", n)
		}
		_, m = get(url.Values{"dc": {"nope"}})
		if n := len(items(m)); n != 0 {
			t.Fatalf("want 0 got %d", n)
		}
	})
	t.Run("cursor pages, and is bound to its filters", func(t *testing.T) {
		q := url.Values{"credentialId": {"cred-1"}, "limit": {"2"}}
		_, m := get(q)
		if len(items(m)) != 2 || m["nextCursor"] == nil {
			t.Fatalf("page 1: %v", m)
		}
		q.Set("cursor", m["nextCursor"].(string))
		_, m2 := get(q)
		if it := items(m2); len(it) != 1 || it[0]["eventId"] != "e4" || m2["nextCursor"] != nil {
			t.Fatalf("page 2: %v", m2)
		}
		q.Set("dc", "dc2.lab.test")
		if code, _ := get(q); code != 400 {
			t.Fatalf("cursor with other filters: %d", code)
		}
	})
	t.Run("the read is audited", func(t *testing.T) {
		var n int
		err := db.WithTenant(ctx, tid, func(ctx context.Context, tx store.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM audit_event WHERE kind = 'audit.queried'`).Scan(&n)
		})
		if err != nil || n < 3 {
			t.Fatalf("audit.queried events: %d %v", n, err)
		}
	})
	t.Run("bad window is 400", func(t *testing.T) {
		if code, _ := get(url.Values{"from": {base.Format(time.RFC3339)}, "to": {base.Add(-time.Hour).Format(time.RFC3339)}}); code != 400 {
			t.Fatalf("%d", code)
		}
	})
}

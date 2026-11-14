package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/modules/directory"
	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

type fakeTx struct {
	tid  tenant.ID
	runs int
	err  error
}

func (f *fakeTx) WithTenant(ctx context.Context, id tenant.ID, fn func(context.Context, store.Tx) error) error {
	f.tid = id
	f.runs++
	if f.err != nil {
		return f.err
	}
	return fn(ctx, nil)
}

type authzRecSink struct{ evs []audit.Event }

func (r *authzRecSink) Append(_ context.Context, _ store.Tx, ev audit.Event) error {
	if err := ev.Validate(); err != nil {
		return err
	}
	r.evs = append(r.evs, ev)
	return nil
}

type fixedAuthz struct {
	ok  bool
	err error
}

func (f fixedAuthz) Allow(context.Context, apihost.Principal, string, string) (bool, error) {
	return f.ok, f.err
}

const auditTenant = "00000000-0000-4000-8000-000000000001"

func newAudited(next apihost.Authorizer, tx *fakeTx, sink *authzRecSink) auditedAuthz {
	return auditedAuthz{next: next, db: tx, sink: sink, now: func() time.Time { return time.Unix(1700000000, 0).UTC() },
		log: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

// Acceptance 2: a caller without the permission is refused and the refusal is in the tenant's audit trail
// with who asked, which permission, and the outcome.
func TestPermissionRefusalIsAudited(t *testing.T) {
	tx, sink := &fakeTx{}, &authzRecSink{}
	a := newAudited(fixedAuthz{ok: false}, tx, sink)
	p := apihost.Principal{ID: "acct-1", Tenant: auditTenant, Kind: apihost.KindSession, SessionID: "s"}
	ok, err := a.Allow(context.Background(), p, "directory.read", "tenant")
	if ok || err != nil {
		t.Fatalf("a refusal must stay a refusal: %v %v", ok, err)
	}
	if len(sink.evs) != 1 || tx.tid.String() != auditTenant {
		t.Fatalf("want one event in the caller's tenant, got %d in %s", len(sink.evs), tx.tid)
	}
	ev := sink.evs[0]
	if ev.Kind != AuditPermissionDenied || ev.Outcome != audit.Denied || ev.Reason != "permission_denied" ||
		string(ev.Actor.Requester.ID) != "acct-1" || ev.Target.GUID != auditTenant {
		t.Fatalf("event: %+v", ev)
	}
	if len(ev.Details) != 2 || ev.Details[0].Key != "permission" || ev.Details[0].Value != "directory.read" || ev.Details[1].Key != "scope" {
		t.Fatalf("details: %+v", ev.Details)
	}
}

func TestGrantAndInfrastructureFaultAreNotRecordedAsRefusals(t *testing.T) {
	p := apihost.Principal{ID: "acct-1", Tenant: auditTenant, Kind: apihost.KindSession}
	for name, next := range map[string]fixedAuthz{"allowed": {ok: true}, "fault": {err: errors.New("db down")}} {
		tx, sink := &fakeTx{}, &authzRecSink{}
		_, _ = newAudited(next, tx, sink).Allow(context.Background(), p, "directory.read", "tenant")
		if tx.runs != 0 || len(sink.evs) != 0 {
			t.Errorf("%s: recorded %d events", name, len(sink.evs))
		}
	}
}

// An audit fault never turns a refusal into an approval.
func TestAuditFaultStillRefuses(t *testing.T) {
	tx, sink := &fakeTx{err: errors.New("audit store down")}, &authzRecSink{}
	p := apihost.Principal{ID: "acct-1", Tenant: auditTenant, Kind: apihost.KindSession}
	ok, err := newAudited(fixedAuthz{}, tx, sink).Allow(context.Background(), p, "directory.read", "tenant")
	if ok || err != nil {
		t.Fatalf("got %v %v", ok, err)
	}
}

func TestPrincipalWithoutATenantIsRefusedButNotChained(t *testing.T) {
	tx, sink := &fakeTx{}, &authzRecSink{}
	ok, _ := newAudited(fixedAuthz{}, tx, sink).Allow(context.Background(), apihost.Principal{ID: "x"}, "directory.read", "tenant")
	if ok || tx.runs != 0 {
		t.Fatalf("ok=%v runs=%d", ok, tx.runs)
	}
}

// End to end through the API host: GET /directory/users by a caller without directory.read answers 403 and
// leaves one audit event; the handler never runs.
func TestSearchWithoutDirectoryReadIs403AndAudited(t *testing.T) {
	doc, err := apihost.LoadDocument()
	if err != nil {
		t.Fatal(err)
	}
	pol, err := apihost.LoadPolicy()
	if err != nil {
		t.Fatal(err)
	}
	tx, sink := &fakeTx{}, &authzRecSink{}
	pr := apihost.Principal{ID: "acct-1", Tenant: auditTenant, Kind: apihost.KindSession, SessionID: "s"}
	base := failClosedPorts(openLimiter{})
	ports := apihost.Ports{Authn: sessionAuthn{pr}, Authz: newAudited(fixedAuthz{}, tx, sink), Limits: base.Limits, StepUp: base.StepUp}
	boom := directory.Handlers{Connections: panicConns{}, Search: nil}
	srv, err := apihost.Build(doc, []apihost.TagHandlers{boom.Bind()}, pol, bootedCatalogue(), ports)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/api/v1/directory/users?q=ann", nil)
	r.RemoteAddr = "203.0.113.7:4444"
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if len(sink.evs) != 1 || sink.evs[0].Outcome != audit.Denied || sink.evs[0].Details[0].Value != "directory.read" {
		t.Fatalf("events: %+v", sink.evs)
	}
}

type sessionAuthn struct{ p apihost.Principal }

func (s sessionAuthn) Authenticate(*http.Request) (apihost.Principal, error) { return s.p, nil }
func (sessionAuthn) CheckCSRF(*http.Request, apihost.Principal) error        { return nil }

type openLimiter struct{}

func (openLimiter) AllowIP(context.Context, string, string) (apihost.Decision, error) {
	return apihost.Decision{Allowed: true}, nil
}
func (openLimiter) AllowPrincipal(context.Context, string, apihost.Principal) (apihost.Decision, error) {
	return apihost.Decision{Allowed: true}, nil
}

type panicConns struct{}

func (panicConns) List(context.Context, tenant.ID, bool) ([]connection.Connection, error) {
	panic("handler ran for a caller without directory.read")
}
func (panicConns) Health(context.Context, tenant.ID, connection.ID, bool, time.Time) (connection.Health, error) {
	panic("handler ran for a caller without directory.read")
}

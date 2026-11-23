package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/apihost/apitest"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	auditread "github.com/skenzeriq/activediq/internal/platform/audit/read"
	"github.com/skenzeriq/activediq/internal/platform/rbac"
)

type readPorts struct{}

func (readPorts) Authenticate(*http.Request) (apihost.Principal, error) {
	return apihost.Principal{ID: "helpdesk-1", Tenant: auditTenant, Kind: apihost.KindToken}, nil
}
func (readPorts) CheckCSRF(*http.Request, apihost.Principal) error { return nil }
func (readPorts) AllowIP(context.Context, string, string) (apihost.Decision, error) {
	return apihost.Decision{Allowed: true}, nil
}
func (readPorts) AllowPrincipal(context.Context, string, apihost.Principal) (apihost.Decision, error) {
	return apihost.Decision{Allowed: true}, nil
}
func (readPorts) Fresh(context.Context, apihost.Principal) (bool, error) { return true, nil }

// T-2300 acceptance 2: a caller without audit.read gets 403, the search never runs, and the refusal is in
// the chain naming the permission.
func TestListAuditEventsRefusalIsAuditedAndSearchDoesNotRun(t *testing.T) {
	doc, err := apihost.LoadDocument()
	if err != nil {
		t.Fatal(err)
	}
	pol, err := apihost.LoadPolicy()
	if err != nil {
		t.Fatal(err)
	}
	denials, sink := &fakeTx{}, &authzRecSink{}
	handlerDB := &fakeTx{err: errors.New("the search must not run for a refused caller")}
	h := auditread.Handlers{DB: handlerDB, Sink: sink}
	srv, err := apihost.Build(doc, []apihost.TagHandlers{h.Bind()}, pol, apitest.Catalogue(doc),
		apihost.Ports{Authn: readPorts{}, Authz: newAudited(fixedAuthz{ok: false}, denials, sink), Limits: readPorts{}, StepUp: readPorts{}})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/api/v1/audit/events?dc=dc1.lab.test", nil)
	r.RemoteAddr = "203.0.113.7:4444"
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if handlerDB.runs != 0 {
		t.Fatal("the handler ran for a refused caller")
	}
	if len(sink.evs) != 1 || sink.evs[0].Kind != AuditPermissionDenied || sink.evs[0].Outcome != audit.Denied ||
		string(sink.evs[0].Actor.Requester.ID) != "helpdesk-1" || sink.evs[0].Details[0].Value != auditread.Permission {
		t.Fatalf("refusal not recorded as expected: %+v", sink.evs)
	}
}

// audit.read is in the permission catalogue and a platform administrator holds it; a help-desk operator does not.
func TestAuditReadPermissionIsCatalogued(t *testing.T) {
	if !slices.Contains(kernelPermissions(), auditread.Permission) {
		t.Fatal("audit.read is not in the kernel permission catalogue")
	}
	for _, role := range rbac.BuiltInRoles() {
		has := false
		for _, p := range role.Permissions {
			has = has || string(p) == auditread.Permission
		}
		if want := role.Name == "platform-administrator"; has != want {
			t.Errorf("role %s holds audit.read = %v, want %v", role.Name, has, want)
		}
	}
}

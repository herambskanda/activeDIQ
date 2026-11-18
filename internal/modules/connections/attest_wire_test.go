package connections

import (
	"context"
	"reflect"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory"
	"github.com/skenzeriq/activediq/internal/platform"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/module/moduletest"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

type nopSink struct{}

func (nopSink) Append(context.Context, store.Tx, audit.Event) error { return nil }

type recAuthz struct {
	operation.Authorizer
	facts authority.Facts
}

func (r *recAuthz) Authorize(_ context.Context, _ authority.Chain, _ authz.Permission, _ authority.TargetRef, f authority.Facts) error {
	r.facts = f
	return nil
}

// Unconfigured, the module registers no API tag (the attestation routes stay unmounted) but still
// registers the permission; configured, it registers exactly its own tag.
func TestAttestationRoutesFollowConfig(t *testing.T) {
	c, err := moduletest.Register(New(platform.Deps{}, directory.Services{}))
	if err != nil {
		t.Fatal(err)
	}
	if n := len(c.API()); n != 0 {
		t.Fatalf("unconfigured: %d tags", n)
	}
	var has bool
	for _, p := range c.Permissions() {
		has = has || p == TakeoverAttestPermission
	}
	if !has {
		t.Fatal("permission not registered")
	}
	deps := platform.Deps{Audit: nopSink{}, Attestation: platform.Attestation{ClientID: "app", Origin: "https://diq.example.com"}}
	c, err = moduletest.Register(New(deps, directory.Services{}))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.API(); len(got) != 1 || got[0].Tag() != string(ModuleID) {
		t.Fatalf("configured: %v", got)
	}
}

// A configured client ID without a public origin cannot build a redirect URI: refuse, never guess one.
func TestAttestationNeedsOrigin(t *testing.T) {
	_, err := moduletest.Register(New(platform.Deps{Audit: nopSink{}, Attestation: platform.Attestation{ClientID: "app"}}, directory.Services{}))
	if err == nil {
		t.Fatal("registered without an origin")
	}
}

// The attestation's entra_tenant target is read with the facts a connection root has; any other target
// gets none, so RBAC refuses it.
func Test_connectionAuthorizer_facts(t *testing.T) {
	conn := "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	for name, c := range map[string]struct {
		t    authority.TargetRef
		want authority.Facts
	}{
		"entra_tenant connection root": {authority.TargetRef{Connection: conn, GUID: conn, Class: "entra_tenant"}, authority.Facts{Exists: true, AncestorsComplete: true}},
		"other class":                  {authority.TargetRef{Connection: conn, GUID: conn, Class: "ou"}, authority.Facts{}},
		"object under the connection":  {authority.TargetRef{Connection: conn, GUID: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", Class: "entra_tenant"}, authority.Facts{}},
		"no connection":                {authority.TargetRef{GUID: conn, Class: "entra_tenant"}, authority.Facts{}},
	} {
		ra := &recAuthz{}
		_ = connectionAuthorizer{ra}.Authorize(context.Background(), authority.Chain{}, "p", c.t)
		if !reflect.DeepEqual(ra.facts, c.want) {
			t.Errorf("%s: facts %+v want %+v", name, ra.facts, c.want)
		}
	}
}

// A nil step-up refuses, so a half-built stack cannot grant one.
func TestSessionStepUpNilRefuses(t *testing.T) {
	if ok, err := (sessionStepUp{}).Fresh(context.Background(), tenant.New(), "s"); ok || err != nil {
		t.Fatalf("%v %v", ok, err)
	}
}

package module_test

import (
	"errors"
	"testing"

	"context"
	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/capability"
	"github.com/skenzeriq/activediq/internal/platform/module"
	"github.com/skenzeriq/activediq/internal/platform/module/moduletest"
)

func contribute(tags []apihost.TagHandlers, perms ...authz.Permission) func(*module.Registrar) error {
	return func(r *module.Registrar) error {
		for _, p := range perms {
			if err := r.Permission(p); err != nil {
				return err
			}
		}
		for _, t := range tags {
			if err := r.API(t); err != nil {
				return err
			}
		}
		return nil
	}
}

func TestAPIAndPermissionAreContributed(t *testing.T) {
	m := &fake{id: "fake", register: contribute([]apihost.TagHandlers{moduletest.Tag("fake", "fake.thing.read", "authenticated")}, "fake.thing.read")}
	c, err := moduletest.Register(m)
	if err != nil {
		t.Fatal(err)
	}
	if got := c.API(); len(got) != 1 || got[0].Tag() != "fake" {
		t.Fatalf("API = %v", got)
	}
	if got := c.Permissions(); len(got) != 1 || got[0] != "fake.thing.read" {
		t.Fatalf("Permissions = %v", got)
	}
}

func TestBootRejectsBadAPIAndPermission(t *testing.T) {
	cases := map[string]struct {
		reg  func(*module.Registrar) error
		want error
	}{
		"tag is not the module ID":      {contribute([]apihost.TagHandlers{moduletest.Tag("other")}), module.ErrNamespace},
		"permission outside module":     {contribute(nil, "other.thing.read"), module.ErrNamespace},
		"permission bare namespace":     {contribute(nil, "fake."), module.ErrNamespace},
		"duplicate permission":          {contribute(nil, "fake.a", "fake.a"), module.ErrDuplicate},
		"duplicate tag":                 {contribute([]apihost.TagHandlers{moduletest.Tag("fake"), moduletest.Tag("fake")}), module.ErrDuplicate},
		"x-permission not in catalogue": {contribute([]apihost.TagHandlers{moduletest.Tag("fake", "fake.missing")}, "fake.a"), module.ErrUnknownPermission},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := moduletest.Register(&fake{id: "fake", register: tc.reg})
			if !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
		})
	}
}

func TestKernelPermissionSatisfiesXPermission(t *testing.T) {
	m := &fake{id: "fake", register: contribute([]apihost.TagHandlers{moduletest.Tag("fake", "operation.approve")})}
	if _, err := moduletest.Register(m); !errors.Is(err, module.ErrUnknownPermission) {
		t.Fatalf("without kernel permissions: %v", err)
	}
	_, err := moduletest.Register(m, module.WithKernelPermissions([]string{"operation.approve"}))
	if err != nil {
		t.Fatal(err)
	}
}

func TestBootRejectsSameTagFromTwoModules(t *testing.T) {
	a := &fake{id: "fake", register: contribute([]apihost.TagHandlers{moduletest.Tag("fake")})}
	b := &fake{id: "fake2", register: contribute([]apihost.TagHandlers{moduletest.Tag("fake")})}
	_, err := module.Boot(context.Background(),
		[]module.Entry{{ID: "fake", Module: a}, {ID: "fake2", Module: b}}, capability.NewSet())
	if !errors.Is(err, module.ErrNamespace) {
		t.Fatalf("got %v", err)
	}
}

func TestZeroRegistrarRefusesAPIAndPermission(t *testing.T) {
	var r module.Registrar
	if err := r.API(moduletest.Tag("fake")); !errors.Is(err, module.ErrClosed) {
		t.Fatalf("API: %v", err)
	}
	if err := r.Permission("fake.x"); !errors.Is(err, module.ErrClosed) {
		t.Fatalf("Permission: %v", err)
	}
}

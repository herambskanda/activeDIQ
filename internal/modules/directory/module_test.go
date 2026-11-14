package directory

import (
	"context"
	"errors"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory"
	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/platform"
	"github.com/skenzeriq/activediq/internal/platform/capability"
	"github.com/skenzeriq/activediq/internal/platform/module"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

func boot(t *testing.T, deps platform.Deps, dir directory.Services) (*module.Contributions, error) {
	t.Helper()
	return module.Boot(context.Background(), []module.Entry{{ID: ModuleID, Module: New(deps, dir)}}, capability.NewSet(),
		module.WithKernelPermissions(nil))
}

// An install with no connector source registers the permission and no routes: the module hands the host
// nothing it cannot answer.
func TestUnconfiguredModuleRegistersOnlyItsPermission(t *testing.T) {
	c, err := boot(t, platform.Deps{}, directory.Services{})
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Permissions(); len(got) != 1 || got[0] != ReadPermission {
		t.Errorf("permissions = %v, want [%s]", got, ReadPermission)
	}
	if got := c.API(); len(got) != 0 {
		t.Errorf("api tags = %d, want none", len(got))
	}
}

// With a connector source configured but no store or read-scope producer the boot fails: a module never
// searches unscoped.
func TestConfiguredModuleWithoutProducerFailsBoot(t *testing.T) {
	dir := directory.Services{Connection: &connection.Registry{}, Source: nopSource{}, Reads: nil}
	if _, err := boot(t, platform.Deps{}, dir); err == nil {
		t.Fatal("boot succeeded without a store and a read-scope producer")
	}
	if _, err := buildSearch(nil, nil); err == nil {
		t.Error("buildSearch accepted a nil producer")
	}
}

type nopSource struct{}

func (nopSource) Connector(context.Context, string) (connectorv1.ConnectorClient, error) {
	return nil, errors.New("no connector")
}

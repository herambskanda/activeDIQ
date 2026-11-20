package reports

import (
	"context"
	"errors"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory"
	"github.com/skenzeriq/activediq/internal/platform"
	"github.com/skenzeriq/activediq/internal/platform/capability"
	"github.com/skenzeriq/activediq/internal/platform/module"
	"github.com/skenzeriq/activediq/internal/platform/store"
)

// A module with no store registers its permissions and no route or job: it hands the host nothing it
// cannot serve (ADR-0013).
func TestUnconfiguredModuleRegistersOnlyPermissions(t *testing.T) {
	c, err := module.Boot(context.Background(), []module.Entry{{ID: ModuleID, Module: New(platform.Deps{}, directory.Services{})}}, capability.NewSet())
	if err != nil {
		t.Fatal(err)
	}
	if len(c.API()) != 0 || len(c.Jobs()) != 0 || len(c.Permissions()) != 7 {
		t.Fatalf("api %d jobs %d permissions %d", len(c.API()), len(c.Jobs()), len(c.Permissions()))
	}
}

// A store without the read-scope producer stops start-up: no installation runs reports unscoped.
func TestStoreWithoutReadScopesStopsBoot(t *testing.T) {
	_, err := module.Boot(context.Background(), []module.Entry{{ID: ModuleID, Module: New(platform.Deps{DB: &store.DB{}}, directory.Services{})}}, capability.NewSet())
	if !errors.Is(err, ErrNoReadScopes) {
		t.Fatalf("Boot = %v; want ErrNoReadScopes", err)
	}
}

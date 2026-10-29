package agentfleet_test

import (
	"testing"

	"github.com/skenzeriq/activediq/internal/directory"
	"github.com/skenzeriq/activediq/internal/platform"

	"github.com/skenzeriq/activediq/internal/modules/agentfleet"
	"github.com/skenzeriq/activediq/internal/platform/module/moduletest"
)

func TestModuleBoots(t *testing.T) {
	m := agentfleet.New(platform.Deps{}, directory.Services{})
	if m.ID() != "agentfleet" {
		t.Fatalf("id %q", m.ID())
	}
	if _, err := moduletest.Register(m); err != nil {
		t.Fatal(err)
	}
}

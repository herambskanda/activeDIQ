package agent_test

import (
	"context"
	"errors"
	"testing"

	"github.com/skenzeriq/activediq/internal/compose/agent"
	"github.com/skenzeriq/activediq/internal/compose/config"
)

func TestRunReportsNotBuilt(t *testing.T) {
	err := agent.Run(context.Background(), config.Config{})
	if !errors.Is(err, agent.ErrNotBuilt) {
		t.Fatalf("Run = %v, want ErrNotBuilt", err)
	}
}

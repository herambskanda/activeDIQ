package edge_test

import (
	"context"
	"errors"
	"testing"

	"github.com/skenzeriq/activediq/internal/compose/config"
	"github.com/skenzeriq/activediq/internal/compose/edge"
)

func TestRunReportsNotBuilt(t *testing.T) {
	err := edge.Run(context.Background(), config.Config{})
	if !errors.Is(err, edge.ErrNotBuilt) {
		t.Fatalf("Run = %v, want ErrNotBuilt", err)
	}
}

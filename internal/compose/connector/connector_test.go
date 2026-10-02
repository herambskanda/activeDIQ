package connector_test

import (
	"context"
	"errors"
	"testing"

	"github.com/skenzeriq/activediq/internal/compose/config"
	"github.com/skenzeriq/activediq/internal/compose/connector"
)

func TestRunReportsNotBuilt(t *testing.T) {
	err := connector.Run(context.Background(), config.Config{})
	if !errors.Is(err, connector.ErrNotBuilt) {
		t.Fatalf("Run = %v, want ErrNotBuilt", err)
	}
}

package server_test

import (
	"context"
	"errors"
	"testing"

	"github.com/skenzeriq/activediq/internal/compose/config"
	"github.com/skenzeriq/activediq/internal/compose/server"
)

func TestRunReportsNotBuilt(t *testing.T) {
	err := server.Run(context.Background(), config.Config{})
	if !errors.Is(err, server.ErrNotBuilt) {
		t.Fatalf("Run = %v, want ErrNotBuilt", err)
	}
}

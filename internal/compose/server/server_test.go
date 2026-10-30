package server_test

import (
	"context"
	"errors"
	"testing"

	"github.com/skenzeriq/activediq/internal/compose/config"
	"github.com/skenzeriq/activediq/internal/compose/server"
)

func TestRunRefusesWithoutADatabase(t *testing.T) {
	err := server.Run(context.Background(), config.Config{}, func(string) string { return "" })
	if !errors.Is(err, server.ErrNoDatabase) {
		t.Fatalf("Run = %v, want ErrNoDatabase", err)
	}
}

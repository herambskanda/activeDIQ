package config_test

import (
	"log/slog"
	"testing"

	"github.com/skenzeriq/activediq/internal/compose/config"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestLoad(t *testing.T) {
	c, err := config.Load(env(nil))
	if err != nil || c.LogLevel != slog.LevelInfo {
		t.Fatalf("default: got %v, %v; want info, nil", c.LogLevel, err)
	}
	c, err = config.Load(env(map[string]string{config.EnvLogLevel: "debug"}))
	if err != nil || c.LogLevel != slog.LevelDebug {
		t.Fatalf("debug: got %v, %v", c.LogLevel, err)
	}
	if _, err = config.Load(env(map[string]string{config.EnvLogLevel: "loud"})); err == nil {
		t.Fatal("an invalid log level must be an error")
	}
}

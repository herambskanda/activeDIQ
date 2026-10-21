package config_test

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
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

func TestLoadShutdownSettings(t *testing.T) {
	c, err := config.Load(env(map[string]string{config.EnvDatabaseDSN: "postgres://x", config.EnvInstanceID: "host-1"}))
	if err != nil || c.DatabaseDSN != "postgres://x" || c.InstanceID != "host-1" ||
		c.ShutdownGrace != config.DefaultShutdownGrace || c.StopTimeout != config.DefaultStopTimeout {
		t.Fatalf("defaults: %+v, %v", c, err)
	}
	c, err = config.Load(env(map[string]string{config.EnvShutdownGrace: "10s", config.EnvStopTimeout: "30s"}))
	if err != nil || c.ShutdownGrace.Seconds() != 10 {
		t.Fatalf("explicit: %+v, %v", c, err)
	}
	for name, m := range map[string]map[string]string{
		"grace twice reaches the stop timeout": {config.EnvShutdownGrace: "45s"},
		"default grace over a short timeout":   {config.EnvStopTimeout: "60s"},
		"unparsable grace":                     {config.EnvShutdownGrace: "soon"},
		"zero grace":                           {config.EnvShutdownGrace: "0s"},
		"negative stop timeout":                {config.EnvStopTimeout: "-5s"},
	} {
		if _, err := config.Load(env(m)); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

func TestConfigNeverPrintsDSN(t *testing.T) {
	const secret = "s3ntinel-pw"
	c, err := config.Load(env(map[string]string{config.EnvDatabaseDSN: "postgres://u:" + secret + "@h/db"}))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("config", "cfg", c)
	for name, out := range map[string]string{
		"%v": fmt.Sprintf("%v", c), "%+v": fmt.Sprintf("%+v", c), "%#v": fmt.Sprintf("%#v", c),
		"%v ptr": fmt.Sprintf("%v", &c), "slog": buf.String(),
	} {
		if strings.Contains(out, secret) {
			t.Errorf("%s leaks the DSN: %s", name, out)
		}
	}
	if !strings.Contains(buf.String(), "[redacted]") {
		t.Errorf("slog output lacks redaction marker: %s", buf.String())
	}
}

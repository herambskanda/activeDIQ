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

func TestLoadAPISettings(t *testing.T) {
	c, err := config.Load(env(nil))
	if err != nil || c.APIAddr != config.DefaultAPIAddr || c.APIBodyBudget != 64<<20 {
		t.Fatalf("defaults: %+v, %v", c, err)
	}
	c, err = config.Load(env(map[string]string{config.EnvAPIAddr: "127.0.0.1:9", config.EnvAPIBodyBudget: "1048576"}))
	if err != nil || c.APIAddr != "127.0.0.1:9" || c.APIBodyBudget != 1<<20 {
		t.Fatalf("explicit: %+v, %v", c, err)
	}
	for _, v := range []string{"0", "-5", "lots", "1.5"} {
		if _, err := config.Load(env(map[string]string{config.EnvAPIBodyBudget: v})); err == nil {
			t.Errorf("body budget %q must fail startup", v)
		}
	}
}

func TestAPIAddrNonLoopbackNeedsTLS(t *testing.T) {
	for _, a := range []string{"127.0.0.1:0", "127.0.0.2:8080", "[::1]:8080", "localhost:8080"} {
		if _, err := config.Load(env(map[string]string{config.EnvAPIAddr: a})); err != nil {
			t.Errorf("%q must be accepted: %v", a, err)
		}
	}
	for _, a := range []string{"0.0.0.0:9", ":8080", "[::]:8080", "10.0.0.5:8080", "example.com:8080", "8080"} {
		_, err := config.Load(env(map[string]string{config.EnvAPIAddr: a}))
		if err == nil || !strings.Contains(err.Error(), config.EnvAPIAddr) || !strings.Contains(err.Error(), config.EnvAPITLSDir) {
			t.Errorf("%q without TLS must be refused naming both variables: %v", a, err)
		}
		c, err := config.Load(env(map[string]string{config.EnvAPIAddr: a, config.EnvAPITLSDir: "/var/lib/activediq/tls"}))
		if a != "8080" && err != nil {
			t.Errorf("%q with TLS configured must be accepted: %v", a, err)
		}
		if err == nil && c.APITLSDir == "" {
			t.Errorf("%q: TLS dir not carried", a)
		}
	}
}

// T-0274 acceptance 3: the in-memory principal store with more than one node fails configuration.
func TestLoadPrincipalStore(t *testing.T) {
	c, err := config.Load(env(nil))
	if err != nil || c.Nodes != 1 || c.PrincipalStore != config.PrincipalStorePostgres {
		t.Fatalf("defaults = %d %q, %v; want 1 node on the shared store", c.Nodes, c.PrincipalStore, err)
	}
	if _, err := config.Load(env(map[string]string{config.EnvNodes: "3"})); err != nil {
		t.Errorf("three nodes on the shared store: %v", err)
	}
	if _, err := config.Load(env(map[string]string{config.EnvPrincipalStore: "memory"})); err != nil {
		t.Errorf("memory on one node: %v", err)
	}
	for name, m := range map[string]map[string]string{
		"memory on two nodes": {config.EnvPrincipalStore: "memory", config.EnvNodes: "2"},
		"unknown store":       {config.EnvPrincipalStore: "redis"},
		"zero nodes":          {config.EnvNodes: "0"},
		"junk nodes":          {config.EnvNodes: "many"},
	} {
		if _, err := config.Load(env(m)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestTrustedProxies(t *testing.T) {
	c, err := config.Load(func(k string) string {
		if k == config.EnvTrustedProxies {
			return "10.0.0.0/8, 192.0.2.1"
		}
		return ""
	})
	if err != nil || len(c.TrustedProxies) != 2 || c.TrustedProxies[1].String() != "192.0.2.1/32" {
		t.Fatalf("got %v, %v", c.TrustedProxies, err)
	}
	if c, _ := config.Load(func(string) string { return "" }); len(c.TrustedProxies) != 0 {
		t.Fatal("default must trust nothing")
	}
	for _, bad := range []string{"nope", "0.0.0.0/0", "::/0", "10.0.0.0/8, 0.0.0.0/0"} {
		if _, err := config.Load(func(k string) string {
			if k == config.EnvTrustedProxies {
				return bad
			}
			return ""
		}); err == nil {
			t.Fatalf("%q must fail startup", bad)
		}
	}
}

func TestAttestationSettings(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	if c, err := config.Load(env(nil)); err != nil || c.AttestClientID != "" {
		t.Fatalf("default: %+v %v", c, err)
	}
	ok := map[string]string{config.EnvAttestClientID: "app", config.EnvPublicURL: "https://diq.example.com"}
	if c, err := config.Load(env(ok)); err != nil || c.AttestClientID != "app" {
		t.Fatalf("configured: %v", err)
	}
	for name, m := range map[string]map[string]string{
		"client without url": {config.EnvAttestClientID: "app"},
		"url without client": {config.EnvPublicURL: "https://diq.example.com"},
		"http":               {config.EnvAttestClientID: "app", config.EnvPublicURL: "http://diq.example.com"},
		"path":               {config.EnvAttestClientID: "app", config.EnvPublicURL: "https://diq.example.com/x"},
		"userinfo":           {config.EnvAttestClientID: "app", config.EnvPublicURL: "https://u:p@diq.example.com"},
		"query":              {config.EnvAttestClientID: "app", config.EnvPublicURL: "https://diq.example.com/?a=b"},
	} {
		if _, err := config.Load(env(m)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestKEKProfileNeedsTLSDir(t *testing.T) {
	if _, err := config.Load(env(map[string]string{config.EnvKEKFile: "/k"})); err == nil || !strings.Contains(err.Error(), config.EnvAPITLSDir) {
		t.Fatalf("KEK file without TLS dir must fail naming both, got %v", err)
	}
	c, err := config.Load(env(map[string]string{config.EnvKEKFile: "/k", config.EnvAPITLSDir: "/d"}))
	if err != nil || c.KEKFile != "/k" || c.KEKID != config.DefaultKEKID {
		t.Fatalf("got %v %+v", err, c)
	}
}

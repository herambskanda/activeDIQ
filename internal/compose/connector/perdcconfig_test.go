package connector

import (
	"crypto/x509"
	"testing"

	"github.com/skenzeriq/activediq/internal/connector/ad"
)

func TestPerDCConfig(t *testing.T) {
	pool := x509.NewCertPool()
	cfg := ad.Config{Servers: []string{"10.0.0.1", "10.0.0.2"}, ServerName: "dc0.corp.example", RootCAs: pool}
	got := perDCConfig(cfg, "dc2.corp.example")
	if len(got.Servers) != 1 || got.Servers[0] != "dc2.corp.example" || got.ServerName != "" || got.RootCAs != pool {
		t.Fatalf("%+v", got)
	}
	if cfg.ServerName != "dc0.corp.example" || len(cfg.Servers) != 2 {
		t.Fatal("input config mutated")
	}
}

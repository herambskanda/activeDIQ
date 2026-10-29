//go:build lab

package labboot

import (
	"context"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/client"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

func envOf(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

// T-0684 acceptance 3 (config half): no lab variables, no lab.
func TestLabSpecsNoEnvSeedsNothing(t *testing.T) {
	sp, err := labSpecs(envOf(nil))
	if err != nil || len(sp) != 0 {
		t.Fatalf("labSpecs(empty) = %v, %v; want none", sp, err)
	}
}

// T-0684 acceptance 1 and 2 (config half): both labs are read from their variables.
func TestLabSpecsReadBothLabs(t *testing.T) {
	sp, err := labSpecs(envOf(map[string]string{
		"WIN_LAB_DC_ADDR": "10.0.0.5", "WIN_LAB_SVC_PASSWORD": "pw1", "WIN_LAB_CA": "/ca1",
		"LAB_LDAPS_PORT": "6361", "LAB_SVC_PASSWORD": "pw2", "LAB_CA": "/ca2"}))
	if err != nil || len(sp) != 2 {
		t.Fatalf("labSpecs = %v, %v", sp, err)
	}
	if sp[0].Name != "win" || sp[0].Server != "10.0.0.5:636" || sp[0].ServerName != winLabTLS {
		t.Errorf("windows spec = %+v", sp[0])
	}
	if sp[1].Name != "samba" || sp[1].Server != "localhost:6361" {
		t.Errorf("samba spec = %+v", sp[1])
	}
}

// A partly configured lab fails closed and the error names the variable, never a value.
func TestLabSpecsPartialConfigFailsWithoutLeaking(t *testing.T) {
	_, err := labSpecs(envOf(map[string]string{"WIN_LAB_DC_ADDR": "10.0.0.5", "WIN_LAB_CA": "/ca"}))
	if err == nil || !strings.Contains(err.Error(), "WIN_LAB_SVC_PASSWORD") {
		t.Fatalf("err = %v, want one naming WIN_LAB_SVC_PASSWORD", err)
	}
	_, err = labSpecs(envOf(map[string]string{"LAB_LDAPS_PORT": "6361", "LAB_SVC_PASSWORD": "hunter2"}))
	if err == nil || !strings.Contains(err.Error(), "LAB_CA") || strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("err = %v, want one naming LAB_CA and not the password", err)
	}
}

// T-0684 acceptance 3 with no environment: the bootstrap returns the tunnel source untouched and
// touches neither database nor registry (both nil).
func TestLabBootstrapWithoutEnvIsInert(t *testing.T) {
	var next client.ConnectorSource = &client.TunnelSource{}
	got, _, closeFn, err := Bootstrap(context.Background(), envOf(nil), next)
	if err != nil || got != next {
		t.Fatalf("Bootstrap(no env) = (%v, %v)", got, err)
	}
	closeFn()
}

// The source routes a seeded connection in process and anything else to the tunnel source.
func TestLabSourceFallsThrough(t *testing.T) {
	s := &labSource{by: map[string]connectorv1.ConnectorClient{}}
	if _, err := s.Connector(context.Background(), "x"); err == nil {
		t.Fatal("an unknown connection with no tunnel source must be refused")
	}
}

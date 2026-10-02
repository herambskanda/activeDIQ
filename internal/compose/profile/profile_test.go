package profile_test

import (
	"testing"

	"github.com/skenzeriq/activediq/internal/compose/profile"
	"github.com/skenzeriq/activediq/internal/platform/capability"
)

func TestManifests(t *testing.T) {
	for _, m := range []profile.Manifest{profile.Windows(), profile.LinuxOCI(), profile.SaaS()} {
		if m.Name == "" || len(m.Processes) == 0 || len(m.Adapters.KeyProviders) == 0 {
			t.Errorf("%q: name, processes and key providers are required", m.Name)
		}
	}
}

// ADR-0002 / blueprint §3.3: the SaaS cell's embedded connector serves Entra only, and AD
// capability is absent there.
func TestSaaSHasNoEmbeddedAD(t *testing.T) {
	m := profile.SaaS()
	for _, p := range m.Processes {
		for _, pr := range p.Providers {
			if pr == profile.ProviderAD {
				t.Errorf("saas process %q embeds the AD provider", p.Binary)
			}
		}
	}
	if capability.NewSet(m.Capabilities...).Enabled(capability.DirectoryAD) {
		t.Error("saas must not enable directory.ad")
	}
}

// The two self-hosted profiles differ in adapters, never in capabilities (ADR-0002 rule 1).
func TestSelfHostedProfilesShareCapabilities(t *testing.T) {
	w, l := profile.Windows().Capabilities, profile.LinuxOCI().Capabilities
	if len(w) != len(l) {
		t.Fatalf("capabilities differ: %v vs %v", w, l)
	}
	ls := capability.NewSet(l...)
	for _, c := range w {
		if !ls.Enabled(c) {
			t.Errorf("windows has %q, linux-oci does not", c)
		}
	}
}

package oidc

import (
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/authn/sso"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// MFA-1a (X-14): MFA evidence is an allow-list, matched case-sensitively. Every value outside it is refused
// at save (ValidateConfig), at Start and at Complete, alone or beside an allowed value.
func TestOIDCConfig_RefusesNonAllowListedMFAEvidence(t *testing.T) {
	for _, bad := range []string{"wia", "rba", "geo", "swk", "pin", "mca", "pwd", "kba", "sms", "tel", "user", "PWD", "Mfa", "MFA", "x", "", " mfa"} {
		for name, evidence := range map[string][]string{"alone": {bad}, "beside allowed": {"mfa", bad}} {
			h := newHarness(t)
			h.cfg.MFAMode, h.cfg.MFAEvidence = sso.MFAClaim, evidence
			if got := sso.ReasonOf(ValidateConfig(&h.cfg)); got != ReasonConfig {
				t.Errorf("%q %s: ValidateConfig reason = %q, want %q", bad, name, got, ReasonConfig)
			}
			if _, _, err := h.v.Start(t.Context(), tenant.New(), h.idp(), sso.IntentSignin); sso.ReasonOf(err) != ReasonConfig {
				t.Errorf("%q %s: Start reason = %q, want %q", bad, name, sso.ReasonOf(err), ReasonConfig)
			}
			if _, err := h.flow2(); sso.ReasonOf(err) != ReasonConfig {
				t.Errorf("%q %s: Complete reason = %q, want %q", bad, name, sso.ReasonOf(err), ReasonConfig)
			}
		}
	}
}

func TestOIDCConfig_AcceptsEveryAllowListedMFAEvidence(t *testing.T) {
	h := newHarness(t)
	h.cfg.MFAMode, h.cfg.MFAEvidence = sso.MFAClaim, []string{"mfa", "hwk", "otp", "fpt", "face", "sc"}
	if err := ValidateConfig(&h.cfg); err != nil {
		t.Fatalf("ValidateConfig: %v", err)
	}
}

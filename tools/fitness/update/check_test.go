package main

import (
	"slices"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/updateverify"
)

func TestRealVerifierPassesBothCouriers(t *testing.T) {
	if p := Run(scenarios(), []courier{onlineCourier, offlineCourier}, realVerify); len(p) > 0 {
		t.Fatal(strings.Join(p, "\n"))
	}
}

// The matrix has to cover every acceptance criterion AC-1..AC-8 and every refusal reason, or a green
// run proves less than the threat model asks for.
func TestMatrixCoversSpec(t *testing.T) {
	acs := map[string]bool{}
	reasons := map[updateverify.Reason]bool{}
	for _, s := range scenarios() {
		acs[s.ac] = true
		reasons[s.want] = true
	}
	for _, ac := range []string{"AC-1", "AC-2", "AC-3", "AC-4", "AC-5", "AC-6", "AC-7", "AC-8"} {
		if !acs[ac] {
			t.Errorf("no scenario for %s", ac)
		}
	}
	for _, r := range updateverify.Reasons() {
		if !reasons[r] {
			t.Errorf("no scenario refuses with %q", r)
		}
	}
	if !reasons[""] {
		t.Error("no accepted scenario")
	}
}

// A harness that cannot fail proves nothing: each broken verifier must be caught.
func TestBrokenVerifiersAreCaught(t *testing.T) {
	for _, mode := range []string{"accept-all", "mislabel", "leak"} {
		v, err := verifyFor(mode)
		if err != nil {
			t.Fatal(err)
		}
		if p := Run(scenarios(), []courier{onlineCourier, offlineCourier}, v); len(p) == 0 {
			t.Errorf("sabotage %s went unnoticed", mode)
		}
	}
}

func TestReasonsHelperIsClosed(t *testing.T) {
	if !slices.Contains(updateverify.Reasons(), updateverify.ReasonWithdrawn) {
		t.Fatal("reasons enum lost withdrawn")
	}
}

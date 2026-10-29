package setup

import (
	"errors"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/apihost/apitypes"
	"github.com/skenzeriq/activediq/internal/platform/secret"
	"github.com/skenzeriq/activediq/internal/platform/setup/api"
)

func TestHandlerClaimsOnceAndRefusesUniformly(t *testing.T) {
	s, c := fresh(t, time.Minute)
	_, _, _ = s.Issue()
	good := secretOf(t, s)
	h := Handlers{Store: s}
	claim := func(v string) (api.ClaimFirstRunSetupOutput, error) {
		return h.ClaimFirstRunSetup(t.Context(), api.ClaimFirstRunSetupInput{Body: api.SetupClaimRequest{Secret: secret.FromBytes([]byte(v))}})
	}
	refused := func(err error) {
		t.Helper()
		var p *apitypes.Problem
		if !errors.As(err, &p) || p.Status != 401 || p.Type != apitypes.ProblemTypeSetupRefused || p.Detail != nil {
			t.Fatalf("want the uniform 401 setup-refused, got %v", err)
		}
	}
	_, err := claim("wrong")
	refused(err)
	if out, err := claim(good); err != nil || out.StatusCode() != 204 {
		t.Fatalf("claim: %v %v", out, err)
	}
	_, err = claim(good)
	refused(err) // used
	s2, c2 := fresh(t, time.Minute)
	_, _, _ = s2.Issue()
	g2 := secretOf(t, s2)
	c2.t = c2.t.Add(time.Hour)
	_, err = Handlers{Store: s2}.ClaimFirstRunSetup(t.Context(), api.ClaimFirstRunSetupInput{Body: api.SetupClaimRequest{Secret: secret.FromBytes([]byte(g2))}})
	refused(err) // expired
	_ = c
}

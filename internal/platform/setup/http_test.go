package setup

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/apihost/apitypes"
	"github.com/skenzeriq/activediq/internal/platform/secret"
	"github.com/skenzeriq/activediq/internal/platform/setup/api"
)

type fakeOwners struct {
	err   error
	calls int
	ip    string
	got   OwnerDetails
}

func (f *fakeOwners) CreateFirstOwner(_ context.Context, o OwnerDetails, ip string) error {
	f.calls++
	f.ip, f.got = ip, o
	return f.err
}

var okOwner = api.SetupOwner{DisplayName: "First Owner", Email: "owner@example.com"}

func claimWith(h Handlers, v string, o api.SetupOwner) (api.ClaimFirstRunSetupOutput, error) {
	return h.ClaimFirstRunSetup(context.Background(), api.ClaimFirstRunSetupInput{Body: api.SetupClaimRequest{Secret: secret.FromBytes([]byte(v)), Owner: o}})
}

func wantRefused(t *testing.T, err error) {
	t.Helper()
	var p *apitypes.Problem
	if !errors.As(err, &p) || p.Status != 401 || p.Type != apitypes.ProblemTypeSetupRefused || p.Detail != nil {
		t.Fatalf("want the uniform 401 setup-refused, got %v", err)
	}
}

func TestHandlerClaimsOnceCreatesOwnerAndRefusesUniformly(t *testing.T) {
	s, _ := fresh(t, time.Minute)
	_, _, _ = s.Issue()
	good := secretOf(t, s)
	fo := &fakeOwners{}
	h := Handlers{Store: s, Owners: fo}
	_, err := claimWith(h, "wrong", okOwner)
	wantRefused(t, err)
	if fo.calls != 0 {
		t.Fatal("an owner was created for a wrong secret")
	}
	if out, err := claimWith(h, good, okOwner); err != nil || out.StatusCode() != 204 {
		t.Fatalf("claim: %v %v", out, err)
	}
	if fo.calls != 1 || fo.got.Email != "owner@example.com" {
		t.Fatalf("owner creator: %+v", fo)
	}
	_, err = claimWith(h, good, okOwner)
	wantRefused(t, err) // used
	if fo.calls != 1 {
		t.Fatal("a second owner was created")
	}
	s2, c2 := fresh(t, time.Minute)
	_, _, _ = s2.Issue()
	g2 := secretOf(t, s2)
	c2.t = c2.t.Add(time.Hour)
	_, err = claimWith(Handlers{Store: s2, Owners: fo}, g2, okOwner)
	wantRefused(t, err) // expired
}

func TestHandlerOwnerFailureKeepsTheSecretUsable(t *testing.T) {
	s, _ := fresh(t, time.Minute)
	_, _, _ = s.Issue()
	good := secretOf(t, s)
	fo := &fakeOwners{err: errors.New("db down")}
	h := Handlers{Store: s, Owners: fo}
	if _, err := claimWith(h, good, okOwner); err == nil {
		t.Fatal("claim succeeded though the owner was not created")
	}
	fo.err = nil
	if _, err := claimWith(h, good, okOwner); err != nil {
		t.Fatalf("retry with the same secret: %v", err)
	}
}

func TestHandlerExistingOwnerIsTheUniformRefusal(t *testing.T) {
	s, _ := fresh(t, time.Minute)
	_, _, _ = s.Issue()
	h := Handlers{Store: s, Owners: &fakeOwners{err: ErrOwnerExists}}
	_, err := claimWith(h, secretOf(t, s), okOwner)
	wantRefused(t, err)
}

// Bad owner details are a 400 whether or not the secret is right, so the answer never confirms the secret,
// and a wrong secret with good details is the 401.
func TestHandlerBadOwnerAnswersTheSameForAnySecret(t *testing.T) {
	s, _ := fresh(t, time.Minute)
	_, _, _ = s.Issue()
	good := secretOf(t, s)
	fo := &fakeOwners{}
	h := Handlers{Store: s, Owners: fo}
	for _, o := range []api.SetupOwner{
		{DisplayName: "", Email: "o@example.com"},
		{DisplayName: "O", Email: "not-an-address"},
		{DisplayName: "O", Email: "Bob <bob@example.com>"},
		{DisplayName: "O\n", Email: "o@example.com"},
	} {
		for _, sec := range []string{good, "wrong"} {
			_, err := claimWith(h, sec, o)
			var p *apitypes.Problem
			if !errors.As(err, &p) || p.Status != 400 {
				t.Fatalf("owner %+v secret-right=%v: %v", o, sec == good, err)
			}
		}
	}
	if fo.calls != 0 {
		t.Fatal("an owner was created from bad details")
	}
	// The bad attempts did not consume the secret.
	if _, err := claimWith(h, good, okOwner); err != nil {
		t.Fatalf("good claim after bad details: %v", err)
	}
}

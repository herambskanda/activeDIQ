package authn

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/apihost/apitypes"
	"github.com/skenzeriq/activediq/internal/platform/authn/api"
	"github.com/skenzeriq/activediq/internal/platform/secret"
)

// The in-flight gate never queues: above the cap it refuses, and a released slot is reusable.
func TestInFlightGateRefusesAboveTheCap(t *testing.T) {
	l := &LocalCredentials{MaxConcurrent: 2}
	r1, ok1 := l.acquire()
	r2, ok2 := l.acquire()
	if !ok1 || !ok2 {
		t.Fatal("the first two slots must be granted")
	}
	if _, ok := l.acquire(); ok {
		t.Fatal("a third slot was granted over a cap of 2")
	}
	r1()
	r3, ok := l.acquire()
	if !ok {
		t.Fatal("a released slot was not reusable")
	}
	r2()
	r3()
}

type failingPassword struct{ err error }

func (f failingPassword) BeginPasswordCookie(context.Context, string, secret.Secret, netip.Addr) (string, error) {
	return "", f.err
}

// A busy gate answers the global 429; a store or key fault fails closed with the same 401 as a wrong
// password (threat model §7.6 rule 2d), never a 500.
func TestPasswordStepBusyAndFaultAnswers(t *testing.T) {
	in := api.SignInBreakGlassPasswordInput{}
	_, err := Handlers{Password: failingPassword{ErrSignInBusy}}.SignInBreakGlassPassword(context.Background(), in)
	var p *apitypes.Problem
	if !errors.As(err, &p) || p.Status != 429 {
		t.Fatalf("busy: %v", err)
	}
	_, fault := Handlers{Password: failingPassword{errors.New("pgx: connection refused")}}.SignInBreakGlassPassword(context.Background(), in)
	_, wrong := Handlers{Password: failingPassword{ErrSignInRefused}}.SignInBreakGlassPassword(context.Background(), in)
	var pf, pw *apitypes.Problem
	if !errors.As(fault, &pf) || !errors.As(wrong, &pw) {
		t.Fatalf("fault %v, wrong %v", fault, wrong)
	}
	if pf.Status != 401 || !reflect.DeepEqual(pf, pw) {
		t.Errorf("a fault must answer exactly the wrong-password 401: %+v vs %+v", pf, pw)
	}
}

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

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

// The in-flight gate never queues: above the cap it refuses, and a released slot is reusable.
func TestInFlightGateRefusesAboveTheCap(t *testing.T) {
	l := &LocalCredentials{MaxConcurrent: 2}
	r1, ok1 := l.acquire(addr("192.0.2.1"))
	r2, ok2 := l.acquire(addr("192.0.2.2"))
	if !ok1 || !ok2 {
		t.Fatal("the first two slots must be granted")
	}
	if _, ok := l.acquire(addr("192.0.2.3")); ok {
		t.Fatal("a third slot was granted over a cap of 2")
	}
	r1()
	r1() // a second release of the same slot must not free another one
	r3, ok := l.acquire(addr("192.0.2.3"))
	if !ok {
		t.Fatal("a released slot was not reusable")
	}
	if _, ok := l.acquire(addr("192.0.2.4")); ok {
		t.Fatal("a double release freed an extra slot")
	}
	r2()
	r3()
	if l.held != 0 || len(l.bySource) != 0 {
		t.Fatalf("slots leaked: held %d, sources %d", l.held, len(l.bySource))
	}
}

// One source holds at most its share, so it cannot take every slot, and a second source still gets one.
func TestInFlightGateGivesEachSourceAFairShare(t *testing.T) {
	l := &LocalCredentials{} // defaults: 4 slots, 1 per source
	hog, ok := l.acquire(addr("198.51.100.7"))
	if !ok {
		t.Fatal("the first slot of a source must be granted")
	}
	for i := 0; i < 20; i++ {
		if _, ok := l.acquire(addr("198.51.100.7")); ok {
			t.Fatal("one source took more than its share")
		}
	}
	others := []string{"198.51.100.8", "203.0.113.9", "2001:db8:1::1"}
	var rel []func()
	for _, o := range others {
		r, ok := l.acquire(addr(o))
		if !ok {
			t.Fatalf("source %s was refused while a single source held one slot", o)
		}
		rel = append(rel, r)
	}
	hog()
	if r, ok := l.acquire(addr("198.51.100.7")); !ok {
		t.Fatal("a source must be able to take a slot again after its release")
	} else {
		r()
	}
	for _, r := range rel {
		r()
	}
}

// Sources are an IPv4 /32 or an IPv6 /64: a host rotating addresses inside its /64, or writing its IPv4
// address in mapped form, does not get a second slot; a different /64 is a different source.
func TestSourceKeyGroupsIPv6By64AndUnmapsIPv4(t *testing.T) {
	same := [][2]string{
		{"2001:db8:aa:bb::1", "2001:db8:aa:bb:ffff:ffff:ffff:ffff"},
		{"192.0.2.5", "::ffff:192.0.2.5"},
		{"fe80::1%eth0", "fe80::2"},
	}
	for _, p := range same {
		if sourceKey(addr(p[0])) != sourceKey(addr(p[1])) {
			t.Errorf("%s and %s must be one source", p[0], p[1])
		}
	}
	diff := [][2]string{
		{"2001:db8:aa:bb::1", "2001:db8:aa:bc::1"},
		{"192.0.2.5", "192.0.2.6"},
	}
	for _, p := range diff {
		if sourceKey(addr(p[0])) == sourceKey(addr(p[1])) {
			t.Errorf("%s and %s must be different sources", p[0], p[1])
		}
	}
	l := &LocalCredentials{}
	r, ok := l.acquire(addr("2001:db8:aa:bb::1"))
	if !ok {
		t.Fatal("first slot refused")
	}
	if _, ok := l.acquire(addr("2001:db8:aa:bb::99")); ok {
		t.Error("a second address in the same /64 got a slot")
	}
	r()
}

// An address that did not parse is one shared source, not an unlimited one.
func TestUnparsedSourceIsOneSharedSource(t *testing.T) {
	l := &LocalCredentials{}
	r, ok := l.acquire(netip.Addr{})
	if !ok {
		t.Fatal("first slot refused")
	}
	if _, ok := l.acquire(netip.Addr{}); ok {
		t.Error("unparsed sources took more than one slot")
	}
	r()
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

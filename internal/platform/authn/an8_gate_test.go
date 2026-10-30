package authn

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/apihost/apitypes"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authn/api"
	"github.com/skenzeriq/activediq/internal/platform/secret"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
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
	l := &LocalCredentials{}
	same := [][2]string{
		{"2001:db8:aa:bb::1", "2001:db8:aa:bb:ffff:ffff:ffff:ffff"},
		{"192.0.2.5", "::ffff:192.0.2.5"},
		{"fe80::1%eth0", "fe80::2"},
		{"64:ff9b::c000:201", "192.0.2.1"}, // NAT64 carries the IPv4 client (§7.8 rule 2)
	}
	for _, p := range same {
		if l.sourceKey(addr(p[0])) != l.sourceKey(addr(p[1])) {
			t.Errorf("%s and %s must be one source", p[0], p[1])
		}
	}
	diff := [][2]string{
		{"2001:db8:aa:bb::1", "2001:db8:aa:bc::1"},
		{"192.0.2.5", "192.0.2.6"},
		{"64:ff9b::c000:201", "64:ff9b::c000:202"}, // two NAT64 clients are two sources, not one /64
	}
	for _, p := range diff {
		if l.sourceKey(addr(p[0])) == l.sourceKey(addr(p[1])) {
			t.Errorf("%s and %s must be different sources", p[0], p[1])
		}
	}
	r, ok := l.acquire(addr("2001:db8:aa:bb::1"))
	if !ok {
		t.Fatal("first slot refused")
	}
	if _, ok := l.acquire(addr("2001:db8:aa:bb::99")); ok {
		t.Error("a second address in the same /64 got a slot")
	}
	r()
}

// The operator's §7.8 prefix lengths apply to the gate as they do to the limiter: at IPv6 /48, two /64s
// in one /48 are one source and share one slot; a different /48 is another source.
func TestSourceKeyHonoursConfiguredPrefixLengths(t *testing.T) {
	l := &LocalCredentials{IPv6Bits: 48}
	r, ok := l.acquire(addr("2001:db8:aa:1::1"))
	if !ok {
		t.Fatal("first slot refused")
	}
	defer r()
	if _, ok := l.acquire(addr("2001:db8:aa:2::1")); ok {
		t.Error("two /64s in one /48 took two slots at IPv6 /48")
	}
	r2, ok := l.acquire(addr("2001:db8:bb:1::1"))
	if !ok {
		t.Fatal("a different /48 was refused")
	}
	r2()
	l4 := &LocalCredentials{IPv4Bits: 24}
	r3, ok := l4.acquire(addr("192.0.2.1"))
	if !ok {
		t.Fatal("first slot refused")
	}
	defer r3()
	if _, ok := l4.acquire(addr("192.0.2.200")); ok {
		t.Error("two addresses in one /24 took two slots at IPv4 /24")
	}
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

type stubKeys struct{ KeySource }
type stubSink struct{ audit.Sink }

// configured returns a LocalCredentials whose dependencies are all set (never called), so only the
// source prefix lengths decide whether ready() accepts it.
func configured(v4, v6 int) *LocalCredentials {
	return &LocalCredentials{DB: &store.DB{}, Sessions: &Store{}, Pending: &PendingStore{}, Keys: stubKeys{}, Audit: stubSink{},
		Tenant: func() (tenant.ID, bool) { return tenant.ID{}, false }, IPv4Bits: v4, IPv6Bits: v6}
}

// A prefix length outside the §7.8 ranges (IPv4 /24../32, IPv6 /48../64) is refused when the gate is
// used, so it is never a finer key; the in-range edges and the zero default are accepted.
func TestSourcePrefixLengthsOutsideTheRangesAreRefused(t *testing.T) {
	for _, c := range []struct{ v4, v6 int }{{0, 128}, {0, 96}, {0, 65}, {0, 47}, {0, -1}, {33, 0}, {23, 0}, {128, 128}} {
		if err := configured(c.v4, c.v6).ready(); err == nil {
			t.Errorf("IPv4Bits=%d IPv6Bits=%d was accepted", c.v4, c.v6)
		}
		if _, err := configured(c.v4, c.v6).BeginPassword(context.Background(), "a", secret.Secret{}, addr("2001:db8::1")); err == nil {
			t.Errorf("BeginPassword ran with IPv4Bits=%d IPv6Bits=%d", c.v4, c.v6)
		}
	}
	for _, c := range []struct{ v4, v6 int }{{0, 0}, {24, 48}, {32, 64}, {28, 56}} {
		if err := configured(c.v4, c.v6).ready(); err != nil {
			t.Errorf("IPv4Bits=%d IPv6Bits=%d refused: %v", c.v4, c.v6, err)
		}
	}
}

// Even if an out-of-range value reached sourceKey, it falls back to the defaults: two addresses in one
// /64 stay one source at IPv6Bits 96 and 128 (the fail-open the ticket describes).
func TestSourceKeyNeverUsesAFinerThanAllowedPrefix(t *testing.T) {
	for _, bits := range []int{96, 128} {
		l := &LocalCredentials{IPv6Bits: bits}
		r, ok := l.acquire(addr("2001:db8:aa:bb::1"))
		if !ok {
			t.Fatalf("/%d: first slot refused", bits)
		}
		if _, ok := l.acquire(addr("2001:db8:aa:bb::2")); ok {
			t.Errorf("/%d: two addresses in one /64 took two slots", bits)
		}
		r()
	}
	l4 := &LocalCredentials{IPv4Bits: 33}
	if l4.sourceKey(addr("192.0.2.1")).Bits() != 32 {
		t.Error("IPv4Bits 33 did not fall back to /32")
	}
}

package limiter

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newL(t *testing.T, c Config) (*Limiter, *clock) {
	t.Helper()
	ck := &clock{t: time.Unix(1_800_000_000, 0)}
	c.Now = ck.now
	c.Principals = NewMemoryStore(ck.now)
	l, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	return l, ck
}

func allow(t *testing.T, l *Limiter, class, ip string) apihost.Decision {
	t.Helper()
	d, err := l.AllowIP(context.Background(), class, ip)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// Acceptance 1: burst+1 requests across two addresses of one /64 are refused with RetryAfter.
func TestBurstPlusOneAcrossOneSlash64(t *testing.T) {
	l, _ := newL(t, Config{})
	b := ipClasses["anonymous"].Burst
	for i := 0; i < b; i++ {
		ip := "2001:db8:1:2::1"
		if i%2 == 1 {
			ip = fmt.Sprintf("2001:db8:1:2:%x::9", i)
		}
		if !allow(t, l, "anonymous", ip).Allowed {
			t.Fatalf("request %d refused inside the burst", i+1)
		}
	}
	d := allow(t, l, "anonymous", "2001:db8:1:2:ffff::7")
	if d.Allowed || d.RetryAfter <= 0 {
		t.Fatalf("burst+1 = %+v, want refused with RetryAfter > 0", d)
	}
	if !allow(t, l, "anonymous", "2001:db8:1:3::1").Allowed {
		t.Fatal("a different /64 shares the bucket")
	}
}

// Acceptance 2: equivalent spellings share one key; different /64s do not.
func TestKeyGroups(t *testing.T) {
	groups := [][]string{
		{"192.0.2.1", "::ffff:192.0.2.1", "64:ff9b::c000:201", "64:ff9b::192.0.2.1"},
		{"fe80::1%eth0", "fe80::1"},
	}
	for _, g := range groups {
		first, ok := ipKey(g[0], 32, 64)
		if !ok {
			t.Fatalf("%q unparseable", g[0])
		}
		for _, s := range g[1:] {
			if k, ok := ipKey(s, 32, 64); !ok || k != first {
				t.Errorf("key(%q) = %q, want %q", s, k, first)
			}
		}
	}
	a, _ := ipKey("2001:db8:1:2::1", 32, 64)
	b, _ := ipKey("2001:db8:1:3::1", 32, 64)
	if a == b || a != "2001:db8:1:2::/64" {
		t.Errorf("keys %q %q", a, b)
	}
	if k, _ := ipKey("192.0.2.7", 32, 64); k != "192.0.2.7/32" {
		t.Errorf("v4 key %q", k)
	}
	if k, _ := ipKey("192.0.2.7", 24, 64); k != "192.0.2.0/24" {
		t.Errorf("v4 /24 key %q", k)
	}
	if k, _ := ipKey("2001:db8:1:2::1", 32, 48); k != "2001:db8:1::/48" {
		t.Errorf("v6 /48 key %q", k)
	}
}

// The shared groups really share a bucket through AllowIP.
func TestSpellingsShareBucket(t *testing.T) {
	l, _ := newL(t, Config{})
	spell := []string{"192.0.2.1", "::ffff:192.0.2.1", "64:ff9b::c000:201"}
	for i := 0; i < ipClasses["auth"].Burst; i++ {
		if !allow(t, l, "auth", spell[i%3]).Allowed {
			t.Fatalf("refused early at %d", i)
		}
	}
	if allow(t, l, "auth", spell[0]).Allowed {
		t.Fatal("burst+1 admitted")
	}
}

// Acceptance 3.
func TestStartupRejectsOutOfRangePrefixes(t *testing.T) {
	for _, c := range []Config{{IPv6Bits: 47}, {IPv6Bits: 65}, {IPv4Bits: 23}, {IPv4Bits: 33}, {IPv6Bits: -1}} {
		c.Principals = NewMemoryStore(nil)
		if _, err := New(c); err == nil {
			t.Errorf("New(%+v) succeeded", c)
		}
	}
	for _, c := range []Config{{}, {IPv4Bits: 24, IPv6Bits: 48}, {IPv4Bits: 32, IPv6Bits: 64}} {
		c.Principals = NewMemoryStore(nil)
		if _, err := New(c); err != nil {
			t.Errorf("New(%+v) = %v", c, err)
		}
	}
}

func TestNonDefaultSettingsLogged(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	if _, err := New(Config{IPv6Bits: 56, Principals: NewMemoryStore(nil), Log: log}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(buf.Bytes(), []byte("ipv6_bits=56")) {
		t.Fatalf("not logged: %q", buf.String())
	}
	buf.Reset()
	if _, err := New(Config{Principals: NewMemoryStore(nil), Log: log}); err != nil || buf.Len() != 0 {
		t.Fatalf("defaults logged or failed: %v %q", err, buf.String())
	}
}

// Acceptance 4a: unparseable sources share one bucket per class and never mint new ones.
func TestUnparseableSourcesShareOneBucket(t *testing.T) {
	l, _ := newL(t, Config{})
	n := ipClasses["anonymous"].Burst
	for i := 0; i < n; i++ {
		if !allow(t, l, "anonymous", fmt.Sprintf("garbage-%d", i)).Allowed {
			t.Fatalf("refused early at %d", i)
		}
	}
	if allow(t, l, "anonymous", "yet-another").Allowed {
		t.Fatal("unparseable source got a fresh bucket")
	}
	if len(l.buckets) != 0 {
		t.Fatalf("raw strings created %d keyed buckets", len(l.buckets))
	}
}

// Acceptance 4b: at the cap new keys share a throttling overflow bucket; existing keys keep theirs.
func TestFullTableThrottlesNewKeys(t *testing.T) {
	l, _ := newL(t, Config{MaxBuckets: 2}) // floor-only class: one bucket per key
	for _, ip := range []string{"192.0.2.1", "192.0.2.2"} {
		if !allow(t, l, "read", ip).Allowed {
			t.Fatal("refused while filling")
		}
	}
	admitted := 0
	for i := 0; i < 1000; i++ {
		if allow(t, l, "read", fmt.Sprintf("198.51.100.%d", i%250)).Allowed {
			admitted++
		}
	}
	if admitted != floor.Burst {
		t.Fatalf("overflow admitted %d, want exactly the shared burst %d", admitted, floor.Burst)
	}
	if len(l.buckets) != 2 {
		t.Fatalf("table grew to %d", len(l.buckets))
	}
	if !allow(t, l, "read", "192.0.2.1").Allowed {
		t.Fatal("a tracked key lost its bucket")
	}
}

// Full buckets are evicted, so the table frees up.
func TestRefilledBucketsAreEvicted(t *testing.T) {
	l, ck := newL(t, Config{MaxBuckets: 1})
	allow(t, l, "read", "192.0.2.1")
	ck.t = ck.t.Add(time.Minute)
	allow(t, l, "read", "192.0.2.2")
	if _, ok := l.buckets[bucketKey{floorScope, "192.0.2.2/32"}]; !ok {
		t.Fatal("new key not tracked after eviction")
	}
}

func TestRefillAndRetryAfter(t *testing.T) {
	l, ck := newL(t, Config{})
	for i := 0; i < ipClasses["anonymous"].Burst; i++ {
		allow(t, l, "anonymous", "192.0.2.1")
	}
	d := allow(t, l, "anonymous", "192.0.2.1")
	if d.Allowed || d.RetryAfter < 900*time.Millisecond || d.RetryAfter > 1100*time.Millisecond {
		t.Fatalf("decision %+v, want about 1s at 60/min", d)
	}
	ck.t = ck.t.Add(d.RetryAfter)
	if !allow(t, l, "anonymous", "192.0.2.1").Allowed {
		t.Fatal("still refused after RetryAfter")
	}
}

// A refusal by the class row must not spend the floor token.
func TestRefusalDoesNotConsumeFloor(t *testing.T) {
	l, _ := newL(t, Config{})
	for i := 0; i < 1000; i++ {
		allow(t, l, "anonymous", "192.0.2.1")
	}
	b := l.buckets[bucketKey{floorScope, "192.0.2.1/32"}]
	if want := float64(floor.Burst - ipClasses["anonymous"].Burst); b.tokens != want {
		t.Fatalf("floor tokens %v, want %v", b.tokens, want)
	}
}

func TestUnknownClassFailsClosed(t *testing.T) {
	l, _ := newL(t, Config{})
	if _, err := l.AllowIP(context.Background(), "nope", "192.0.2.1"); err == nil {
		t.Fatal("unknown class admitted")
	}
	if _, err := l.AllowPrincipal(context.Background(), "anonymous", apihost.Principal{ID: "u"}); err == nil {
		t.Fatal("IP-only class admitted for a principal")
	}
	if _, err := l.AllowPrincipal(context.Background(), "read", apihost.Principal{}); err == nil {
		t.Fatal("empty principal admitted")
	}
}

func TestPrincipalBucketsPerClassAndPrincipal(t *testing.T) {
	l, _ := newL(t, Config{})
	ctx := context.Background()
	alice := apihost.Principal{ID: "alice", Kind: apihost.KindToken}
	for i := 0; i < principalClasses["bulk"].Burst; i++ {
		if d, err := l.AllowPrincipal(ctx, "bulk", alice); err != nil || !d.Allowed {
			t.Fatalf("%d: %+v %v", i, d, err)
		}
	}
	if d, _ := l.AllowPrincipal(ctx, "bulk", alice); d.Allowed || d.RetryAfter <= 0 {
		t.Fatalf("burst+1 = %+v", d)
	}
	// Same human through a session shares the budget; another class or person does not.
	if d, _ := l.AllowPrincipal(ctx, "bulk", apihost.Principal{ID: "alice", Kind: apihost.KindSession}); d.Allowed {
		t.Fatal("session got a second budget")
	}
	if d, _ := l.AllowPrincipal(ctx, "write", alice); !d.Allowed {
		t.Fatal("classes share a budget")
	}
	if d, _ := l.AllowPrincipal(ctx, "bulk", apihost.Principal{ID: "bob"}); !d.Allowed {
		t.Fatal("principals share a budget")
	}
}

// SourcePrefix is the one definition of "source" (§7.8 rules 1-3) the AN-8 gate shares with ipKey.
func TestSourcePrefixCanonicalForms(t *testing.T) {
	cases := []struct {
		addr   string
		v4, v6 int
		want   string
	}{
		{"192.0.2.1", 32, 64, "192.0.2.1/32"},
		{"::ffff:192.0.2.1", 32, 64, "192.0.2.1/32"},
		{"64:ff9b::c000:201", 32, 64, "192.0.2.1/32"},
		{"64:ff9b::c000:201", 24, 64, "192.0.2.0/24"},
		{"2001:db8:aa:bb:1::1%eth0", 32, 64, "2001:db8:aa:bb::/64"},
		{"2001:db8:aa:bb::1", 32, 48, "2001:db8:aa::/48"},
	}
	for _, c := range cases {
		p, ok := SourcePrefix(netip.MustParseAddr(c.addr), c.v4, c.v6)
		if !ok || p.String() != c.want {
			t.Errorf("SourcePrefix(%s,/%d,/%d) = %v,%v; want %s", c.addr, c.v4, c.v6, p, ok, c.want)
		}
	}
	if _, ok := SourcePrefix(netip.Addr{}, 32, 64); ok {
		t.Error("an invalid address produced a prefix")
	}
	if _, ok := SourcePrefix(netip.MustParseAddr("192.0.2.1"), 33, 64); ok {
		t.Error("an out-of-range prefix length produced a prefix")
	}
	for _, bits := range []int{47, 65, 96, 128} { // net/netip accepts these; §7.8 does not
		if p, ok := SourcePrefix(netip.MustParseAddr("2001:db8:aa:bb::1"), 32, bits); ok {
			t.Errorf("IPv6 /%d produced a prefix %v", bits, p)
		}
	}
	if _, ok := SourcePrefix(netip.MustParseAddr("192.0.2.1"), 23, 64); ok {
		t.Error("IPv4 /23 produced a prefix")
	}
}

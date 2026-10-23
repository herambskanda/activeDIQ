package fleetsql

import (
	"context"
	"testing"
	"time"
)

func TestMemoryLimiter(t *testing.T) {
	now := time.Unix(1000, 0)
	l := NewMemoryLimiter(MemoryLimiterConfig{Burst: 2, Refill: time.Minute, MaxSources: 2, Now: func() time.Time { return now }})
	ctx := context.Background()
	blocked := func(src string) bool { _, b, _ := l.Blocked(ctx, src); return b }

	l.Failed(ctx, "203.0.113.5")
	if blocked("203.0.113.5") {
		t.Fatal("blocked after one failure")
	}
	l.Failed(ctx, "203.0.113.5")
	if !blocked("203.0.113.5") || blocked("203.0.113.6") {
		t.Fatal("budget is per source")
	}
	now = now.Add(61 * time.Second)
	if blocked("203.0.113.5") {
		t.Fatal("budget does not refill")
	}
	// An IPv6 /64 is one source.
	l.Failed(ctx, "2001:db8::1")
	l.Failed(ctx, "2001:db8::ffff")
	if !blocked("2001:db8::1234") {
		t.Fatal("addresses of one /64 do not share a bucket")
	}
	// A full table sends new sources to the shared overflow bucket, which still throttles.
	for _, s := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"} {
		l.Failed(ctx, s)
		l.Failed(ctx, s)
	}
	if !blocked("192.0.2.99") {
		t.Fatal("overflow bucket admits unlimited attempts")
	}
	if len(l.m) > 3 {
		t.Fatalf("table grew to %d", len(l.m))
	}
}

func TestTokenRoundTrip(t *testing.T) {
	if _, ok := tenantOf(ParseToken("  garbage ")); ok {
		t.Fatal("garbage parsed")
	}
}

func TestSourceKeyForms(t *testing.T) {
	now := time.Unix(1000, 0)
	l := NewMemoryLimiter(MemoryLimiterConfig{Burst: 2, Refill: time.Minute, Now: func() time.Time { return now }})
	ctx := context.Background()
	blocked := func(src string) bool { _, b, err := l.Blocked(ctx, src); return b && err == nil }

	for i := 0; i < 5; i++ {
		l.Failed(ctx, "203.0.113.9:4000"+string(rune('0'+i)))
	}
	if !blocked("203.0.113.9:1") {
		t.Fatal("ip:port forms of one address do not share a bucket")
	}
	if blocked("198.51.100.1:5555") {
		t.Fatal("a different IP in ip:port form is throttled by another")
	}
	l.Failed(ctx, "[2001:db8::1]:443")
	l.Failed(ctx, "2001:db8::2")
	if !blocked("[2001:db8::99]:1") {
		t.Fatal("bracketed and bare IPv6 in one /64 do not share a bucket")
	}
}

func TestUnreadableSourceHasNoBucket(t *testing.T) {
	l := NewMemoryLimiter(MemoryLimiterConfig{Burst: 1})
	ctx := context.Background()
	for _, s := range []string{"", "garbage", "1.2.3.4:", "[::1"} {
		if _, _, err := l.Blocked(ctx, s); err == nil {
			t.Fatalf("Blocked(%q) did not error", s)
		}
		l.Failed(ctx, s)
	}
	if len(l.m) != 0 {
		t.Fatalf("unreadable sources created %d buckets", len(l.m))
	}
}

// A real clock moves between calls. Every other test freezes it, which hid a limiter that never
// blocked (decay took spent just under Burst before each check).
func TestMemoryLimiterMovingClock(t *testing.T) {
	now := time.Unix(1000, 0)
	const refill = 30 * time.Second
	l := NewMemoryLimiter(MemoryLimiterConfig{Burst: 5, Refill: refill, Now: func() time.Time {
		now = now.Add(time.Nanosecond)
		return now
	}})
	ctx := context.Background()
	const src = "203.0.113.9:4444"
	attempt := func() bool {
		wait, blocked, err := l.Blocked(ctx, src)
		if err != nil {
			t.Fatal(err)
		}
		if blocked {
			if wait <= 0 || wait > refill {
				t.Fatalf("retryAfter %v outside (0, %v]", wait, refill)
			}
			return false
		}
		l.Failed(ctx, src)
		return true
	}
	admitted := 0
	for range 1000 {
		if attempt() {
			admitted++
		}
	}
	if admitted != 5 {
		t.Fatalf("admitted %d of 1000, want Burst=5", admitted)
	}
	now = now.Add(refill)
	admitted = 0
	for range 100 {
		if attempt() {
			admitted++
		}
	}
	if admitted != 1 {
		t.Fatalf("after one Refill admitted %d, want exactly 1", admitted)
	}
}

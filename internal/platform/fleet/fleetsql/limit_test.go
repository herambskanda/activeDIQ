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

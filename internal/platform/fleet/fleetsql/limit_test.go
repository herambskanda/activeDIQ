package fleetsql

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMemoryLimiter(t *testing.T) {
	now := time.Unix(1000, 0)
	l := NewMemoryLimiter(MemoryLimiterConfig{Burst: 2, Refill: time.Minute, MaxSources: 2, Now: func() time.Time { return now }})
	ctx := context.Background()
	admit := func(src string) bool { _, ok, err := l.Admit(ctx, src); return ok && err == nil }

	if !admit("203.0.113.5") || !admit("203.0.113.5") {
		t.Fatal("refused within budget")
	}
	if admit("203.0.113.5") || !admit("203.0.113.6") {
		t.Fatal("budget is per source")
	}
	now = now.Add(61 * time.Second)
	if !admit("203.0.113.5") {
		t.Fatal("budget does not refill")
	}
	// An IPv6 /64 is one source.
	admit("2001:db8::1")
	admit("2001:db8::ffff")
	if admit("2001:db8::1234") {
		t.Fatal("addresses of one /64 do not share a bucket")
	}
	// A full table sends new sources to the shared overflow bucket, which still throttles.
	for _, s := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"} {
		admit(s)
		admit(s)
	}
	if admit("192.0.2.99") {
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
	admit := func(src string) bool { _, ok, err := l.Admit(ctx, src); return ok && err == nil }

	for i := 0; i < 2; i++ {
		if !admit("203.0.113.9:4000" + string(rune('0'+i))) {
			t.Fatal("refused within budget")
		}
	}
	if admit("203.0.113.9:1") {
		t.Fatal("ip:port forms of one address do not share a bucket")
	}
	if !admit("198.51.100.1:5555") {
		t.Fatal("a different IP in ip:port form is throttled by another")
	}
	admit("[2001:db8::1]:443")
	admit("2001:db8::2")
	if admit("[2001:db8::99]:1") {
		t.Fatal("bracketed and bare IPv6 in one /64 do not share a bucket")
	}
}

func TestUnreadableSourceHasNoBucket(t *testing.T) {
	l := NewMemoryLimiter(MemoryLimiterConfig{Burst: 1})
	ctx := context.Background()
	for _, s := range []string{"", "garbage", "1.2.3.4:", "[::1"} {
		if _, ok, err := l.Admit(ctx, s); err == nil || ok {
			t.Fatalf("Admit(%q) = ok %v err %v, want an error", s, ok, err)
		}
		l.Succeeded(ctx, s)
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
		wait, ok, err := l.Admit(ctx, src)
		if err != nil {
			t.Fatal(err)
		}
		if !ok && (wait <= 0 || wait > refill) {
			t.Fatalf("retryAfter %v outside (0, %v]", wait, refill)
		}
		return ok
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

// Admission reserves the try under the limiter's lock: attempts that overlap, as they do while each
// holds a database transaction, cannot all pass before any is charged.
func TestMemoryLimiterConcurrentAdmit(t *testing.T) {
	for name, now := range map[string]func() time.Time{"real clock": time.Now} {
		t.Run(name, func(t *testing.T) {
			l := NewMemoryLimiter(MemoryLimiterConfig{Now: now})
			ctx := context.Background()
			var admitted atomic.Int32
			start := make(chan struct{})
			var wg sync.WaitGroup
			for range 200 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					if _, ok, err := l.Admit(ctx, "203.0.113.9:4444"); err == nil && ok {
						time.Sleep(5 * time.Millisecond) // the database round trip
						admitted.Add(1)
					}
				}()
			}
			close(start)
			wg.Wait()
			if admitted.Load() != 5 {
				t.Fatalf("admitted %d of 200, want Burst=5", admitted.Load())
			}
		})
	}
}

func TestMemoryLimiterSucceededRefunds(t *testing.T) {
	now := time.Unix(1000, 0)
	l := NewMemoryLimiter(MemoryLimiterConfig{Burst: 2, Refill: time.Minute, Now: func() time.Time { return now }})
	ctx := context.Background()
	const src = "203.0.113.5"
	for range 10 {
		if _, ok, _ := l.Admit(ctx, src); !ok {
			t.Fatal("a source whose redeems all succeed was refused")
		}
		l.Succeeded(ctx, src)
	}
	if b := l.m["203.0.113.5/32"]; b == nil || b.spent != 0 {
		t.Fatalf("budget not left unchanged: %+v", b)
	}
	l.Succeeded(ctx, "198.51.100.1") // no bucket: must not create one
	if len(l.m) != 1 {
		t.Fatalf("refund created a bucket: %d", len(l.m))
	}
}

func TestMemoryLimiterSweepIsRateLimitedWhenFull(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	sweeps := 0
	l := NewMemoryLimiter(MemoryLimiterConfig{Burst: 2, Refill: time.Hour, MaxSources: 10, SweepEvery: time.Second,
		OnSweep: func() { sweeps++ }, Now: func() time.Time { return now }})
	for i := 0; i < 10; i++ { // fill with live sources
		if _, ok, err := l.Admit(context.Background(), fmt.Sprintf("10.0.0.%d", i)); err != nil || !ok {
			t.Fatalf("fill %d: ok=%v err=%v", i, ok, err)
		}
	}
	sweeps = 0
	admitted := 0
	for i := 0; i < 10000; i++ {
		if i%1000 == 0 {
			now = now.Add(time.Second) // 10 intervals over the run
		}
		_, ok, err := l.Admit(context.Background(), fmt.Sprintf("10.1.%d.%d", i/250, i%250))
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			admitted++
		}
	}
	if sweeps > 10 {
		t.Fatalf("sweeps = %d, want <= 10 (one per interval)", sweeps)
	}
	// Every new source is metered by the one overflow bucket: only Burst tries pass in total.
	if admitted != 2 {
		t.Fatalf("overflow admitted %d, want 2", admitted)
	}
	if len(l.m) > 11 {
		t.Fatalf("table grew to %d", len(l.m))
	}
}

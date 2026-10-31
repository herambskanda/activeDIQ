package limiter

// TM-F-SESSION §7.8 proof, limiter only (T-0208, split from T-0073): every rate class admits exactly
// its burst and refuses burst + 1 with a positive RetryAfter, per source prefix and per principal.
// The apihost chain turns a refused Decision into 429 /problems/rate-limited with Retry-After
// (chain.go steps 3 and 10); that mapping is proved there. Multi-node is T-0062 / pgstore_test.go.
//
// The numbers below are copied from the §7.8 table on purpose and are not read from the limiter's
// own tables: a default that drifts from the threat model must fail here, not be re-blessed.

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

// spec78 is the §7.8 table for the classes this limiter owns. AN-8's per-account row (uniform 401)
// and AN-10's pending-handle row are enforced by the sign-in flow, not by these buckets.
var spec78 = struct {
	floor     Limit
	ip        map[string]Limit // source-IP rows on top of the floor
	principal map[string]Limit
}{
	floor: Limit{Rate: 1200, Burst: 300},
	ip: map[string]Limit{
		"anonymous": {Rate: 60, Burst: 20},
		"auth":      {Rate: 60, Burst: 30},
	},
	principal: map[string]Limit{
		"read":   {Rate: 600, Burst: 120},
		"write":  {Rate: 120, Burst: 30},
		"bulk":   {Rate: 10, Burst: 3},
		"reveal": {Rate: 10, Burst: 5},
		"secret": {Rate: 30, Burst: 10},
	},
}

// retryBound is the time one token takes to refill; a refusal never asks for longer.
func retryBound(l Limit) time.Duration {
	return time.Duration(float64(time.Minute) / float64(l.Rate))
}

// fireAtOnce releases n calls together from n goroutines and counts the admissions. Every refused
// call must carry 0 < RetryAfter <= bound, and no call may error.
func fireAtOnce(t *testing.T, n int, bound time.Duration, call func(i int) (apihost.Decision, error)) (admitted int) {
	t.Helper()
	var (
		wg      sync.WaitGroup
		ok      atomic.Int64
		bad     atomic.Value
		release = make(chan struct{})
	)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-release
			d, err := call(i)
			switch {
			case err != nil:
				bad.CompareAndSwap(nil, fmt.Sprintf("call %d: error %v", i, err))
			case d.Allowed:
				ok.Add(1)
			case d.RetryAfter <= 0 || d.RetryAfter > bound:
				bad.CompareAndSwap(nil, fmt.Sprintf("call %d: refused with RetryAfter %v, want in (0, %v]", i, d.RetryAfter, bound))
			}
		}()
	}
	close(release)
	wg.Wait()
	if v := bad.Load(); v != nil {
		t.Fatal(v)
	}
	return int(ok.Load())
}

func TestLimiter(t *testing.T) {
	// The limiter must not own a class the threat model does not list, or the proof below skips it.
	t.Run("limiter_classes_match_spec", func(t *testing.T) {
		if floor != spec78.floor {
			t.Errorf("floor = %+v, §7.8 says %+v", floor, spec78.floor)
		}
		if len(ipClasses) != len(spec78.ip) {
			t.Errorf("limiter has %d source-IP classes, §7.8 has %d", len(ipClasses), len(spec78.ip))
		}
		for c, want := range spec78.ip {
			if got := ipClasses[c]; got != want {
				t.Errorf("class %s = %+v, §7.8 says %+v", c, got, want)
			}
		}
		if len(principalClasses) != len(spec78.principal) {
			t.Errorf("limiter has %d principal classes, §7.8 has %d", len(principalClasses), len(spec78.principal))
		}
		for c, want := range spec78.principal {
			if got := principalClasses[c]; got != want {
				t.Errorf("class %s = %+v, §7.8 says %+v", c, got, want)
			}
		}
	})

	// Source-IP rows: the floor ("(all)", reached by any class) and the anonymous and auth rows.
	ipRows := map[string]Limit{"floor": spec78.floor}
	for c, l := range spec78.ip {
		ipRows[c] = l
	}
	for name, lim := range ipRows {
		class := name
		if name == "floor" {
			class = "read" // a class with no source-IP row of its own meets only the floor
		}
		t.Run("limiter_burst_plus_one_"+name, func(t *testing.T) {
			// Exactly burst of burst+1 simultaneous requests from one IPv4 source.
			l, _ := newL(t, Config{})
			n := fireAtOnce(t, lim.Burst+1, retryBound(lim), func(int) (apihost.Decision, error) {
				return l.AllowIP(context.Background(), class, "192.0.2.10")
			})
			if n != lim.Burst {
				t.Fatalf("admitted %d of %d at once, want exactly %d", n, lim.Burst+1, lim.Burst)
			}
			// Frozen clock: nothing has refilled, so the very next request is refused too.
			if d := allow(t, l, class, "192.0.2.10"); d.Allowed || d.RetryAfter <= 0 {
				t.Fatalf("burst+2 = %+v, want refused with RetryAfter > 0", d)
			}
			// Another source has its own bucket.
			if !allow(t, l, class, "192.0.2.11").Allowed {
				t.Fatal("a different source shares the bucket")
			}
			// Sequential arrival gives the same answer, and the refusal is the burst+1'th.
			l2, _ := newL(t, Config{})
			for i := 1; i <= lim.Burst; i++ {
				if !allow(t, l2, class, "198.51.100.1").Allowed {
					t.Fatalf("request %d of %d refused inside the burst", i, lim.Burst)
				}
			}
			if d := allow(t, l2, class, "198.51.100.1"); d.Allowed || d.RetryAfter <= 0 || d.RetryAfter > retryBound(lim) {
				t.Fatalf("burst+1 = %+v, want refused with RetryAfter in (0, %v]", d, retryBound(lim))
			}
		})
	}

	// Principal rows, on the in-memory store (one node). The same rows on PostgreSQL are below.
	for class, lim := range spec78.principal {
		t.Run("limiter_burst_plus_one_"+class, func(t *testing.T) {
			l, _ := newL(t, Config{})
			principalBurstPlusOne(t, l, class, lim, true)
		})
	}

	// Acceptance 2: sources in one /64 share one bucket however they are spelled or rotated.
	t.Run("limiter_v6_prefix", func(t *testing.T) {
		for name, lim := range ipRows {
			class := name
			if name == "floor" {
				class = "read"
			}
			t.Run(name, func(t *testing.T) {
				l, _ := newL(t, Config{})
				// 2*burst distinct hosts (privacy-address style interface IDs) in 2001:db8:1:2::/64.
				n := fireAtOnce(t, 2*lim.Burst, retryBound(lim), func(i int) (apihost.Decision, error) {
					ip := fmt.Sprintf("2001:db8:1:2:%x:%x:%x:%x", 0x1000+i, 0xabcd^i, i*7919%65536, i+1)
					return l.AllowIP(context.Background(), class, ip)
				})
				if n != lim.Burst {
					t.Fatalf("one /64 admitted %d of %d together, want exactly %d", n, 2*lim.Burst, lim.Burst)
				}
				// A neighbouring /64 is a different source.
				if !allow(t, l, class, "2001:db8:1:3::1").Allowed {
					t.Fatal("the next /64 shares the bucket")
				}
				// The bucket is the /64, not the first address seen: the zone and the low 64 bits are ignored.
				if allow(t, l, class, "2001:db8:1:2::1").Allowed {
					t.Fatal("a new host in the exhausted /64 got a fresh bucket")
				}
			})
		}
	})

	// A coarser configured prefix widens the shared bucket; it never narrows it below /64.
	t.Run("limiter_v6_prefix_configured_48", func(t *testing.T) {
		lim := spec78.ip["anonymous"]
		l, _ := newL(t, Config{IPv6Bits: 48})
		n := fireAtOnce(t, 2*lim.Burst, retryBound(lim), func(i int) (apihost.Decision, error) {
			// Different /64s, one /48.
			return l.AllowIP(context.Background(), "anonymous", fmt.Sprintf("2001:db8:7:%x::1", i+1))
		})
		if n != lim.Burst {
			t.Fatalf("one /48 admitted %d, want exactly %d", n, lim.Burst)
		}
	})
}

// principalBurstPlusOne proves one principal class on l: exactly burst of burst+1 simultaneous calls,
// a second token of the same human on the same bucket, and another human unaffected.
//
// frozen says the store's clock does not move (MemoryStore under the test clock), so the count is
// exact. PostgreSQL stamps tokens with its own clock, which cannot be frozen: there the admissions
// may exceed the burst only by the tokens the measured elapsed time could have refilled, which for
// the slow classes (every row but read) is zero within a test's lifetime.
func principalBurstPlusOne(t *testing.T, l *Limiter, class string, lim Limit, frozen bool) {
	t.Helper()
	ctx := context.Background()
	started := time.Now()
	human := apihost.Principal{ID: "human-1", Tenant: "t1", Kind: apihost.KindSession}
	n := fireAtOnce(t, lim.Burst+1, retryBound(lim), func(i int) (apihost.Decision, error) {
		p := human
		if i%2 == 1 {
			p.Kind = apihost.KindToken // the human's API token counts against the same owner
		}
		return l.AllowPrincipal(ctx, class, p)
	})
	extra := 0
	if !frozen {
		extra = int(time.Since(started).Seconds() * float64(lim.Rate) / 60)
	}
	if n < lim.Burst || n > lim.Burst+extra {
		t.Fatalf("admitted %d of %d at once, want exactly %d (refill allowance %d)", n, lim.Burst+1, lim.Burst, extra)
	}
	if !frozen && n > lim.Burst {
		return // the bucket legitimately refilled while the calls ran; burst+2 below would be a race
	}
	if d, err := l.AllowPrincipal(ctx, class, human); err != nil || d.Allowed || d.RetryAfter <= 0 {
		t.Fatalf("burst+2 = %+v, %v; want refused with RetryAfter > 0", d, err)
	}
	if d, err := l.AllowPrincipal(ctx, class, apihost.Principal{ID: "human-2", Tenant: "t1"}); err != nil || !d.Allowed {
		t.Fatalf("another principal = %+v, %v; want admitted", d, err)
	}
}

// The same principal rows on the shared PostgreSQL store, which is what a deployment runs.
func TestLimiterPrincipalClassesOnPostgres(t *testing.T) {
	for class, lim := range spec78.principal {
		t.Run("limiter_burst_plus_one_"+class, func(t *testing.T) {
			eachDB(t, func(t *testing.T, d *storetest.Database) {
				principalBurstPlusOne(t, limiterOn(t, node(t, d)), class, lim, false)
			})
		})
	}
}

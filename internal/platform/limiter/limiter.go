// Package limiter implements apihost.Limiter: the token buckets of threat model §7.8 (TM-D22).
//
// Per-IP buckets (chain step 3) live in this node's memory, keyed by a network prefix, never by the
// raw source string. Per-principal buckets (step 10) live in a shared store so every node sees one
// count (ADR-0002 rule 6); the store is a port, PrincipalStore.
package limiter

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"sync"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
)

// Limit is a token bucket: Rate is the refill per minute, Burst the bucket size.
type Limit struct {
	Rate  int
	Burst int
}

// floorScope is the limit every request meets at step 3, whatever its class.
const floorScope = "*"

// floor is the §7.8 "(all)" row.
var floor = Limit{Rate: 1200, Burst: 300}

// ipClasses are the classes with their own source-IP row, on top of the floor.
var ipClasses = map[string]Limit{
	"anonymous": {Rate: 60, Burst: 20},
	"auth":      {Rate: 60, Burst: 30},
}

// principalClasses are the classes keyed by principal.
var principalClasses = map[string]Limit{
	"read":   {Rate: 600, Burst: 120},
	"write":  {Rate: 120, Burst: 30},
	"bulk":   {Rate: 10, Burst: 3},
	"reveal": {Rate: 10, Burst: 5},
	"secret": {Rate: 30, Burst: 10},
}

// ErrUnknownClass is returned for a class not in the §7.8 table, or used with the wrong key kind.
// Fail closed: an unrecognised class is never admitted.
var ErrUnknownClass = errors.New("limiter: unknown or misused rate class")

// PrincipalStore is the shared store of per-principal buckets. Take atomically refills the bucket
// named key to at most burst at rate tokens per minute and removes one token if there is one.
type PrincipalStore interface {
	Take(ctx context.Context, key string, l Limit) (apihost.Decision, error)
}

// Config configures a Limiter. Zero values take the defaults.
type Config struct {
	// IPv4Bits and IPv6Bits are the per-IP key prefix lengths; 0 means /32 and /64.
	IPv4Bits, IPv6Bits int
	// MaxBuckets bounds the per-IP table; 0 means 100000.
	MaxBuckets int
	// Principals is the shared store for AllowPrincipal. Required.
	Principals PrincipalStore
	Log        *slog.Logger
	Now        func() time.Time // tests only
}

// Limiter implements apihost.Limiter.
type Limiter struct {
	v4, v6 int
	max    int
	store  PrincipalStore
	now    func() time.Time

	mu        sync.Mutex
	buckets   map[bucketKey]*bucket
	special   map[specialKey]*bucket // unparseable and overflow buckets, one each per scope
	lastSweep time.Time
}

type bucketKey struct{ scope, prefix string }
type specialKey struct {
	scope    string
	overflow bool
}

type bucket struct {
	tokens float64
	at     time.Time
}

var _ apihost.Limiter = (*Limiter)(nil)

// New validates the configuration and returns the Limiter. A prefix length outside IPv4 /24../32 or
// IPv6 /48../64 fails (startup must fail). Non-default settings are logged.
func New(c Config) (*Limiter, error) {
	if c.IPv4Bits == 0 {
		c.IPv4Bits = DefaultIPv4Bits
	}
	if c.IPv6Bits == 0 {
		c.IPv6Bits = DefaultIPv6Bits
	}
	if err := checkBits(c.IPv4Bits, c.IPv6Bits); err != nil {
		return nil, err
	}
	if c.MaxBuckets < 0 {
		return nil, fmt.Errorf("limiter: MaxBuckets %d is negative", c.MaxBuckets)
	}
	if c.MaxBuckets == 0 {
		c.MaxBuckets = 100000
	}
	if c.Principals == nil {
		return nil, errors.New("limiter: a shared PrincipalStore is required")
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Log == nil {
		c.Log = slog.Default()
	}
	if c.IPv4Bits != DefaultIPv4Bits || c.IPv6Bits != DefaultIPv6Bits {
		c.Log.Info("limiter: non-default per-IP key prefix lengths", "ipv4_bits", c.IPv4Bits, "ipv6_bits", c.IPv6Bits)
	}
	return &Limiter{v4: c.IPv4Bits, v6: c.IPv6Bits, max: c.MaxBuckets, store: c.Principals, now: c.Now,
		buckets: map[bucketKey]*bucket{}, special: map[specialKey]*bucket{}}, nil
}

// AllowIP meters against the floor and, for anonymous and auth, the class row. Both must have a
// token; no token is taken unless both do.
func (l *Limiter) AllowIP(_ context.Context, class, ip string) (apihost.Decision, error) {
	if _, ok := ipClasses[class]; !ok {
		if _, ok := principalClasses[class]; !ok {
			return apihost.Decision{}, fmt.Errorf("%w: %q", ErrUnknownClass, class)
		}
	}
	prefix, parsed := ipKey(ip, l.v4, l.v6)
	scopes := []struct {
		scope string
		lim   Limit
	}{{floorScope, floor}}
	if lim, ok := ipClasses[class]; ok {
		scopes = append(scopes, struct {
			scope string
			lim   Limit
		}{class, lim})
	}
	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()
	bs := make([]*bucket, len(scopes))
	for i, s := range scopes {
		bs[i] = l.find(now, s.scope, prefix, parsed, s.lim)
	}
	var wait time.Duration
	for i, s := range scopes {
		refill(bs[i], s.lim, now)
		if bs[i].tokens < 1 {
			wait = max(wait, retryAfter(bs[i].tokens, s.lim))
		}
	}
	if wait > 0 {
		return apihost.Decision{RetryAfter: wait}, nil
	}
	for _, b := range bs {
		b.tokens--
	}
	return apihost.Decision{Allowed: true}, nil
}

// find returns the bucket for a key: the key's own, a new one, or when the table is full the
// scope's shared overflow bucket. An unparseable source gets the scope's single shared bucket.
func (l *Limiter) find(now time.Time, scope, prefix string, parsed bool, lim Limit) *bucket {
	if !parsed {
		return l.shared(specialKey{scope: scope}, lim, now)
	}
	k := bucketKey{scope, prefix}
	if b, ok := l.buckets[k]; ok {
		return b
	}
	if len(l.buckets) >= l.max {
		l.sweep(now)
	}
	if len(l.buckets) >= l.max {
		return l.shared(specialKey{scope: scope, overflow: true}, lim, now)
	}
	b := &bucket{tokens: float64(lim.Burst), at: now}
	l.buckets[k] = b
	return b
}

func (l *Limiter) shared(k specialKey, lim Limit, now time.Time) *bucket {
	b, ok := l.special[k]
	if !ok {
		b = &bucket{tokens: float64(lim.Burst), at: now}
		l.special[k] = b
	}
	return b
}

// sweep evicts buckets that have refilled to their burst: they carry no state. It runs at most once
// a second, so a flood of new keys cannot turn every request into a full scan.
func (l *Limiter) sweep(now time.Time) {
	if now.Sub(l.lastSweep) < time.Second {
		return
	}
	l.lastSweep = now
	for k, b := range l.buckets {
		lim := floor
		if c, ok := ipClasses[k.scope]; ok {
			lim = c
		}
		refill(b, lim, now)
		if b.tokens >= float64(lim.Burst) {
			delete(l.buckets, k)
		}
	}
}

func refill(b *bucket, lim Limit, now time.Time) {
	if d := now.Sub(b.at); d > 0 {
		b.tokens = math.Min(float64(lim.Burst), b.tokens+d.Seconds()*float64(lim.Rate)/60)
		b.at = now
	}
}

// retryAfter is the time until the bucket holds one token, never zero for a refused request.
func retryAfter(tokens float64, lim Limit) time.Duration {
	d := time.Duration(math.Ceil((1 - tokens) / (float64(lim.Rate) / 60) * float64(time.Second)))
	return max(d, time.Millisecond)
}

// AllowPrincipal meters against the principal's bucket in the shared store. The key is the class and
// the principal ID, which is the human behind a token (§7.8), so tokens do not multiply a budget.
func (l *Limiter) AllowPrincipal(ctx context.Context, class string, p apihost.Principal) (apihost.Decision, error) {
	lim, ok := principalClasses[class]
	if !ok {
		return apihost.Decision{}, fmt.Errorf("%w: %q", ErrUnknownClass, class)
	}
	if p.ID == "" {
		return apihost.Decision{}, errors.New("limiter: principal has no ID")
	}
	d, err := l.store.Take(ctx, class+"\x00"+p.ID, lim)
	if err != nil {
		return apihost.Decision{}, fmt.Errorf("limiter: principal store: %w", err)
	}
	return d, nil
}

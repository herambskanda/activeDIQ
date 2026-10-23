package fleetsql

import (
	"context"
	"errors"
	"math"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// FailureLimiter meters redeem attempts per source (TM-TB6-T1). Admit is asked before the token is
// looked at, so a refusal never depends on whether the token exists. Admit reserves a try
// atomically with the check, so concurrent attempts cannot all pass before any is charged; Succeeded
// refunds the try when the redeem worked, so a legitimate enrolment costs nothing. A shared-store
// implementation must reserve atomically too (INCR or a Lua script), never read then write.
type FailureLimiter interface {
	// Admit charges source one try and reports ok, or reports how long until it has a try again.
	Admit(ctx context.Context, source string) (retryAfter time.Duration, ok bool, err error)
	// Succeeded refunds the try Admit charged for a redeem that succeeded.
	Succeeded(ctx context.Context, source string)
}

// MemoryLimiterConfig sets the budget. Zero values take the defaults: 5 failures, then one more try
// every 30 seconds, at most 100000 sources remembered.
type MemoryLimiterConfig struct {
	Burst      int
	Refill     time.Duration // time to regain one try
	MaxSources int
	Now        func() time.Time // tests only
}

type fail struct {
	spent float64
	at    time.Time
}

// MemoryLimiter is a per-node FailureLimiter. The source is reduced to a network prefix (IPv4 /32,
// IPv6 /64; an unreadable source is an error, never a shared bucket) so one attacker cannot mint a bucket per
// address of a /64, and a full table sends new sources to one shared overflow bucket that is
// throttled rather than admitted. It is deliberately per node: a shared-store variant implements the
// same port when the gateway is clustered.
type MemoryLimiter struct {
	cfg MemoryLimiterConfig
	mu  sync.Mutex
	m   map[string]*fail
}

// NewMemoryLimiter returns a limiter with cfg's defaults filled in.
func NewMemoryLimiter(cfg MemoryLimiterConfig) *MemoryLimiter {
	if cfg.Burst <= 0 {
		cfg.Burst = 5
	}
	if cfg.Refill <= 0 {
		cfg.Refill = 30 * time.Second
	}
	if cfg.MaxSources <= 0 {
		cfg.MaxSources = 100000
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &MemoryLimiter{cfg: cfg, m: map[string]*fail{}}
}

const overflowKey = "*"

var errUnreadableSource = errors.New("fleetsql: source address is not an IP address")

// sourceKey reduces a peer address to its bucket: IPv4 /32, IPv6 /64. It accepts a bare address or
// the ip:port (bracketed for IPv6) form that net/http and gRPC report. An address it cannot read has
// no bucket: sharing one would let any anonymous caller throttle every other.
func sourceKey(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	a, err := netip.ParseAddr(raw)
	if err != nil {
		ap, perr := netip.ParseAddrPort(raw)
		if perr != nil {
			return "", false
		}
		a = ap.Addr()
	}
	a = a.WithZone("").Unmap()
	bits := 64
	if a.Is4() {
		bits = 32
	}
	p, err := a.Prefix(bits)
	if err != nil {
		return "", false
	}
	return p.Masked().String(), true
}

// bucket returns the entry for key, decayed to now. Caller holds mu.
func (l *MemoryLimiter) bucket(key string, now time.Time) *fail {
	b, ok := l.m[key]
	if !ok {
		if len(l.m) >= l.cfg.MaxSources {
			l.sweep(now)
		}
		if len(l.m) >= l.cfg.MaxSources {
			key = overflowKey
			b = l.m[key]
		}
		if b == nil {
			b = &fail{at: now}
			l.m[key] = b
		}
	}
	if d := now.Sub(b.at); d > 0 {
		b.spent = math.Max(0, b.spent-float64(d)/float64(l.cfg.Refill))
		b.at = now
	}
	return b
}

// sweep drops sources that have fully recovered: they carry no state.
func (l *MemoryLimiter) sweep(now time.Time) {
	for k, b := range l.m {
		if float64(now.Sub(b.at))/float64(l.cfg.Refill) >= b.spent {
			delete(l.m, k)
		}
	}
}

// Admit implements FailureLimiter.
func (l *MemoryLimiter) Admit(_ context.Context, source string) (time.Duration, bool, error) {
	key, ok := sourceKey(source)
	if !ok {
		return 0, false, errUnreadableSource
	}
	now := l.cfg.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.bucket(key, now)
	// A try is admitted only while a whole try is in hand: spent <= Burst-1. Admitting charges it
	// under the same lock, capped at Burst, so a source that has used its budget needs one full
	// Refill to earn the next try; the continuous decay between calls cannot slip it under the line.
	if over := b.spent - float64(l.cfg.Burst-1); over > 0 {
		wait := time.Duration(math.Ceil(over * float64(l.cfg.Refill)))
		return max(wait, time.Millisecond), false, nil
	}
	b.spent = math.Min(b.spent+1, float64(l.cfg.Burst))
	return 0, true, nil
}

// Succeeded implements FailureLimiter.
func (l *MemoryLimiter) Succeeded(_ context.Context, source string) {
	key, ok := sourceKey(source)
	if !ok {
		return
	}
	now := l.cfg.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.m[key]; !ok {
		return
	}
	b := l.bucket(key, now)
	b.spent = math.Max(0, b.spent-1)
}

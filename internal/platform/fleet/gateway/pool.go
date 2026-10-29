package gateway

import (
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"math/rand/v2"
	"sync/atomic"
	"time"
)

// The gateway's ClientCAs pool (fleet-contract 'Gateway client-CA pool', T-0712/T-0714). It is a first
// gate: a leaf from a forged or unknown CA is refused in memory before any database work. It is never
// the authority; every RPC still checks the leaf against the SAN tenant's own CAs (TM-Q8).

// Pool timing (F-POOL-5). The worst case for a CA withdrawn at commit is DefaultPoolInterval plus
// DefaultPoolTimeout: a refresh whose query started just before the commit misses it, and the next one
// starts at most one interval later and may run for the whole timeout.
const (
	DefaultPoolInterval = 10 * time.Second
	DefaultPoolTimeout  = 5 * time.Second
	// DefaultPoolStale is how long the pool survives without a successful refresh. After it the pool is
	// empty and client certificates are refused until the database answers (fail closed).
	DefaultPoolStale = 60 * time.Second
	// poolJitter is the fraction of the interval that is taken off, never added: the interval is
	// uniform in [0.8, 1.0] times the configured one, so it never exceeds it.
	poolJitter = 0.2
)

// PoolConfig configures a PoolProvider.
type PoolConfig struct {
	// Load returns every CA certificate that may sign a client certificate: all tenants, active and
	// retired. It must return only certificates it has validated; an error keeps the previous pool.
	Load     func(ctx context.Context) ([]*x509.Certificate, error)
	Interval time.Duration // 0: DefaultPoolInterval
	Timeout  time.Duration // 0: DefaultPoolTimeout
	Stale    time.Duration // 0: DefaultPoolStale
	Logger   *slog.Logger  // nil: slog.Default()
	Clock    func() time.Time
	// Rand returns a number in [0,1); tests only.
	Rand func() float64
}

// PoolProvider serves the immutable client-CA pool and keeps it fresh.
type PoolProvider struct {
	load     func(context.Context) ([]*x509.Certificate, error)
	interval time.Duration
	timeout  time.Duration
	stale    time.Duration
	log      *slog.Logger
	now      func() time.Time
	rnd      func() float64
	cur      atomic.Pointer[poolState]
	kick     chan struct{}
}

type poolState struct {
	pool *CAIndex
	at   time.Time // when the load that produced it succeeded
}

var emptyPool = NewCAIndex(nil)

// ErrPoolConfig is returned by NewPoolProvider when there is no loader.
var ErrPoolConfig = errors.New("fleet: client CA pool provider is not configured")

// NewPoolProvider returns a provider whose pool is empty until the first successful Refresh.
func NewPoolProvider(cfg PoolConfig) (*PoolProvider, error) {
	if cfg.Load == nil {
		return nil, ErrPoolConfig
	}
	p := &PoolProvider{load: cfg.Load, interval: cfg.Interval, timeout: cfg.Timeout, stale: cfg.Stale,
		log: cfg.Logger, now: cfg.Clock, rnd: cfg.Rand, kick: make(chan struct{}, 1)}
	if p.interval <= 0 {
		p.interval = DefaultPoolInterval
	}
	if p.timeout <= 0 {
		p.timeout = DefaultPoolTimeout
	}
	if p.stale <= 0 {
		p.stale = DefaultPoolStale
	}
	if p.log == nil {
		p.log = slog.Default()
	}
	if p.now == nil {
		p.now = time.Now
	}
	if p.rnd == nil {
		p.rnd = rand.Float64
	}
	return p, nil
}

// Pool returns the current pool. It never blocks and never touches the database. Without a successful
// refresh in the last Stale period it is empty.
func (p *PoolProvider) Pool() *CAIndex {
	s := p.cur.Load()
	if s == nil || p.now().Sub(s.at) > p.stale {
		return emptyPool
	}
	return s.pool
}

// Staleness is the time since the last successful refresh (for the metric and alert); a provider that
// never refreshed reports a negative duration.
func (p *PoolProvider) Staleness() time.Duration {
	s := p.cur.Load()
	if s == nil {
		return -1
	}
	return p.now().Sub(s.at)
}

// Refresh loads the anchors once under the query timeout and swaps the pool. On failure the previous
// pool stays (until it goes stale) and the error is returned.
func (p *PoolProvider) Refresh(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	certs, err := p.load(ctx)
	if err != nil {
		return err
	}
	p.cur.Store(&poolState{pool: NewCAIndex(certs), at: p.now()})
	return nil
}

// Invalidate asks for a refresh now. The process that commits a rollover, withdrawal or tenant
// provision calls it. It never blocks; a request made while a refresh runs causes one more refresh
// after it, because the running query may have started before the commit.
func (p *PoolProvider) Invalidate() {
	select {
	case p.kick <- struct{}{}:
	default:
	}
}

// next is the wait before the following refresh: uniform in [0.8, 1.0] of the interval.
func (p *PoolProvider) next() time.Duration {
	return time.Duration(float64(p.interval) * (1 - poolJitter*p.rnd()))
}

// Run refreshes immediately, then on the jittered interval and on Invalidate, until ctx ends. A failed
// refresh is logged without the error text beyond its type: it can carry connection details.
func (p *PoolProvider) Run(ctx context.Context) {
	for {
		if err := p.Refresh(ctx); err != nil && ctx.Err() == nil {
			p.log.Error("fleet: client CA pool refresh failed", slog.String("error_type", errKind(err)), slog.Duration("staleness", p.Staleness()))
		}
		t := time.NewTimer(p.next())
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-p.kick:
			t.Stop()
		case <-t.C:
		}
	}
}

func errKind(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	default:
		return "load"
	}
}

// CAIndex is the immutable set of client CAs, indexed by SubjectKeyId. Every fleet CA carries the one
// constant subject (F-POOL-6), so the subject cannot select a candidate and a flat x509.CertPool would
// try up to 100 same-subject CAs per chain, each a signature check, for an attacker-supplied leaf.
// Selecting by the leaf's AuthorityKeyId bounds that to the CAs that really share a key id.
type CAIndex struct {
	bySKID map[string][]*x509.Certificate
}

// NewCAIndex indexes certs. A CA without a SubjectKeyId cannot be selected and so never verifies a leaf.
func NewCAIndex(certs []*x509.Certificate) *CAIndex {
	ix := &CAIndex{bySKID: make(map[string][]*x509.Certificate, len(certs))}
	for _, c := range certs {
		if c != nil && len(c.SubjectKeyId) > 0 {
			ix.bySKID[string(c.SubjectKeyId)] = append(ix.bySKID[string(c.SubjectKeyId)], c)
		}
	}
	return ix
}

// candidates are the CAs whose SubjectKeyId equals the leaf's AuthorityKeyId; none if the leaf names none.
func (ix *CAIndex) candidates(leaf *x509.Certificate) []*x509.Certificate {
	if ix == nil || len(leaf.AuthorityKeyId) == 0 {
		return nil
	}
	return ix.bySKID[string(leaf.AuthorityKeyId)]
}

// errNoIssuer is returned, without any signature check, for a leaf whose issuer key id is absent or unknown.
var errNoIssuer = errors.New("fleet: client certificate issuer is not a known CA")

// verify builds the chain for a client leaf: directly under an indexed CA, ClientAuth EKU, valid now.
func (ix *CAIndex) verify(leaf *x509.Certificate, at time.Time) ([][]*x509.Certificate, error) {
	cands := ix.candidates(leaf)
	if len(cands) == 0 {
		return nil, errNoIssuer
	}
	roots := x509.NewCertPool()
	for _, c := range cands {
		roots.AddCert(c)
	}
	return leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: at})
}

// Contains reports whether c is in the index.
func (ix *CAIndex) Contains(c *x509.Certificate) bool {
	for _, k := range ix.bySKID[string(c.SubjectKeyId)] {
		if k.Equal(c) {
			return true
		}
	}
	return false
}

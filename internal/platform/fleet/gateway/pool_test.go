package gateway_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	"github.com/skenzeriq/activediq/internal/platform/fleet/gateway"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// loader is a mutable anchor source.
type loader struct {
	mu    sync.Mutex
	certs []*x509.Certificate
	err   error
	calls atomic.Int32
}

func (l *loader) set(certs ...*x509.Certificate) {
	l.mu.Lock()
	l.certs, l.err = certs, nil
	l.mu.Unlock()
}
func (l *loader) fail(err error) { l.mu.Lock(); l.err = err; l.mu.Unlock() }
func (l *loader) load(context.Context) ([]*x509.Certificate, error) {
	l.calls.Add(1)
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.certs, l.err
}

func inPool(p *x509.CertPool, c *x509.Certificate) bool {
	_, err := c.Verify(x509.VerifyOptions{Roots: p, CurrentTime: time.Now()})
	return err == nil
}

// F-POOL-5: freshness bound, fail-closed staleness, recovery without a restart.
func TestPoolProviderFreshnessAndStaleness(t *testing.T) {
	a, b := newCA(t, time.Now().Add(time.Hour)), newCA(t, time.Now().Add(time.Hour))
	clk := &fakeClock{t: time.Now()}
	l := &loader{}
	l.set(a.cert, b.cert)
	p, err := gateway.NewPoolProvider(gateway.PoolConfig{Load: l.load, Clock: clk.now})
	if err != nil {
		t.Fatal(err)
	}
	if inPool(p.Pool(), a.cert) {
		t.Fatal("pool is populated before the first refresh")
	}
	if err := p.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !inPool(p.Pool(), a.cert) || !inPool(p.Pool(), b.cert) {
		t.Fatal("both tenants' CAs belong in the pool")
	}
	// Withdrawal: gone after the next refresh.
	l.set(b.cert)
	clk.add(10 * time.Second)
	if err := p.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if inPool(p.Pool(), a.cert) || !inPool(p.Pool(), b.cert) {
		t.Fatal("withdrawn CA must leave the pool and the other tenant stay")
	}
	// Failing refreshes keep the last pool for 60 s, then the pool is empty.
	l.fail(errors.New("db down"))
	clk.add(30 * time.Second)
	if err := p.Refresh(context.Background()); err == nil {
		t.Fatal("expected the refresh to fail")
	}
	if !inPool(p.Pool(), b.cert) {
		t.Fatal("pool dropped before the staleness bound")
	}
	clk.add(31 * time.Second)
	if inPool(p.Pool(), b.cert) {
		t.Fatal("no successful refresh for 60 s must give an empty pool")
	}
	// Recovery on the next success.
	l.set(a.cert, b.cert)
	if err := p.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !inPool(p.Pool(), a.cert) || !inPool(p.Pool(), b.cert) {
		t.Fatal("pool did not recover")
	}
}

func TestPoolRefreshHonoursTimeoutAndJitterNeverExceedsInterval(t *testing.T) {
	p, err := gateway.NewPoolProvider(gateway.PoolConfig{
		Load:    func(ctx context.Context) ([]*x509.Certificate, error) { <-ctx.Done(); return nil, ctx.Err() },
		Timeout: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := p.Refresh(context.Background()); !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > time.Second {
		t.Fatalf("refresh = %v after %v", err, time.Since(start))
	}
	for _, r := range []float64{0, 0.5, 0.999999} {
		r := r
		q, _ := gateway.NewPoolProvider(gateway.PoolConfig{Load: func(context.Context) ([]*x509.Certificate, error) { return nil, nil }, Rand: func() float64 { return r }})
		d := q.NextForTest()
		if d > gateway.DefaultPoolInterval || d < 8*time.Second-time.Millisecond {
			t.Fatalf("interval %v for r=%v outside [8s,10s]", d, r)
		}
	}
	if _, err := gateway.NewPoolProvider(gateway.PoolConfig{}); !errors.Is(err, gateway.ErrPoolConfig) {
		t.Fatalf("no loader: %v", err)
	}
}

// Run refreshes at once, on Invalidate (also when a refresh is in flight), and stops with its context.
func TestPoolRunInvalidate(t *testing.T) {
	a := newCA(t, time.Now().Add(time.Hour))
	l := &loader{}
	p, _ := gateway.NewPoolProvider(gateway.PoolConfig{Load: l.load, Interval: time.Hour})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()
	waitFor(t, "first refresh", func() bool { return l.calls.Load() == 1 })
	l.set(a.cert)
	p.Invalidate()
	waitFor(t, "invalidate refresh", func() bool { return inPool(p.Pool(), a.cert) })
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop")
	}
}

// casMut is a mutable per-tenant CA source.
type casMut struct {
	mu  sync.Mutex
	m   map[tenant.ID][]*x509.Certificate
	err error
}

func (c *casMut) set(tid tenant.ID, cs ...*x509.Certificate) {
	c.mu.Lock()
	c.m[tid] = cs
	c.mu.Unlock()
}
func (c *casMut) fail(err error) { c.mu.Lock(); c.err = err; c.mu.Unlock() }
func (c *casMut) TenantCAs(_ context.Context, tid tenant.ID) ([]*x509.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.m[tid], c.err
}

// F-POOL-8: CloseTenant closes only that tenant's streams; a stream re-check drops a leaf whose CA was
// withdrawn (as on another node), leaves other tenants alone, and fails closed after CAStale.
func TestWithdrawnCAEndsStreams(t *testing.T) {
	const other = "66666666-7777-4888-8999-aaaaaaaaaaaa"
	nb, na, eku := time.Now().Add(-time.Minute), time.Now().Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	caA, caB, caA2 := newCA(t, na), newCA(t, na), newCA(t, na)
	tidA, tidB := tenant.New(), tenant.New()
	pool := x509.NewCertPool()
	pool.AddCert(caA.cert)
	pool.AddCert(caB.cert)
	pool.AddCert(caA2.cert)

	setup := func(t *testing.T, cas *casMut, opts ...func(*gateway.Config)) (*rig, []interface{ Close() error }, []chan error) {
		r := start(t, cas, pool, nil, opts...)
		r.fleet.hold.Store(true)
		la, la2, lb := caA.leaf(t, tidA, nb, na, eku), caA2.leafFor(t, tidA, other, nb, na, eku), caB.leaf(t, tidB, nb, na, eku)
		var errs []chan error
		for _, l := range []tls.Certificate{la, la2, lb} {
			l := l
			cc := r.dial(t, &l)
			errs = append(errs, recvErr(openTunnel(t, cc)))
		}
		waitFor(t, "three open streams", func() bool { return r.fleet.open.Load() == 3 })
		return r, nil, errs
	}
	expectEnded := func(t *testing.T, ch chan error, what string) {
		t.Helper()
		select {
		case err := <-ch:
			if code(err) != codes.Unauthenticated {
				t.Fatalf("%s ended with %v", what, err)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("%s stayed open", what)
		}
	}
	expectOpen := func(t *testing.T, ch chan error, what string) {
		t.Helper()
		select {
		case err := <-ch:
			t.Fatalf("%s ended: %v", what, err)
		case <-time.After(300 * time.Millisecond):
		}
	}

	t.Run("CloseTenant", func(t *testing.T) {
		cas := &casMut{m: map[tenant.ID][]*x509.Certificate{tidA: {caA.cert, caA2.cert}, tidB: {caB.cert}}}
		r, _, errs := setup(t, cas)
		if n := r.gw.CloseTenant(tidA); n != 2 {
			t.Fatalf("CloseTenant closed %d, want 2", n)
		}
		expectEnded(t, errs[0], "tenant A stream 1")
		expectEnded(t, errs[1], "tenant A stream 2")
		expectOpen(t, errs[2], "tenant B stream")
	})

	t.Run("recheck on another node", func(t *testing.T) {
		cas := &casMut{m: map[tenant.ID][]*x509.Certificate{tidA: {caA.cert, caA2.cert}, tidB: {caB.cert}}}
		_, _, errs := setup(t, cas)
		cas.set(tidA, caA2.cert) // caA withdrawn; its leaf is still valid
		expectEnded(t, errs[0], "withdrawn-CA stream")
		expectOpen(t, errs[1], "same tenant, other CA")
		expectOpen(t, errs[2], "tenant B stream")
	})

	t.Run("lookup failure fails closed after CAStale", func(t *testing.T) {
		cas := &casMut{m: map[tenant.ID][]*x509.Certificate{tidA: {caA.cert, caA2.cert}, tidB: {caB.cert}}}
		_, _, errs := setup(t, cas, func(c *gateway.Config) { c.CAStale = 400 * time.Millisecond })
		cas.fail(errors.New("db down"))
		expectOpen(t, errs[0], "stream during a short outage") // 300 ms < CAStale
		expectEnded(t, errs[0], "stream after CAStale")
	})
}

// F-POOL-7: a client handshake against a pool of 1,000 tenants x 8 CAs, all with the one subject.
// Budget: median under 50 ms. A failure here is the trigger for fallback option (d) (fleet-contract).
func TestPoolHandshakeAtScale(t *testing.T) {
	if testing.Short() {
		t.Skip("builds 8,000 CAs")
	}
	const tenants, perTenant = 1000, 8
	subj := pkix.Name{CommonName: "activeDIQ fleet CA", Organization: []string{"activeDIQ"}}
	pool := x509.NewCertPool()
	var real testCA
	for i := 0; i < tenants*perTenant; i++ {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 1)), Subject: subj,
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true, MaxPathLen: 0, MaxPathLenZero: true}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		pool.AddCert(c)
		if i == tenants*perTenant/2 {
			real = testCA{c, k}
		}
	}
	tid := tenant.New()
	leaf := real.leaf(t, tid, time.Now().Add(-time.Minute), time.Now().Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})

	r := start(t, casByTenant{tid: {real.cert}}, pool, nil)
	var durs []time.Duration
	for i := 0; i < 20; i++ {
		s := time.Now()
		cc := r.dial(t, &leaf)
		if err := callTunnel(cc); !errors.Is(err, io.EOF) { // EOF: the handler ran and returned
			t.Fatalf("handshake against the large pool: %v", err)
		}
		durs = append(durs, time.Since(s))
	}
	sortDurs(durs)
	med := durs[len(durs)/2]
	t.Logf("1,000 tenants x 8 CAs: median %v, max %v", med, durs[len(durs)-1])
	if med > 50*time.Millisecond {
		t.Fatalf("median handshake %v exceeds the 50 ms budget (F-POOL-7): fall back to option (d)", med)
	}
}

func sortDurs(d []time.Duration) {
	for i := 1; i < len(d); i++ {
		for j := i; j > 0 && d[j] < d[j-1]; j-- {
			d[j], d[j-1] = d[j-1], d[j]
		}
	}
}

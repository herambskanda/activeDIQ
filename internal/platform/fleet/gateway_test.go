package fleet_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/skenzeriq/activediq/internal/platform/fleet"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

const (
	tunnelMethod = "/activediq.fleet.v1.Fleet/Tunnel"
	compID       = "11111111-2222-4333-8444-555555555555"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newCA(t *testing.T, notAfter time.Time) testCA {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter,
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true, MaxPathLen: 0, MaxPathLenZero: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return testCA{c, k}
}

func (ca testCA) leaf(t *testing.T, tid tenant.ID, notBefore, notAfter time.Time, eku []x509.ExtKeyUsage) tls.Certificate {
	t.Helper()
	return ca.leafFor(t, tid, compID, notBefore, notAfter, eku)
}

func (ca testCA) leafFor(t *testing.T, tid tenant.ID, comp string, notBefore, notAfter time.Time, eku []x509.ExtKeyUsage) tls.Certificate {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "x"},
		NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: eku,
		URIs: fleet.URIs(tid, "connector", comp),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &k.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

type casByTenant map[tenant.ID][]*x509.Certificate

func (m casByTenant) TenantCAs(_ context.Context, tid tenant.ID) ([]*x509.Certificate, error) {
	return m[tid], nil
}

type failCAs struct{}

func (failCAs) TenantCAs(context.Context, tenant.ID) ([]*x509.Certificate, error) {
	return nil, errors.New("db down")
}

// fakeComps is the component lifecycle: every component is usable until it is revoked.
type fakeComps struct {
	mu      sync.Mutex
	revoked map[string]bool
	err     error
}

func (f *fakeComps) revoke(comp string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.revoked == nil {
		f.revoked = map[string]bool{}
	}
	f.revoked[comp] = true
}

func (f *fakeComps) Usable(_ context.Context, id fleet.Identity) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.err == nil && !f.revoked[id.ComponentID], f.err
}

type fakeFleet struct {
	calls  atomic.Int32
	lastID atomic.Value
	hold   atomic.Bool // stream handlers block until their context ends
	open   atomic.Int32
}

func (f *fakeFleet) desc(name string) *grpc.ServiceDesc {
	return &grpc.ServiceDesc{
		ServiceName: name, HandlerType: (*any)(nil),
		Methods: []grpc.MethodDesc{{MethodName: "Enroll", Handler: f.unary}},
		Streams: []grpc.StreamDesc{{StreamName: "Tunnel", Handler: f.stream, ServerStreams: true, ClientStreams: true}},
	}
}

func (f *fakeFleet) unary(_ any, ctx context.Context, dec func(any) error, ic grpc.UnaryServerInterceptor) (any, error) {
	in := new(emptypb.Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	h := func(ctx context.Context, _ any) (any, error) {
		f.calls.Add(1)
		if id, ok := fleet.IdentityFrom(ctx); ok {
			f.lastID.Store(id)
		}
		return &emptypb.Empty{}, nil
	}
	if ic == nil {
		return h(ctx, in)
	}
	return ic(ctx, in, &grpc.UnaryServerInfo{FullMethod: fleet.EnrollMethod}, h)
}

func (f *fakeFleet) stream(_ any, ss grpc.ServerStream) error {
	f.calls.Add(1)
	if id, ok := fleet.IdentityFrom(ss.Context()); ok {
		f.lastID.Store(id)
	}
	if f.hold.Load() {
		f.open.Add(1)
		defer f.open.Add(-1)
		<-ss.Context().Done()
		return ss.Context().Err()
	}
	return nil
}

var allMethods = map[string]fleet.AuthClass{fleet.EnrollMethod: fleet.ClassPublic, tunnelMethod: fleet.ClassClientCert}

type rig struct {
	addr  string
	fleet *fakeFleet
	pool  *x509.CertPool
	srv   *grpc.Server
	comps *fakeComps
	gw    *fleet.Gateway
}

func start(t *testing.T, cas fleet.TenantCAs, pool *x509.CertPool, now func() time.Time) *rig {
	t.Helper()
	comps := &fakeComps{}
	g, err := fleet.NewGateway(fleet.Config{Methods: allMethods, CAs: cas, Components: comps, Recheck: 50 * time.Millisecond, Clock: now})
	if err != nil {
		t.Fatal(err)
	}
	sk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "srv"}, DNSNames: []string{"localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &sk.PublicKey, sk)
	srvCert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: sk}
	ff := &fakeFleet{}
	srv, err := g.NewServer(srvCert, func() *x509.CertPool { return pool }, func(r grpc.ServiceRegistrar) {
		r.RegisterService(ff.desc("activediq.fleet.v1.Fleet"), ff)
	})
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(srv.Stop)
	return &rig{addr: l.Addr().String(), fleet: ff, pool: pool, srv: srv, comps: comps, gw: g}
}

func (r *rig) dial(t *testing.T, client *tls.Certificate) *grpc.ClientConn {
	t.Helper()
	conf := &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true} // test server cert is self-signed
	if client != nil {
		conf.Certificates = []tls.Certificate{*client}
	}
	cc, err := grpc.NewClient(r.addr, grpc.WithTransportCredentials(credentials.NewTLS(conf)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	return cc
}

func callEnroll(cc *grpc.ClientConn) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return cc.Invoke(ctx, fleet.EnrollMethod, &emptypb.Empty{}, &emptypb.Empty{})
}

func callTunnel(cc *grpc.ClientConn) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := cc.NewStream(ctx, &grpc.StreamDesc{StreamName: "Tunnel", ClientStreams: true, ServerStreams: true}, tunnelMethod)
	if err != nil {
		return err
	}
	_ = s.CloseSend()
	return s.RecvMsg(new(emptypb.Empty)) // io.EOF when the handler ran and returned nil
}

func code(err error) codes.Code { return status.Code(err) }

func TestNoCertificateOnlyEnrollWorks(t *testing.T) {
	ca := newCA(t, time.Now().Add(time.Hour))
	tid := tenant.New()
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	r := start(t, casByTenant{tid: {ca.cert}}, pool, nil)
	cc := r.dial(t, nil)

	if err := callTunnel(cc); code(err) != codes.Unauthenticated {
		t.Fatalf("stream without certificate: %v", err)
	}
	if r.fleet.calls.Load() != 0 {
		t.Fatal("handler ran for a stream without a certificate")
	}
	if err := callEnroll(cc); err != nil {
		t.Fatalf("Enroll without certificate must work: %v", err)
	}
	if r.fleet.calls.Load() != 1 {
		t.Fatal("Enroll handler did not run")
	}
}

func TestValidCertificateGivesIdentityFromSAN(t *testing.T) {
	ca := newCA(t, time.Now().Add(time.Hour))
	tid := tenant.New()
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	r := start(t, casByTenant{tid: {ca.cert}}, pool, nil)
	leaf := ca.leaf(t, tid, time.Now().Add(-time.Minute), time.Now().Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	if err := callTunnel(r.dial(t, &leaf)); err != nil && err.Error() != "EOF" {
		t.Fatalf("valid certificate refused: %v", err)
	}
	id, _ := r.fleet.lastID.Load().(fleet.Identity)
	if id.Tenant != tid || id.Kind != "connector" || id.ComponentID != compID {
		t.Fatalf("identity from context = %+v", id)
	}
}

func TestForeignOrExpiredCertificateRefused(t *testing.T) {
	ca := newCA(t, time.Now().Add(time.Hour))
	other := newCA(t, time.Now().Add(time.Hour))
	tid := tenant.New()
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	r := start(t, casByTenant{tid: {ca.cert}}, pool, nil)
	eku := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}

	foreign := other.leaf(t, tid, time.Now().Add(-time.Minute), time.Now().Add(time.Hour), eku)
	expired := ca.leaf(t, tid, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour), eku)
	for name, c := range map[string]tls.Certificate{"foreign CA": foreign, "expired": expired} {
		// Either the handshake or the interceptor refuses; the handler must not run either way.
		err := callTunnel(r.dial(t, &c))
		if err == nil || err.Error() == "EOF" {
			t.Fatalf("%s: stream accepted", name)
		}
	}
	if r.fleet.calls.Load() != 0 {
		t.Fatal("handler ran")
	}
}

func TestCertificateOutsideValidityRefusedByInterceptor(t *testing.T) {
	// The TLS layer would accept this chain; the interceptor's own clock check is the second wall.
	ca := newCA(t, time.Now().Add(3*time.Hour))
	tid := tenant.New()
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	r := start(t, casByTenant{tid: {ca.cert}}, pool, func() time.Time { return time.Now().Add(2 * time.Hour) })
	leaf := ca.leaf(t, tid, time.Now().Add(-time.Minute), time.Now().Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	if err := callTunnel(r.dial(t, &leaf)); code(err) != codes.Unauthenticated {
		t.Fatalf("expired by gateway clock: %v", err)
	}
}

func TestTenantBoundToIssuer(t *testing.T) {
	caA, caB := newCA(t, time.Now().Add(time.Hour)), newCA(t, time.Now().Add(time.Hour))
	tidA, tidB := tenant.New(), tenant.New()
	pool := x509.NewCertPool() // the listener trusts every tenant's CA
	pool.AddCert(caA.cert)
	pool.AddCert(caB.cert)
	r := start(t, casByTenant{tidA: {caA.cert}, tidB: {caB.cert}}, pool, nil)
	eku := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}

	// Signed by tenant A's CA, SAN names tenant B: the chain verifies, the binding must not.
	mint := caA.leaf(t, tidB, time.Now().Add(-time.Minute), time.Now().Add(time.Hour), eku)
	if err := callTunnel(r.dial(t, &mint)); code(err) != codes.Unauthenticated {
		t.Fatalf("cross-tenant leaf: %v", err)
	}
	if r.fleet.calls.Load() != 0 {
		t.Fatal("handler ran for a cross-tenant leaf")
	}
	ok := caB.leaf(t, tidB, time.Now().Add(-time.Minute), time.Now().Add(time.Hour), eku)
	if err := callTunnel(r.dial(t, &ok)); err != nil && err.Error() != "EOF" {
		t.Fatalf("own-tenant leaf refused: %v", err)
	}
}

func TestNoServerAuthOnlyLeafAndCALookupFailureRefused(t *testing.T) {
	ca := newCA(t, time.Now().Add(time.Hour))
	tid := tenant.New()
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	r := start(t, casByTenant{tid: {ca.cert}}, pool, nil)
	srvOnly := ca.leaf(t, tid, time.Now().Add(-time.Minute), time.Now().Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	if err := callTunnel(r.dial(t, &srvOnly)); err == nil || err.Error() == "EOF" {
		t.Fatalf("server-auth-only leaf accepted: %v", err)
	}

	r2 := start(t, failCAs{}, pool, nil)
	leaf := ca.leaf(t, tid, time.Now().Add(-time.Minute), time.Now().Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	if err := callTunnel(r2.dial(t, &leaf)); code(err) != codes.Unavailable {
		t.Fatalf("CA lookup failure must refuse: %v", err)
	}
}

func TestStartupFailsClosed(t *testing.T) {
	cas := casByTenant{}
	if _, err := fleet.NewGateway(fleet.Config{Methods: map[string]fleet.AuthClass{"/activediq.fleet.v1.Fleet/Other": fleet.ClassPublic}, CAs: cas, Components: &fakeComps{}}); !errors.Is(err, fleet.ErrPublicMethod) {
		t.Fatalf("public non-Enroll: %v", err)
	}
	if _, err := fleet.NewGateway(fleet.Config{Methods: map[string]fleet.AuthClass{tunnelMethod: 0}, CAs: cas, Components: &fakeComps{}}); !errors.Is(err, fleet.ErrUnclassified) {
		t.Fatalf("zero class: %v", err)
	}

	ff := &fakeFleet{}
	// Tunnel not classified.
	g, _ := fleet.NewGateway(fleet.Config{Methods: map[string]fleet.AuthClass{fleet.EnrollMethod: fleet.ClassPublic}, CAs: cas, Components: &fakeComps{}})
	if _, err := g.NewServer(tls.Certificate{Certificate: [][]byte{{1}}}, func() *x509.CertPool { return nil }, func(r grpc.ServiceRegistrar) { r.RegisterService(ff.desc("activediq.fleet.v1.Fleet"), ff) }); !errors.Is(err, fleet.ErrUnclassified) {
		t.Fatalf("unclassified method: %v", err)
	}
	// A non-fleet service on the fleet listener.
	g, _ = fleet.NewGateway(fleet.Config{Methods: map[string]fleet.AuthClass{fleet.EnrollMethod: fleet.ClassPublic, tunnelMethod: fleet.ClassClientCert,
		"/activediq.console.v1.Console/Enroll": fleet.ClassClientCert, "/activediq.console.v1.Console/Tunnel": fleet.ClassClientCert}, CAs: cas, Components: &fakeComps{}})
	if _, err := g.NewServer(tls.Certificate{Certificate: [][]byte{{1}}}, func() *x509.CertPool { return nil }, func(r grpc.ServiceRegistrar) { r.RegisterService(ff.desc("activediq.console.v1.Console"), ff) }); !errors.Is(err, fleet.ErrForeignMount) {
		t.Fatalf("foreign service: %v", err)
	}
}

func TestRoutesListOnlyFleet(t *testing.T) {
	ca := newCA(t, time.Now().Add(time.Hour))
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	r := start(t, casByTenant{}, pool, nil)
	got := fleet.Routes(r.srv)
	want := []string{fleet.EnrollMethod, tunnelMethod}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("routes = %v", got)
	}
}

func TestUnaryClientCertMethodRefusedWithoutPeer(t *testing.T) {
	g, err := fleet.NewGateway(fleet.Config{Methods: map[string]fleet.AuthClass{"/activediq.fleet.v1.Fleet/Other": fleet.ClassClientCert}, CAs: casByTenant{}, Components: &fakeComps{}})
	if err != nil {
		t.Fatal(err)
	}
	ran := false
	_, err = g.Unary(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/activediq.fleet.v1.Fleet/Other"},
		func(context.Context, any) (any, error) { ran = true; return nil, nil })
	if code(err) != codes.Unauthenticated || ran {
		t.Fatalf("err=%v ran=%v", err, ran)
	}
	// An unknown method is refused even though it is "public" nowhere.
	_, err = g.Unary(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/x.Y/Z"},
		func(context.Context, any) (any, error) { ran = true; return nil, nil })
	if code(err) != codes.PermissionDenied || ran {
		t.Fatalf("unknown method: err=%v ran=%v", err, ran)
	}
}

// A caller-supplied Creds option must not replace the gateway's mTLS (Enroll would be served in
// plaintext): a plaintext client cannot reach Enroll.
func TestCallerCredsCannotReplaceTLS(t *testing.T) {
	g, err := fleet.NewGateway(fleet.Config{Methods: allMethods, CAs: casByTenant{}, Components: &fakeComps{}})
	if err != nil {
		t.Fatal(err)
	}
	sk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "srv"}, DNSNames: []string{"localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &sk.PublicKey, sk)
	ff := &fakeFleet{}
	srv, err := g.NewServer(tls.Certificate{Certificate: [][]byte{der}, PrivateKey: sk}, func() *x509.CertPool { return nil },
		func(r grpc.ServiceRegistrar) { r.RegisterService(ff.desc("activediq.fleet.v1.Fleet"), ff) },
		grpc.Creds(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient(l.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := conn.Invoke(ctx, fleet.EnrollMethod, &emptypb.Empty{}, &emptypb.Empty{}); err == nil {
		t.Fatal("plaintext client reached Enroll")
	}
	if ff.calls.Load() != 0 {
		t.Fatal("handler ran over plaintext")
	}
}

func openTunnel(t *testing.T, cc *grpc.ClientConn) grpc.ClientStream {
	t.Helper()
	s, err := cc.NewStream(context.Background(), &grpc.StreamDesc{StreamName: "Tunnel", ClientStreams: true, ServerStreams: true}, tunnelMethod)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for end := time.Now().Add(3 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

func recvErr(s grpc.ClientStream) chan error {
	ch := make(chan error, 1)
	go func() { ch <- s.RecvMsg(new(emptypb.Empty)) }()
	return ch
}

// TestRevokedComponentRefusedAndStreamClosed covers T-0157 criteria 1-3: a revoked component with a
// valid certificate is refused on every RPC, its open stream is closed (at once through
// CloseComponent, and by the periodic re-check when the revocation happened elsewhere), and other
// components, in the same tenant or another, are unaffected.
func TestRevokedComponentRefusedAndStreamClosed(t *testing.T) {
	const other = "66666666-7777-4888-8999-aaaaaaaaaaaa"
	ca := newCA(t, time.Now().Add(time.Hour))
	tidA := tenant.New()
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	nb, na, eku := time.Now().Add(-time.Minute), time.Now().Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}

	for _, via := range []string{"close", "recheck"} {
		t.Run(via, func(t *testing.T) {
			r := start(t, casByTenant{tidA: {ca.cert}}, pool, nil)
			r.fleet.hold.Store(true)
			victim := ca.leaf(t, tidA, nb, na, eku)
			sibling := ca.leafFor(t, tidA, other, nb, na, eku)
			vs, ss := openTunnel(t, r.dial(t, &victim)), openTunnel(t, r.dial(t, &sibling))
			waitFor(t, "two open streams", func() bool { return r.fleet.open.Load() == 2 })
			verr, serr := recvErr(vs), recvErr(ss)

			r.comps.revoke(compID) // the Component row is revoked
			if via == "close" {
				if n := r.gw.CloseComponent(tidA, compID); n != 1 {
					t.Fatalf("CloseComponent closed %d streams, want 1", n)
				}
			}
			select {
			case err := <-verr:
				if code(err) != codes.Unauthenticated {
					t.Fatalf("revoked stream ended with %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("revoked component's stream stayed open")
			}
			select {
			case err := <-serr:
				t.Fatalf("sibling stream ended: %v", err)
			case <-time.After(300 * time.Millisecond):
			}
			if r.fleet.open.Load() < 1 {
				t.Fatal("sibling handler is gone")
			}

			// Re-establishing and any other RPC: refused with a certificate that is still valid.
			if err := callTunnel(r.dial(t, &victim)); code(err) != codes.Unauthenticated {
				t.Fatalf("revoked component re-established a stream: %v", err)
			}
		})
	}
}

// TestCloseComponentIsTenantScoped: the registry keys on tenant and component, so a component ID
// that also exists in another tenant is not closed.
func TestCloseComponentIsTenantScoped(t *testing.T) {
	ca := newCA(t, time.Now().Add(time.Hour))
	tidA, tidB := tenant.New(), tenant.New()
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	r := start(t, casByTenant{tidA: {ca.cert}, tidB: {ca.cert}}, pool, nil)
	r.fleet.hold.Store(true)
	nb, na, eku := time.Now().Add(-time.Minute), time.Now().Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	a, b := ca.leaf(t, tidA, nb, na, eku), ca.leaf(t, tidB, nb, na, eku)
	sa, sb := openTunnel(t, r.dial(t, &a)), openTunnel(t, r.dial(t, &b))
	waitFor(t, "two open streams", func() bool { return r.fleet.open.Load() == 2 })
	ea, eb := recvErr(sa), recvErr(sb)
	if n := r.gw.CloseComponent(tidA, compID); n != 1 {
		t.Fatalf("closed %d", n)
	}
	select {
	case <-ea:
	case <-time.After(2 * time.Second):
		t.Fatal("tenant A stream stayed open")
	}
	select {
	case err := <-eb:
		t.Fatalf("tenant B stream ended: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
}

func TestStatusLookupFailureRefused(t *testing.T) {
	ca := newCA(t, time.Now().Add(time.Hour))
	tid := tenant.New()
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	r := start(t, casByTenant{tid: {ca.cert}}, pool, nil)
	r.comps.err = errors.New("db down")
	leaf := ca.leaf(t, tid, time.Now().Add(-time.Minute), time.Now().Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	if err := callTunnel(r.dial(t, &leaf)); code(err) != codes.Unavailable {
		t.Fatalf("status failure must fail closed: %v", err)
	}
}

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
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
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
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "x"},
		NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: eku,
		URIs: fleet.URIs(tid, "connector", compID),
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

type fakeFleet struct {
	calls  atomic.Int32
	lastID atomic.Value
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
	return nil
}

var allMethods = map[string]fleet.AuthClass{fleet.EnrollMethod: fleet.ClassPublic, tunnelMethod: fleet.ClassClientCert}

type rig struct {
	addr  string
	fleet *fakeFleet
	pool  *x509.CertPool
	srv   *grpc.Server
}

func start(t *testing.T, cas fleet.TenantCAs, pool *x509.CertPool, now func() time.Time) *rig {
	t.Helper()
	g, err := fleet.NewGateway(fleet.Config{Methods: allMethods, CAs: cas, Clock: now})
	if err != nil {
		t.Fatal(err)
	}
	sk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "srv"}, DNSNames: []string{"localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &sk.PublicKey, sk)
	srvCert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: sk}
	ff := &fakeFleet{}
	srv, err := g.NewServer(fleet.ServerTLS(srvCert, func() *x509.CertPool { return pool }), func(r grpc.ServiceRegistrar) {
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
	return &rig{addr: l.Addr().String(), fleet: ff, pool: pool, srv: srv}
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
	if _, err := fleet.NewGateway(fleet.Config{Methods: map[string]fleet.AuthClass{"/activediq.fleet.v1.Fleet/Other": fleet.ClassPublic}, CAs: cas}); !errors.Is(err, fleet.ErrPublicMethod) {
		t.Fatalf("public non-Enroll: %v", err)
	}
	if _, err := fleet.NewGateway(fleet.Config{Methods: map[string]fleet.AuthClass{tunnelMethod: 0}, CAs: cas}); !errors.Is(err, fleet.ErrUnclassified) {
		t.Fatalf("zero class: %v", err)
	}

	tlsConf := &tls.Config{MinVersion: tls.VersionTLS13}
	ff := &fakeFleet{}
	// Tunnel not classified.
	g, _ := fleet.NewGateway(fleet.Config{Methods: map[string]fleet.AuthClass{fleet.EnrollMethod: fleet.ClassPublic}, CAs: cas})
	if _, err := g.NewServer(tlsConf, func(r grpc.ServiceRegistrar) { r.RegisterService(ff.desc("activediq.fleet.v1.Fleet"), ff) }); !errors.Is(err, fleet.ErrUnclassified) {
		t.Fatalf("unclassified method: %v", err)
	}
	// A non-fleet service on the fleet listener.
	g, _ = fleet.NewGateway(fleet.Config{Methods: map[string]fleet.AuthClass{fleet.EnrollMethod: fleet.ClassPublic, tunnelMethod: fleet.ClassClientCert,
		"/activediq.console.v1.Console/Enroll": fleet.ClassClientCert, "/activediq.console.v1.Console/Tunnel": fleet.ClassClientCert}, CAs: cas})
	if _, err := g.NewServer(tlsConf, func(r grpc.ServiceRegistrar) { r.RegisterService(ff.desc("activediq.console.v1.Console"), ff) }); !errors.Is(err, fleet.ErrForeignMount) {
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
	g, err := fleet.NewGateway(fleet.Config{Methods: map[string]fleet.AuthClass{"/activediq.fleet.v1.Fleet/Other": fleet.ClassClientCert}, CAs: casByTenant{}})
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

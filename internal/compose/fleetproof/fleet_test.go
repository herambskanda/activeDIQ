package fleetproof

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/skenzeriq/activediq/internal/platform/fleet"
	"github.com/skenzeriq/activediq/internal/platform/fleet/dial"
	"github.com/skenzeriq/activediq/internal/platform/fleet/fleetsql"
	"github.com/skenzeriq/activediq/internal/platform/fleet/gateway"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	fleetv1 "github.com/skenzeriq/activediq/internal/proto/activediq/fleet/v1"
)

// classes is the auth class of every method of the generated contract: Enroll public, everything
// else a client certificate. It is derived from the descriptor, so an RPC added to fleet.proto is
// covered by every test below without being listed.
func classes() map[string]gateway.AuthClass {
	m := map[string]gateway.AuthClass{}
	for _, md := range fleetv1.Fleet_ServiceDesc.Methods {
		m["/"+fleetv1.Fleet_ServiceDesc.ServiceName+"/"+md.MethodName] = gateway.ClassClientCert
	}
	for _, sd := range fleetv1.Fleet_ServiceDesc.Streams {
		m["/"+fleetv1.Fleet_ServiceDesc.ServiceName+"/"+sd.StreamName] = gateway.ClassClientCert
	}
	m[gateway.EnrollMethod] = gateway.ClassPublic
	return m
}

type cas map[tenant.ID][]*x509.Certificate

func (c cas) TenantCAs(_ context.Context, tid tenant.ID) ([]*x509.Certificate, error) {
	return c[tid], nil
}

type comps struct {
	mu      sync.Mutex
	revoked map[string]bool
}

func (c *comps) revoke(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.revoked == nil {
		c.revoked = map[string]bool{}
	}
	c.revoked[id] = true
}

func (c *comps) Usable(_ context.Context, id fleet.Identity) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.revoked[id.ComponentID], nil
}

func (c *comps) Current(ctx context.Context, id fleet.Identity) (bool, error) {
	return c.Usable(ctx, id)
}

// server is the fleet service the gateway fronts. Enroll signs the CSR for (tid, compID) with ca the
// way the real Enroller does; Tunnel holds the stream open until its context ends.
type server struct {
	fleetv1.UnimplementedFleetServer
	ca      authority // the tenant client CA
	srvCA   authority // the installation server CA: the pin, and the CA of the presented chain
	tid     tenant.ID
	enroll  atomic.Int32
	tunnel  atomic.Int32
	tunnels atomic.Int32 // open
}

func (s *server) Enroll(_ context.Context, r *fleetv1.EnrollRequest) (*fleetv1.EnrollResponse, error) {
	s.enroll.Add(1)
	csr, err := x509.ParseCertificateRequest(r.CsrDer)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "csr")
	}
	der := s.ca.sign(nil2t, &x509.Certificate{
		URIs:        fleet.URIs(s.tid, "connector", compID),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature,
	}, csr.PublicKey)
	return &fleetv1.EnrollResponse{
		LeafCertificateDer: der, CaBundlePem: append(pemOf(s.srvCA.cert), pemOf(s.ca.cert)...),
		Endpoints:    []*fleetv1.Endpoint{{Host: "fleet.example", Port: 8443}},
		LeafNotAfter: timestamppb.New(time.Now().Add(time.Hour)),
	}, nil
}

func (s *server) Tunnel(st grpc.BidiStreamingServer[fleetv1.TunnelFrame, fleetv1.TunnelFrame]) error {
	s.tunnel.Add(1)
	s.tunnels.Add(1)
	defer s.tunnels.Add(-1)
	<-st.Context().Done()
	return st.Context().Err()
}

// nil2t lets the server handler sign with the test's helper; set by rig.
var nil2t *testing.T

type rig struct {
	addr  string
	srv   *server
	comps *comps
	gw    *gateway.Gateway
	ca    authority // tenant client CA
	srvCA authority // installation server CA (ADR-0008)
	tid   tenant.ID
	grpc  *grpc.Server
}

func start(t *testing.T) *rig {
	t.Helper()
	nil2t = t
	ca := newAuthority(t, "tenant client CA")
	srvCA := newAuthority(t, "installation server CA")
	tid := tenant.New()
	cm := &comps{}
	gw, err := gateway.NewGateway(gateway.Config{
		Methods: classes(), CAs: cas{tid: {ca.cert}}, Components: cm, Recheck: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	pool := gateway.NewCAIndex([]*x509.Certificate{ca.cert})
	s := &server{ca: ca, srvCA: srvCA, tid: tid}
	gs, err := gw.NewServer(srvCA.serverCert(t), func() *gateway.CAIndex { return pool }, func(r grpc.ServiceRegistrar) {
		fleetv1.RegisterFleetServer(r, s)
	})
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = gs.Serve(l) }()
	t.Cleanup(gs.Stop)
	return &rig{addr: l.Addr().String(), srv: s, comps: cm, gw: gw, ca: ca, srvCA: srvCA, tid: tid, grpc: gs}
}

func (r *rig) conn(t *testing.T, client *tls.Certificate) *grpc.ClientConn {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(r.srvCA.cert)
	conf := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "localhost"}
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

func ctx5(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return c
}

// TestOnlyEnrollWorksWithoutAClientCertificate: TM-TB6-T8, TM-O2. Every RPC of the contract except
// Enroll is refused without a certificate, and its handler never runs.
func TestOnlyEnrollWorksWithoutAClientCertificate(t *testing.T) {
	r := start(t)
	cc := r.conn(t, nil)

	if err := cc.Invoke(ctx5(t), gateway.EnrollMethod, &fleetv1.EnrollRequest{}, &fleetv1.EnrollResponse{}); status.Code(err) == codes.Unauthenticated || status.Code(err) == codes.PermissionDenied {
		t.Fatalf("Enroll must work without a certificate, got %v", err)
	}
	if r.srv.enroll.Load() != 1 {
		t.Fatal("the Enroll handler did not run")
	}

	for name, class := range classes() {
		if class == gateway.ClassPublic {
			continue
		}
		var err error
		if name == "/activediq.fleet.v1.Fleet/Tunnel" {
			var s grpc.ClientStream
			s, err = cc.NewStream(ctx5(t), &grpc.StreamDesc{ClientStreams: true, ServerStreams: true}, name)
			if err == nil {
				err = s.RecvMsg(new(fleetv1.TunnelFrame))
			}
		} else {
			err = cc.Invoke(ctx5(t), name, &emptypb.Empty{}, &emptypb.Empty{})
		}
		if status.Code(err) != codes.Unauthenticated {
			t.Errorf("%s without a certificate: %v, want Unauthenticated", name, err)
		}
	}
	// Methods outside the contract are refused whatever the caller presents.
	for _, m := range []string{"/activediq.fleet.v1.Fleet/Other", "/grpc.health.v1.Health/Check", "/activediq.fleet.v1.Fleet/enroll"} {
		if err := cc.Invoke(ctx5(t), m, &emptypb.Empty{}, &emptypb.Empty{}); status.Code(err) != codes.Unimplemented && status.Code(err) != codes.PermissionDenied {
			t.Errorf("%s: %v, want a refusal (Unimplemented or PermissionDenied)", m, err)
		}
	}
	if r.srv.tunnel.Load() != 0 || r.srv.enroll.Load() != 1 {
		t.Fatalf("a handler other than Enroll ran: tunnel %d enroll %d", r.srv.tunnel.Load(), r.srv.enroll.Load())
	}
}

// TestCertificateFromAnotherCAOrTenantIsRefused: a certificate is not enough; it must be this
// tenant's own CA's.
func TestCertificateFromAnotherCAOrTenantIsRefused(t *testing.T) {
	r := start(t)
	rogue := newAuthority(t, "rogue CA")
	c := rogue.clientCert(t, r.tid, compID)
	cc := r.conn(t, &c)
	s, err := cc.NewStream(ctx5(t), &grpc.StreamDesc{ClientStreams: true, ServerStreams: true}, "/activediq.fleet.v1.Fleet/Tunnel")
	if err == nil {
		err = s.RecvMsg(new(fleetv1.TunnelFrame))
	}
	if err == nil || r.srv.tunnel.Load() != 0 {
		t.Fatalf("rogue-CA certificate reached the tunnel: %v", err)
	}
}

// TestGatewayRefusesToStartWithAPublicMethodOtherThanEnroll: deny by default is a startup rule.
func TestGatewayRefusesToStartWithAPublicMethodOtherThanEnroll(t *testing.T) {
	m := classes()
	m["/activediq.fleet.v1.Fleet/Tunnel"] = gateway.ClassPublic
	if _, err := gateway.NewGateway(gateway.Config{Methods: m, CAs: cas{}, Components: &comps{}}); !errors.Is(err, gateway.ErrPublicMethod) {
		t.Fatalf("public Tunnel: %v", err)
	}
	m = classes()
	delete(m, "/activediq.fleet.v1.Fleet/Tunnel")
	g, err := gateway.NewGateway(gateway.Config{Methods: m, CAs: cas{}, Components: &comps{}})
	if err != nil {
		t.Fatal(err)
	}
	ca := newAuthority(t, "ca")
	if _, err := g.NewServer(ca.serverCert(t), func() *gateway.CAIndex { return gateway.NewCAIndex(nil) }, func(r grpc.ServiceRegistrar) {
		fleetv1.RegisterFleetServer(r, &server{})
	}); !errors.Is(err, gateway.ErrUnclassified) {
		t.Fatalf("unclassified Tunnel mounted: %v", err)
	}
}

func exchange(ctx context.Context, creds credentials.TransportCredentials, addr, token string, csr []byte) (dial.Response, error) {
	cc, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return dial.Response{}, err
	}
	defer cc.Close()
	out, err := fleetv1.NewFleetClient(cc).Enroll(ctx, &fleetv1.EnrollRequest{EnrollmentToken: token, CsrDer: csr})
	if err != nil {
		return dial.Response{}, err
	}
	r := dial.Response{LeafDER: out.LeafCertificateDer, CABundlePEM: out.CaBundlePem}
	for _, e := range out.Endpoints {
		r.Endpoints = append(r.Endpoints, dial.Endpoint{Host: e.Host, Port: uint16(e.Port)})
	}
	return r, nil
}

// TestEnrollEndToEndThenRevocationKillsTheStream: the positive control and TM-TB6-T9. A component
// enrols through the real gateway with the real dial package, opens its tunnel, and loses it when
// revoked - at once through CloseComponent, and by recheck when revoked elsewhere - and cannot get a
// new one.
func TestEnrollEndToEndThenRevocationKillsTheStream(t *testing.T) {
	r := start(t)
	mat := dial.Material{Address: r.addr, Token: "tok", Pin: fleetsql.PinOf(r.srvCA.cert)}
	st, err := dial.Enroll(ctx5(t), mat, filepath.Join(t.TempDir(), "state"), exchange)
	if err != nil {
		t.Fatalf("enrol with the right pin: %v", err)
	}

	open := func() (grpc.ClientStream, chan error) {
		cc, err := dial.DialOut(r.addr, st)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cc.Close() })
		s, err := cc.NewStream(context.Background(), &grpc.StreamDesc{ClientStreams: true, ServerStreams: true}, "/activediq.fleet.v1.Fleet/Tunnel")
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- s.RecvMsg(new(fleetv1.TunnelFrame)) }()
		return s, done
	}
	waitOpen := func(n int32) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for r.srv.tunnels.Load() != n {
			if time.Now().After(deadline) {
				t.Fatalf("open tunnels = %d, want %d", r.srv.tunnels.Load(), n)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	wait := func(done chan error) error {
		select {
		case err := <-done:
			return err
		case <-time.After(5 * time.Second):
			t.Fatal("a revoked component kept its stream")
			return nil
		}
	}

	// Revoked through this instance: closed at once.
	_, done := open()
	waitOpen(1)
	r.comps.revoke(compID)
	if n := r.gw.CloseComponent(r.tid, compID); n != 1 {
		t.Fatalf("CloseComponent closed %d streams, want 1", n)
	}
	if code := status.Code(wait(done)); code != codes.Unauthenticated {
		t.Fatalf("revoked stream ended with %v, want Unauthenticated", code)
	}
	// And a revoked component, whose certificate is still valid, is refused a new one.
	_, done = open()
	if code := status.Code(wait(done)); code != codes.Unauthenticated {
		t.Fatalf("new stream of a revoked component: %v, want Unauthenticated", code)
	}
	if r.srv.tunnels.Load() != 0 {
		t.Fatal("a handler is still running for a revoked component")
	}
}

// TestRevocationElsewhereEndsTheStreamAtTheNextRecheck: no CloseComponent call (another instance
// made the revocation); the periodic check still ends the stream.
func TestRevocationElsewhereEndsTheStreamAtTheNextRecheck(t *testing.T) {
	r := start(t)
	c := r.ca.clientCert(t, r.tid, compID)
	cc := r.conn(t, &c)
	s, err := cc.NewStream(context.Background(), &grpc.StreamDesc{ClientStreams: true, ServerStreams: true}, "/activediq.fleet.v1.Fleet/Tunnel")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.RecvMsg(new(fleetv1.TunnelFrame)) }()
	deadline := time.Now().Add(5 * time.Second)
	for r.srv.tunnels.Load() != 1 {
		if time.Now().After(deadline) {
			t.Fatal("tunnel did not open")
		}
		time.Sleep(10 * time.Millisecond)
	}
	r.comps.revoke(compID)
	select {
	case err := <-done:
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("ended with %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a revoked component kept its stream past the recheck period")
	}
}

func nothingPersisted(t *testing.T, dir string) {
	t.Helper()
	if es, err := os.ReadDir(dir); err == nil && len(es) != 0 {
		t.Fatalf("enrolment persisted %d entries after a refusal", len(es))
	}
}

// TestComponentRefusesUnpinnedServers: TM-TB6-T2, TB6-T13(c), TB12-T2. A server the pinned CA did not
// sign never receives the token, and a connector never dials one out either.
func TestComponentRefusesUnpinnedServers(t *testing.T) {
	good := start(t) // the installation the component belongs to: it supplies the pin
	imposter := start(t)

	// The imposter has a certificate chain that verifies against its own CA but not the pin.
	dir := filepath.Join(t.TempDir(), "state")
	mat := dial.Material{Address: imposter.addr, Token: "secret-token", Pin: fleetsql.PinOf(good.srvCA.cert)}
	_, err := dial.Enroll(ctx5(t), mat, dir, exchange)
	if !errors.Is(err, dial.ErrUntrustedServer) {
		t.Fatalf("enrol against an unpinned server: %v, want ErrUntrustedServer", err)
	}
	if imposter.srv.enroll.Load() != 0 {
		t.Fatal("the enrollment token reached an unpinned server")
	}
	nothingPersisted(t, dir)

	// A malformed or absent pin never falls back to trusting the host roots.
	for _, pin := range []string{"", "sha256:", "sha256:zz", "md5:00"} {
		m := mat
		m.Pin = pin
		if _, err := dial.Enroll(ctx5(t), m, dir, exchange); err == nil {
			t.Fatalf("pin %q accepted", pin)
		}
	}
	if imposter.srv.enroll.Load() != 0 {
		t.Fatal("a token was sent with no valid pin")
	}

	// After enrolment the connector dials out only to the installation CA's servers.
	st, err := dial.Enroll(ctx5(t), dial.Material{Address: good.addr, Token: "tok", Pin: fleetsql.PinOf(good.srvCA.cert)}, filepath.Join(t.TempDir(), "ok"), exchange)
	if err != nil {
		t.Fatal(err)
	}
	cc, err := dial.DialOut(imposter.addr, st)
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	err = cc.Invoke(ctx5(t), "/activediq.fleet.v1.Fleet/Other", &emptypb.Empty{}, &emptypb.Empty{})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("dial-out to an unpinned server: %v, want Unavailable (certificate)", err)
	}
	if imposter.srv.tunnel.Load() != 0 {
		t.Fatal("a handler of an unpinned server ran")
	}
}

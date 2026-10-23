package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math/big"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/skenzeriq/activediq/internal/platform/fleet/fleetsql"
	fleetv1 "github.com/skenzeriq/activediq/internal/proto/activediq/fleet/v1"
)

type fakeBackend struct {
	source, token string
	rotated       *x509.Certificate
	err           error
}

func (f *fakeBackend) Enroll(_ context.Context, source, token string, _ []byte) (fleetsql.Enrolled, error) {
	f.source, f.token = source, token
	return fleetsql.Enrolled{LeafDER: []byte{1}, CABundlePEM: []byte("pem"), NotAfter: time.Unix(100, 0),
		Endpoints: []fleetsql.Endpoint{{Host: "h", Port: 1}}}, f.err
}

func (f *fakeBackend) Rotate(_ context.Context, leaf *x509.Certificate, _ []byte) (fleetsql.Enrolled, error) {
	f.rotated = leaf
	return fleetsql.Enrolled{LeafDER: []byte{2}, NotAfter: time.Unix(200, 0)}, f.err
}

func peerCtx(addr string, info credentials.AuthInfo) context.Context {
	tcp, _ := net.ResolveTCPAddr("tcp", addr)
	return peer.NewContext(context.Background(), &peer.Peer{Addr: tcp, AuthInfo: info})
}

func TestEnrollAdapterUsesTransportPeerAndFixedErrors(t *testing.T) {
	b := &fakeBackend{}
	s := &fleetEnrollService{backend: b}
	resp, err := s.Enroll(peerCtx("198.51.100.7:4444", nil), &fleetv1.EnrollRequest{EnrollmentToken: "tok", CsrDer: []byte{1}})
	if err != nil || b.source != "198.51.100.7:4444" || b.token != "tok" || resp.Endpoints[0].Port != 1 || resp.LeafNotAfter.AsTime().Unix() != 100 {
		t.Fatalf("resp %+v err %v backend %+v", resp, err, b)
	}
	for name, c := range map[string]struct {
		err  error
		code codes.Code
	}{
		"invalid":   {fleetsql.ErrTokenInvalid, codes.Unauthenticated},
		"rate":      {&fleetsql.RateLimitedError{RetryAfter: time.Minute}, codes.ResourceExhausted},
		"csr":       {fleetsql.ErrCSR, codes.InvalidArgument},
		"internal":  {errors.New("pq: password=hunter2 relation fleet_ca"), codes.Internal},
		"not-conf":  {fleetsql.ErrNotConfigured, codes.Internal},
		"rotate-no": {fleetsql.ErrRotateRefused, codes.Unauthenticated},
	} {
		b.err = c.err
		_, err := s.Enroll(peerCtx("198.51.100.7:4444", nil), &fleetv1.EnrollRequest{EnrollmentToken: "tok"})
		st, _ := status.FromError(err)
		if st.Code() != c.code || strings.Contains(st.Message(), "hunter2") || strings.Contains(st.Message(), "fleet_ca") {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// Oversize token or version: refused before the backend.
	b.token = ""
	if _, err := s.Enroll(peerCtx("198.51.100.7:1", nil), &fleetv1.EnrollRequest{EnrollmentToken: strings.Repeat("a", 300)}); err == nil || b.token != "" {
		t.Fatalf("oversize token reached the backend: %v", err)
	}
}

func TestEnrollAdapterRotateNeedsAVerifiedCertificate(t *testing.T) {
	b := &fakeBackend{}
	s := &fleetEnrollService{backend: b}
	// No token and no certificate: refused.
	if _, err := s.Enroll(peerCtx("198.51.100.7:4444", nil), &fleetv1.EnrollRequest{CsrDer: []byte{1}}); err == nil || b.rotated != nil {
		t.Fatalf("no token, no cert: %v", err)
	}
	cert := &x509.Certificate{URIs: []*url.URL{
		{Scheme: "urn", Opaque: "activediq:tenant:00000000-0000-4000-8000-000000000001"},
		{Scheme: "urn", Opaque: "activediq:component:agent:00000000-0000-4000-8000-000000000002"}},
		SerialNumber: bigOne()}
	// An unverified certificate (PeerCertificates only) is not an identity.
	unverified := credentials.TLSInfo{State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}}
	if _, err := s.Enroll(peerCtx("198.51.100.7:4444", unverified), &fleetv1.EnrollRequest{CsrDer: []byte{1}}); err == nil || b.rotated != nil {
		t.Fatalf("unverified certificate rotated: %v", err)
	}
	verified := credentials.TLSInfo{State: tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{cert}}}}
	if _, err := s.Enroll(peerCtx("198.51.100.7:4444", verified), &fleetv1.EnrollRequest{CsrDer: []byte{1}}); err != nil {
		t.Fatal(err)
	}
	if b.rotated != cert {
		t.Fatalf("Rotate did not get the VerifiedChains leaf: %+v", b.rotated)
	}
}

func bigOne() *big.Int { return big.NewInt(1) }

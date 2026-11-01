package main

import (
	"context"
	"crypto/x509"
	"net"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/skenzeriq/activediq/internal/platform/fleet"
	"github.com/skenzeriq/activediq/internal/platform/fleet/dial"
	fleetv1 "github.com/skenzeriq/activediq/internal/proto/activediq/fleet/v1"
)

// The stub is only useful as lab evidence if the real enrolment client accepts what it issues, and it must be
// single-use like a real token. Both are proved here with the production dial.Enroll.
func TestStubIssuesWhatTheRealClientAccepts(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint32(lis.Addr().(*net.TCPAddr).Port)
	s, tlsCfg, pin := newStub("127.0.0.1", port)
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsCfg)))
	fleetv1.RegisterFleetServer(srv, s)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	ex := func(ctx context.Context, creds credentials.TransportCredentials, addr, token string, csr []byte) (dial.Response, error) {
		conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
		if err != nil {
			return dial.Response{}, err
		}
		defer conn.Close()
		r, err := fleetv1.NewFleetClient(conn).Enroll(ctx, &fleetv1.EnrollRequest{EnrollmentToken: token, CsrDer: csr})
		if err != nil {
			return dial.Response{}, err
		}
		out := dial.Response{LeafDER: r.GetLeafCertificateDer(), CABundlePEM: r.GetCaBundlePem()}
		for _, e := range r.GetEndpoints() {
			out.Endpoints = append(out.Endpoints, dial.Endpoint{Host: e.GetHost(), Port: uint16(e.GetPort())})
		}
		return out, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))
	dir := filepath.Join(t.TempDir(), "enrol")
	st, err := dial.Enroll(ctx, dial.Material{Address: addr, Token: s.token, Pin: pin}, dir, ex)
	if err != nil {
		t.Fatalf("real client refused the stub's enrolment: %v", err)
	}
	leaf, err := x509.ParseCertificate(st.Leaf.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fleet.IdentityOf(leaf); err != nil {
		t.Fatal(err)
	}
	// Failing fixture: the token is single-use, and a wrong pin is refused before the token is sent.
	if _, err := dial.Enroll(ctx, dial.Material{Address: addr, Token: s.token, Pin: pin}, filepath.Join(t.TempDir(), "e2"), ex); err == nil {
		t.Fatal("stub accepted a used token")
	}
	badPin := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	if _, err := dial.Enroll(ctx, dial.Material{Address: addr, Token: "x", Pin: badPin}, filepath.Join(t.TempDir(), "e3"), ex); err == nil {
		t.Fatal("enrolled against a wrong pin")
	}
}

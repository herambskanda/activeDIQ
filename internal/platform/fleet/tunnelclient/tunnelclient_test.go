package tunnelclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/skenzeriq/activediq/internal/platform/fleet"
	"github.com/skenzeriq/activediq/internal/platform/fleet/dial"
)

func TestEndpointAddr(t *testing.T) {
	if got := endpointAddr(dial.Endpoint{Host: "fleet.example", Port: 8443}); got != "fleet.example:8443" {
		t.Fatal(got)
	}
	if got := endpointAddr(dial.Endpoint{Host: "::1", Port: 1}); got != "[::1]:1" {
		t.Fatal(got)
	}
}

// A Config without an opener fails closed: nothing is dialled-and-served without a wire binding.
func TestServeConnRequiresOpener(t *testing.T) {
	if err := serveConn(context.Background(), nil, Config{}, func() {}); err == nil {
		t.Fatal("served without an opener")
	}
}

func TestErrKindFromStatus(t *testing.T) {
	cases := map[string]error{
		"closed":        nil,
		"rejected":      status.Error(codes.Unauthenticated, "no"),
		"tls_trust":     status.Error(codes.Unavailable, "connection error: desc = \"transport: authentication handshake failed: tls: failed to verify certificate: x509: certificate signed by unknown authority\""),
		"tls_handshake": status.Error(codes.Unavailable, "connection error: desc = \"error reading server preface: remote error: tls: bad certificate\""),
		"resolve":       status.Error(codes.Unavailable, "dial tcp: lookup dc.example: no such host"),
		"unreachable":   status.Error(codes.Unavailable, "connection error: dial tcp 10.0.0.1:8443: connectex: connection refused"),
		"transport":     errors.New("boom"),
	}
	for want, err := range cases {
		if got := errKind(err); got != want {
			t.Errorf("errKind(%v) = %s, want %s", err, got, want)
		}
	}
	if got := errKind(&fleet.ProtocolError{}); got != "protocol" {
		t.Errorf("protocol: %s", got)
	}
}

// Real failures through a real gRPC client classify as the runbook says.
func TestErrKindRealDialFailures(t *testing.T) {
	probe := func(t *testing.T, addr string, creds credentials.TransportCredentials) error {
		t.Helper()
		conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return conn.Invoke(ctx, "/x.Y/Z", &emptypb.Empty{}, &emptypb.Empty{})
	}
	t.Run("refused", func(t *testing.T) {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := l.Addr().String()
		l.Close()
		if got := errKind(probe(t, addr, insecure.NewCredentials())); got != "unreachable" {
			t.Fatalf("got %s", got)
		}
	})
	t.Run("untrusted server certificate", func(t *testing.T) {
		srv := httptest.NewUnstartedServer(http.NotFoundHandler()) // its CA is not in the client's pool
		srv.EnableHTTP2 = true                                     // gRPC negotiates h2; without it the handshake fails earlier
		srv.StartTLS()
		defer srv.Close()
		creds := credentials.NewTLS(&tls.Config{RootCAs: x509.NewCertPool(), MinVersion: tls.VersionTLS13, ServerName: "example.test"})
		if got := errKind(probe(t, srv.Listener.Addr().String(), creds)); got != "tls_trust" {
			t.Fatalf("got %s", got)
		}
	})
}

// T-1249: the resource-limit burst window is opened for a connection attempt and closed exactly once
// when it fails, so a failed dial can never leave the process uncapped.
func TestBurstClosedOnceWhenDialFails(t *testing.T) {
	opened, closed := 0, 0
	c := Config{State: &dial.State{}, Burst: func() func() { opened++; return func() { closed++ } }}
	if err := serveOnce(context.Background(), c); err == nil {
		t.Fatal("served without endpoints")
	}
	if opened != 1 || closed != 1 {
		t.Fatalf("burst opened %d closed %d, want 1 and 1", opened, closed)
	}
}

// T-1249 security review: a peer that accepts the connection and then stalls (a tarpit, a dropped
// handshake) must not hold the set-up, and with it the Burst window, open past our own deadline.
func TestSetupTimeoutEndsAStalledStreamOpen(t *testing.T) {
	opened := 0
	stall := func(ctx context.Context, _ grpc.ClientConnInterface) (fleet.Transport, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	c := Config{Open: stall, SetupTimeout: 50 * time.Millisecond}
	start := time.Now()
	err := serveConn(context.Background(), nil, c, func() { opened++ })
	if !errors.Is(err, errSetupTimeout) {
		t.Fatalf("stalled open returned %v, want the set-up timeout", err)
	}
	if opened != 1 {
		t.Fatalf("the Burst window end ran %d times, want 1", opened)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("set-up deadline took %s", d)
	}
}

func TestSetupTimeoutDefaultIsBounded(t *testing.T) {
	if DefaultSetupTimeout <= 0 || DefaultSetupTimeout > 30*time.Second {
		t.Fatalf("DefaultSetupTimeout %s is not a short bounded value", DefaultSetupTimeout)
	}
}

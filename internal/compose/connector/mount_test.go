package connector_test

import (
	"context"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/skenzeriq/activediq/internal/compose/connector"
	"github.com/skenzeriq/activediq/internal/connector/rights"
	"github.com/skenzeriq/activediq/internal/connector/write"
	"github.com/skenzeriq/activediq/internal/platform/fleet"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	v1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

type nopBase struct{}

func (nopBase) Append(string, []write.Mark) error { return nil }

type stubDir struct{ rights.ADDirectory }

type wire struct {
	in   <-chan fleet.Frame
	out  chan<- fleet.Frame
	done chan struct{}
	once *sync.Once
}

func (w *wire) Send(f fleet.Frame) error {
	select {
	case w.out <- f:
		return nil
	case <-w.done:
		return io.ErrClosedPipe
	}
}

func (w *wire) Recv() (fleet.Frame, error) {
	select {
	case f := <-w.in:
		return f, nil
	case <-w.done:
		return fleet.Frame{}, io.EOF
	}
}

func newWires() (a, b *wire) {
	ab, ba, done, once := make(chan fleet.Frame, 128), make(chan fleet.Frame, 128), make(chan struct{}), new(sync.Once)
	return &wire{in: ba, out: ab, done: done, once: once}, &wire{in: ab, out: ba, done: done, once: once}
}

type rep struct{}

func (rep) ProtocolError(context.Context, fleet.Identity, fleet.Violation) error { return nil }

func handler(t *testing.T) *rights.VerifyHandler {
	t.Helper()
	gate, _ := write.NewGateBook(nopBase{}, nil)
	h, err := rights.NewVerifyHandler(rights.VerifyConfig{Dir: stubDir{}, Epoch: rights.NewEpochState(nil, nil, nil),
		Directory: &v1.DirectoryIdentity{}, Gate: gate, OnLocalRecordFailed: gate.CloseLocalRecordFailed})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// The server (RoleServer) opens VerifyConnection over a tunnel whose component side is the
// connector's TunnelBinding; a method outside the contract is refused at registration.
func TestTunnelBindingServesVerifyOverTunnel(t *testing.T) {
	if _, err := connector.TunnelBinding(nil); err == nil {
		t.Fatal("nil handler accepted")
	}
	bd, err := connector.TunnelBinding(handler(t))
	if err != nil {
		t.Fatal(err)
	}
	a, b := newWires()
	id := fleet.Identity{Tenant: tenant.New(), Kind: fleet.KindConnector, ComponentID: "11111111-1111-4111-8111-111111111111"}
	srv, err := fleet.NewMux(fleet.MuxConfig{Role: fleet.RoleServer, Identity: id, Transport: a, Reporter: rep{},
		Binding: fleet.Binding{Contract: bd.Contract}})
	if err != nil {
		t.Fatal(err)
	}
	comp, err := fleet.NewMux(fleet.MuxConfig{Role: fleet.RoleComponent, Identity: id, Transport: b, Binding: bd})
	if err != nil {
		t.Fatalf("component mux with the connector binding: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	var wg sync.WaitGroup
	for _, m := range []*fleet.Mux{srv, comp} {
		wg.Add(1)
		go func() { defer wg.Done(); _ = m.Run(ctx) }()
	}
	t.Cleanup(func() { cancel(); a.once.Do(func() { close(a.done) }); wg.Wait() })

	st, err := v1.NewConnectorClient(srv.Conn()).VerifyConnection(ctx, &v1.VerifyConnectionRequest{})
	if err == nil {
		_, err = st.Recv()
	}
	// The handler was reached: an empty request is its fixed INVALID_ARGUMENT, not UNIMPLEMENTED/UNAVAILABLE.
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("VerifyConnection over tunnel = %v, want InvalidArgument", err)
	}
	// A method the contract does not carry is not served by the component.
	err = srv.Conn().Invoke(ctx, "/grpc.health.v1.Health/Check", &v1.VerifyConnectionRequest{}, &v1.VerifyConnectionRequest{})
	if status.Code(err) == codes.OK || status.Code(err) == codes.InvalidArgument {
		t.Fatalf("method outside the contract was served: %v", err)
	}
}

// Guard (TM-TB6-T10, TM-F-PORTS): the connector composition root has no listener or process gRPC
// server of its own.
func TestNoListenerInConnectorComposition(t *testing.T) {
	banned := []string{"grpc.NewServer", "net.Listen", "credentials.NewTLS", "tls.Listen", "http.ListenAndServe", "ListenAndServe"}
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parser.ParseFile(token.NewFileSet(), f, src, parser.ParseComments); err != nil {
			t.Fatal(err)
		}
		for _, b := range banned {
			if strings.Contains(string(src), b) {
				t.Errorf("%s uses %s: the connector dials out only", f, b)
			}
		}
	}
}

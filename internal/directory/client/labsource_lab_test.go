//go:build lab

package client

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

type describeOnly struct {
	connectorv1.UnimplementedConnectorServer
}

func (describeOnly) Describe(context.Context, *connectorv1.DescribeRequest) (*connectorv1.DescribeResponse, error) {
	return &connectorv1.DescribeResponse{}, nil
}

type stubSource struct{ calls []string }

func (s *stubSource) Connector(_ context.Context, id string) (connectorv1.ConnectorClient, error) {
	s.calls = append(s.calls, id)
	return nil, errors.New("tunnel: not connected")
}

// An unknown connection with no next source is refused; with one, it falls through.
func TestLabSourceFallsThrough(t *testing.T) {
	if _, err := NewLabSource(nil).Connector(context.Background(), "x"); err == nil {
		t.Fatal("an unknown connection with no tunnel source must be refused")
	}
	next := &stubSource{}
	if _, err := NewLabSource(next).Connector(context.Background(), "y"); err == nil || len(next.calls) != 1 || next.calls[0] != "y" {
		t.Fatalf("fall-through: err=%v calls=%v", err, next.calls)
	}
	// A zero handle binds nothing: the connection still falls through.
	s := NewLabSource(next)
	s.Bind("z", LabConnector{})
	if _, err := s.Connector(context.Background(), "z"); err == nil {
		t.Fatal("a zero LabConnector must not be served")
	}
}

// A bound connection is served by the in-process connector over a real gRPC hop: an implemented RPC
// answers, an unimplemented one comes back as a gRPC status, and next is never asked.
func TestLabSourceServesInProcessConnector(t *testing.T) {
	if _, _, err := DialInProcess(nil); err == nil {
		t.Fatal("DialInProcess(nil) must fail")
	}
	lc, stop, err := DialInProcess(describeOnly{})
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	next := &stubSource{}
	s := NewLabSource(next)
	s.Bind("c1", lc)
	cl, err := s.Connector(context.Background(), "c1")
	if err != nil || cl == nil {
		t.Fatalf("Connector(c1) = %v, %v", cl, err)
	}
	if _, err := cl.Describe(context.Background(), &connectorv1.DescribeRequest{}); err != nil {
		t.Fatalf("Describe over the in-process hop: %v", err)
	}
	st, err := cl.Read(context.Background(), &connectorv1.ReadRequest{})
	if err == nil {
		_, err = st.Recv()
	}
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("an unserved RPC: err = %v, want Unimplemented", err)
	}
	if len(next.calls) != 0 {
		t.Fatalf("next asked for a bound connection: %v", next.calls)
	}
}

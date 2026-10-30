//go:build lab

package client

import (
	"context"
	"errors"
	"net"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// Lab connector plumbing (T-0684, T-0795), compiled only under the `lab` build tag. The generated
// connector-contract client is owned by this package (ADR-0005 O2): the lab bootstrap in
// internal/compose/server builds the connector's server side, and this file turns it into an
// in-process connector and a ConnectorSource without the client ever leaving this package. A
// LabConnector is an opaque handle, so a composition root can hold and bind one but cannot issue an
// RPC on it; every RPC still goes through this package's Read, Verify and Write.

// LabConnector is an in-process connector: a connector server reached over a real gRPC hop on an
// in-memory pipe (marshalling, status errors, streaming), never leaving the process.
type LabConnector struct {
	c connectorv1.ConnectorClient
}

// DialInProcess serves srv on an in-memory gRPC pipe and returns the connector and its closer.
func DialInProcess(srv connectorv1.ConnectorServer) (LabConnector, func(), error) {
	if srv == nil {
		return LabConnector{}, nil, errors.New("client: in-process connector needs a server")
	}
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	connectorv1.RegisterConnectorServer(gs, srv)
	go func() { _ = gs.Serve(lis) }()
	cc, err := grpc.NewClient("passthrough:///lab-connector",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		gs.Stop()
		return LabConnector{}, nil, errors.New("client: in-process connector dial")
	}
	return LabConnector{c: connectorv1.NewConnectorClient(cc)}, func() { _ = cc.Close(); gs.Stop() }, nil
}

// LabSource resolves the connections bound to an in-process connector and everything else to next
// (the fleet tunnel source).
type LabSource struct {
	mu   sync.RWMutex
	by   map[string]connectorv1.ConnectorClient
	next ConnectorSource
}

var _ ConnectorSource = (*LabSource)(nil)

// NewLabSource returns a source with no bound connection that falls through to next (nil: refuse).
func NewLabSource(next ConnectorSource) *LabSource {
	return &LabSource{by: map[string]connectorv1.ConnectorClient{}, next: next}
}

// Bind serves connectionID from c from now on.
func (s *LabSource) Bind(connectionID string, c LabConnector) {
	s.mu.Lock()
	s.by[connectionID] = c.c
	s.mu.Unlock()
}

// Connector implements ConnectorSource.
func (s *LabSource) Connector(ctx context.Context, connectionID string) (connectorv1.ConnectorClient, error) {
	s.mu.RLock()
	c, ok := s.by[connectionID]
	s.mu.RUnlock()
	if ok && c != nil {
		return c, nil
	}
	if s.next == nil {
		return nil, errors.New("client: no connector for connection")
	}
	return s.next.Connector(ctx, connectionID)
}

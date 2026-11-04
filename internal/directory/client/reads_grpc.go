package client

import (
	"context"
	"errors"

	"google.golang.org/grpc"

	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// ConnectorSource yields the generated connector client that serves one connection. The component
// that owns connector endpoints and their mutual-TLS dialling implements it; this package neither
// dials nor caches.
type ConnectorSource interface {
	Connector(ctx context.Context, connectionID string) (connectorv1.ConnectorClient, error)
}

// GRPCReadTransport is the ReadTransport over the generated Connector client.
type GRPCReadTransport struct{ src ConnectorSource }

var _ ReadTransport = GRPCReadTransport{}

// NewGRPCReadTransport returns the transport over src.
func NewGRPCReadTransport(src ConnectorSource) (GRPCReadTransport, error) {
	if src == nil {
		return GRPCReadTransport{}, errors.New("client: read transport needs a connector source")
	}
	return GRPCReadTransport{src: src}, nil
}

// Read implements ReadTransport.
func (t GRPCReadTransport) Read(ctx context.Context, req *connectorv1.ReadRequest) (ReadStream, error) {
	cc, err := t.src.Connector(ctx, req.GetConnection().GetConnectionId())
	if err != nil {
		return nil, err
	}
	return cc.Read(ctx, req)
}

// GRPCVerifyTransport is the VerifyTransport over the generated Connector client (contract §8.4).
type GRPCVerifyTransport struct{ src ConnectorSource }

var _ VerifyTransport = GRPCVerifyTransport{}

// NewGRPCVerifyTransport returns the transport over src.
func NewGRPCVerifyTransport(src ConnectorSource) (GRPCVerifyTransport, error) {
	if src == nil {
		return GRPCVerifyTransport{}, errors.New("client: verify transport needs a connector source")
	}
	return GRPCVerifyTransport{src: src}, nil
}

// VerifyConnection implements VerifyTransport. The connector is resolved by the request's
// connection id; the source refuses a connection it cannot route.
func (t GRPCVerifyTransport) VerifyConnection(ctx context.Context, req *connectorv1.VerifyConnectionRequest) (VerifyStream, error) {
	cc, err := t.src.Connector(ctx, req.GetConnection().GetConnectionId())
	if err != nil {
		return nil, err
	}
	return cc.VerifyConnection(ctx, req)
}

// GRPCPerDCTransport is the PerDCTransport over the generated Connector client.
type GRPCPerDCTransport struct{ src ConnectorSource }

var _ PerDCTransport = GRPCPerDCTransport{}

// NewGRPCPerDCTransport returns the transport over src.
func NewGRPCPerDCTransport(src ConnectorSource) (GRPCPerDCTransport, error) {
	if src == nil {
		return GRPCPerDCTransport{}, errors.New("client: per-DC transport needs a connector source")
	}
	return GRPCPerDCTransport{src: src}, nil
}

// ReadPerDC implements PerDCTransport.
func (t GRPCPerDCTransport) ReadPerDC(ctx context.Context, req *connectorv1.ReadPerDCRequest) (PerDCStream, error) {
	cc, err := t.src.Connector(ctx, req.GetConnection().GetConnectionId())
	if err != nil {
		return nil, err
	}
	return cc.ReadPerDC(ctx, req)
}

// ReadClient is the two read RPCs of the generated connector client that sync uses. It is a narrow
// interface, not an alias: a holder cannot reach Plan or Apply, so connector writes stay reachable only
// through Write, which needs a step.Step and a step.Clearance (ADR-0005 rule 2, O2).
type ReadClient interface {
	Describe(ctx context.Context, in *connectorv1.DescribeRequest, opts ...grpc.CallOption) (*connectorv1.DescribeResponse, error)
	ScopedSearch(ctx context.Context, in *connectorv1.ScopedSearchRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[connectorv1.ScopedSearchResponse], error)
}

// ReadSource resolves a connection to its read-only connector handle.
type ReadSource struct{ src ConnectorSource }

// NewReadSource narrows src to the read RPCs of ReadClient.
func NewReadSource(src ConnectorSource) (ReadSource, error) {
	if src == nil {
		return ReadSource{}, errors.New("client: read source needs a connector source")
	}
	return ReadSource{src: src}, nil
}

// Connector returns the read-only handle of the connection's connector.
func (r ReadSource) Connector(ctx context.Context, connectionID string) (ReadClient, error) {
	cc, err := r.src.Connector(ctx, connectionID)
	if err != nil {
		return nil, err
	}
	return cc, nil
}

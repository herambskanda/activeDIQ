package client

import (
	"context"
	"errors"

	"google.golang.org/grpc"

	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// Reader is the read-only slice of the connector client that the sync engine's full read uses: Describe
// and ScopedSearch, never Plan or Apply. The directory write RPC is reachable only through a function that
// takes a step.Clearance (ADR-0005 rule 2, fitness O2), so a package that only reads is handed this narrow
// port and not the generated client. TestReaderIsReadOnly fixes its method set.
type Reader interface {
	Describe(ctx context.Context, in *connectorv1.DescribeRequest, opts ...grpc.CallOption) (*connectorv1.DescribeResponse, error)
	ScopedSearch(ctx context.Context, in *connectorv1.ScopedSearchRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[connectorv1.ScopedSearchResponse], error)
}

// ReaderSource yields the Reader that serves one connection.
type ReaderSource interface {
	Reader(ctx context.Context, connectionID string) (Reader, error)
}

// NewReaderSource narrows src to read-only access. The returned reader wraps the generated client without
// embedding it, so Plan and Apply are not in its method set.
func NewReaderSource(src ConnectorSource) (ReaderSource, error) {
	if src == nil {
		return nil, errors.New("client: reader source needs a connector source")
	}
	return readerSource{src: src}, nil
}

type readerSource struct{ src ConnectorSource }

func (r readerSource) Reader(ctx context.Context, connectionID string) (Reader, error) {
	cc, err := r.src.Connector(ctx, connectionID)
	if err != nil {
		return nil, err
	}
	return readOnly{cc: cc}, nil
}

type readOnly struct{ cc connectorv1.ConnectorClient }

func (r readOnly) Describe(ctx context.Context, in *connectorv1.DescribeRequest, opts ...grpc.CallOption) (*connectorv1.DescribeResponse, error) {
	return r.cc.Describe(ctx, in, opts...)
}

func (r readOnly) ScopedSearch(ctx context.Context, in *connectorv1.ScopedSearchRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[connectorv1.ScopedSearchResponse], error) {
	return r.cc.ScopedSearch(ctx, in, opts...)
}

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

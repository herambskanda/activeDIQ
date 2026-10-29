package client

import (
	"context"
	"errors"

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

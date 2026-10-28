package connector

import (
	"crypto/tls"
	"crypto/x509"
	"errors"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/skenzeriq/activediq/internal/connector/rights"
)

// ErrMount is returned for an incomplete mount; it carries no certificate or directory text.
var ErrMount = errors.New("connector: mount needs a server certificate, client CAs and a verify handler")

// NewServer builds the connector's gRPC server and mounts the VerifyConnection group on it with
// rights.Register. rights.Register adds no authentication of its own (T-0233 review), so the server
// itself requires mTLS (connector contract): TLS 1.3, a client certificate that verifies against
// clientCAs is mandatory, and there is no insecure or optional-client-certificate path. A nil
// handler, an empty CA pool or a missing server certificate refuses construction.
func NewServer(server tls.Certificate, clientCAs *x509.CertPool, h *rights.VerifyHandler, opts ...grpc.ServerOption) (*grpc.Server, error) {
	if h == nil || clientCAs == nil || clientCAs.Equal(x509.NewCertPool()) || len(server.Certificate) == 0 {
		return nil, ErrMount
	}
	creds := credentials.NewTLS(&tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{server},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
	})
	// Caller options go first so they can never replace the credentials.
	srv := grpc.NewServer(append(append([]grpc.ServerOption{}, opts...), grpc.Creds(creds))...)
	rights.Register(srv, h)
	return srv, nil
}

package dial

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// clientTLS is the only TLS client configuration of the package: TLS 1.3, roots exactly the given
// pool (never nil), the server name from the address, and the standard verification. leaf, when
// given, is the client certificate for mTLS.
func clientTLS(roots *x509.CertPool, host string, leaf *tls.Certificate) *tls.Config {
	c := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: host}
	if leaf != nil {
		c.Certificates = []tls.Certificate{*leaf}
	}
	return c
}

// Credentials returns gRPC transport credentials that verify the server against the pinned CAs only.
// An empty set is refused instead of becoming an empty pool that fails every call late.
func Credentials(ca []*x509.Certificate, host string, leaf *tls.Certificate) (credentials.TransportCredentials, error) {
	if len(ca) == 0 || host == "" {
		return nil, ErrBundle
	}
	return credentials.NewTLS(clientTLS(Pool(ca), host, leaf)), nil
}

// DialOut opens the component's client connection to the server (the tunnel's carrier), verifying the
// server against the persisted installation CA only and presenting the component's leaf. The address
// is "host:port"; the host is the server name that must be in the certificate.
func DialOut(addr string, st *State) (*grpc.ClientConn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return nil, errors.New("dial: address must be host:port")
	}
	creds, err := Credentials(st.CA, host, &st.Leaf)
	if err != nil {
		return nil, err
	}
	return grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
}

// pinnedRoot finds the pinned CA among the certificates the server presents, without trusting
// anything: the handshake runs against an empty, non-nil pool, so it always fails verification and
// hands back the unverified chain (tls.CertificateVerificationError), and no application data is
// sent. The CA found is then used as the only root of the real, fully verified connection. A server
// whose chain does not contain the pinned CA yields ErrUntrustedServer.
func pinnedRoot(ctx context.Context, addr, host string, pin Pin) (*x509.Certificate, error) {
	d := tls.Dialer{Config: clientTLS(x509.NewCertPool(), host, nil)}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err == nil { // cannot happen with an empty pool; never use such a connection
		conn.Close()
		return nil, ErrUntrustedServer
	}
	var ve *tls.CertificateVerificationError
	if !errors.As(err, &ve) {
		return nil, err // network or protocol failure, not a trust decision
	}
	for _, c := range ve.UnverifiedCertificates {
		if isCA(c) && pin.Matches(c) {
			return c, nil
		}
	}
	return nil, ErrUntrustedServer
}

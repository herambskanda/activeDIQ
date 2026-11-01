package egress

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"
)

// ErrTLSHandshake: the TLS handshake of a stream failed (a certificate that does not verify, a
// protocol mismatch). The underlying error is wrapped beside it.
var ErrTLSHandshake = errors.New("egress: TLS handshake failed")

// DialStream opens a TCP connection for a non-HTTP protocol (syslog and SMTP, for example) under the same
// resolve, vet, pin rule as Do: loopback, private and metadata ranges are refused unless the
// operator allow-listed them. With useTLS the connection is wrapped in TLS 1.2+ verified against
// the host name (and Config.RootCAs); there is no way to skip verification. useTLS=false is the
// caller's explicit decision and must be audited by the caller. host must be a name or IP literal,
// port a decimal port.
func (c *Client) DialStream(ctx context.Context, host, port string, useTLS bool) (net.Conn, error) {
	if host == "" || port == "" {
		return nil, fmt.Errorf("%w: no host or port", ErrBadRequest)
	}
	raw, err := c.d.dialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, err
	}
	if !useTLS {
		return raw, nil
	}
	return c.wrapTLS(ctx, raw, host)
}

// TLSConfig returns the client TLS configuration for host: TLS 1.2 or later, verified against the
// system roots (or Config.RootCAs) for that name. A protocol that upgrades an open connection
// itself (SMTP STARTTLS) passes it to its library; the connection it upgrades came from DialStream
// with useTLS=false, so it was vetted at dial time. The config is a copy and there is no field
// that turns verification off.
func (c *Client) TLSConfig(host string) *tls.Config {
	cfg := c.tlsCfg.Clone()
	cfg.ServerName = host
	return cfg
}

func (c *Client) wrapTLS(ctx context.Context, raw net.Conn, host string) (net.Conn, error) {
	tc := tls.Client(raw, c.TLSConfig(host))
	hctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := tc.HandshakeContext(hctx); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("egress: TLS handshake with %s: %w: %w", host, ErrTLSHandshake, err)
	}
	return tc, nil
}

package egress

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// DialStream opens a TCP connection for a non-HTTP protocol (syslog, for example) under the same
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
	cfg := c.tlsCfg.Clone()
	cfg.ServerName = host
	tc := tls.Client(raw, cfg)
	hctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := tc.HandshakeContext(hctx); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("egress: TLS handshake with %s: %w", host, err)
	}
	return tc, nil
}

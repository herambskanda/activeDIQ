// Package egress is the one outbound HTTP client of the server (threat model §5.9, TM-TB9-T1,
// TM-F-EGRESS). Every integration that calls out over HTTP(S) (ITSM, SIEM, HR sources, SMS and
// webhook endpoints, ManageEngine comparators) goes through a Client from this package; the
// FF-SP2 rule "outbound-http" flags a net/http client, transport or dialer anywhere else.
//
// What a Client enforces, with no option to turn any of it off:
//
//   - Resolve, then vet, then pin. The host is resolved once per connection; every answer must be
//     permitted; the connection is made to the vetted IP literal. There is no second lookup between
//     check and dial, so a DNS answer that changes in between (rebinding) is never used.
//   - Loopback, link-local, private, CGNAT, multicast, reserved and cloud-metadata addresses are
//     refused unless the installation operator allow-lists the range (Config.Allow). A range that
//     contains a metadata address cannot be allow-listed.
//   - Redirects are followed at most five times; every hop is held to the scheme rule and to the
//     same dial vetting, an https to http downgrade is refused, and a hop to another origin drops
//     every request header except Accept, Accept-Language and User-Agent (judged against the
//     ORIGINAL origin on every hop); a cross-origin 307/308 carrying a body is refused.
//   - TLS is verified against the system roots (or Config.RootCAs for an operator CA), TLS 1.2 or
//     later. There is no field, option or environment variable that skips verification.
//   - Errors carry scheme://host[:port] only, never the path or query (they may hold a token).
//   - No proxy is used (a proxy would dial on our behalf outside the vetting) and no integrated
//     Windows authentication is attempted (TM-TB9-T2).
//
// Residual risk: FF-SP2 cannot see HTTP clients created inside third-party SDKs. An SDK that makes
// its own requests must be driven through a Client (no SDK may build its own transport), or it
// bypasses every control above.
package egress

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// Typed refusals. Test with errors.Is; the wrapped message names the host and address, never the
// path or query (which may carry a token).
var (
	// ErrDestinationDenied: the destination resolves to an address that is not permitted.
	ErrDestinationDenied = errors.New("egress: destination address not permitted")
	// ErrSchemeDenied: the URL scheme is not permitted (only https unless Config.AllowHTTP).
	ErrSchemeDenied = errors.New("egress: URL scheme not permitted")
	// ErrRedirectDenied: a redirect was refused (too many, a downgrade, or a disallowed scheme).
	ErrRedirectDenied = errors.New("egress: redirect refused")
	// ErrBadRequest: the request has no host, or carries credentials in the URL.
	ErrBadRequest = errors.New("egress: request refused")
	// ErrBadConfig: the Config is invalid.
	ErrBadConfig = errors.New("egress: invalid configuration")
)

const (
	maxRedirects        = 5
	defaultTimeout      = 60 * time.Second
	defaultConnsPerHost = 8
)

// Resolver is the part of *net.Resolver the client uses; tests inject a fake.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Config configures a Client. The zero value is the strictest client: https only, public
// destinations only, system trust roots.
type Config struct {
	// Allow is the operator's allow-list: address ranges that stay reachable although they are
	// loopback, link-local, private and so on. It cannot cover a cloud-metadata address.
	Allow []netip.Prefix
	// AllowHTTP permits the plain http scheme. It is the operator's explicit opt-in for an
	// integration that cannot do TLS; https to http redirects stay refused.
	AllowHTTP bool
	// RootCAs adds the operator's CA for internal integrations. Nil means the system roots.
	// Verification itself cannot be disabled.
	RootCAs *x509.CertPool
	// Timeout bounds a whole request including redirects and reading the body. Default 60 s.
	Timeout time.Duration
	// MaxConnsPerHost bounds concurrent connections to one destination (TM-TB9-T8). Default 8.
	MaxConnsPerHost int
	// Resolver defaults to net.DefaultResolver.
	Resolver Resolver

	dial func(ctx context.Context, network, addr string) (net.Conn, error) // test seam; sees IP literals only
}

// Client is the egress HTTP client. Safe for concurrent use.
type Client struct {
	hc        *http.Client
	allowHTTP bool
}

// New validates cfg and returns a Client.
func New(cfg Config) (*Client, error) {
	for _, p := range cfg.Allow {
		if !p.IsValid() {
			return nil, fmt.Errorf("%w: invalid allow-list prefix", ErrBadConfig)
		}
		if p = p.Masked(); coversMetadata(p) {
			return nil, fmt.Errorf("%w: allow-list prefix %s covers a cloud-metadata address", ErrBadConfig, p)
		}
	}
	if cfg.Timeout < 0 || cfg.MaxConnsPerHost < 0 {
		return nil, fmt.Errorf("%w: negative limit", ErrBadConfig)
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = defaultTimeout
	}
	if cfg.MaxConnsPerHost == 0 {
		cfg.MaxConnsPerHost = defaultConnsPerHost
	}
	if cfg.Resolver == nil {
		cfg.Resolver = net.DefaultResolver
	}
	d := &dialer{allow: append([]netip.Prefix(nil), cfg.Allow...), res: cfg.Resolver, dial: cfg.dial}
	if d.dial == nil {
		nd := &net.Dialer{Timeout: 10 * time.Second}
		d.dial = nd.DialContext
	}
	tr := &http.Transport{
		Proxy:                 nil, // a proxy would dial on our behalf, outside the vetting
		DialContext:           d.dialContext,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: cfg.RootCAs},
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		MaxConnsPerHost:       cfg.MaxConnsPerHost,
		MaxIdleConnsPerHost:   cfg.MaxConnsPerHost,
		IdleConnTimeout:       90 * time.Second,
	}
	return &Client{
		hc:        &http.Client{Transport: tr, Timeout: cfg.Timeout, CheckRedirect: redirectPolicy(cfg.AllowHTTP)},
		allowHTTP: cfg.AllowHTTP,
	}, nil
}

// Do sends req. The request is refused before any lookup when its scheme is not permitted, it has
// no host, or it carries user information in the URL.
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, fmt.Errorf("%w: nil request", ErrBadRequest)
	}
	if err := checkURL(req.URL, c.allowHTTP); err != nil {
		return nil, err
	}
	resp, err := c.hc.Do(req)
	return resp, redactURL(err)
}

// redactURL reduces the URL inside a *url.Error to scheme://host[:port]: webhook and SMS URLs
// carry tokens in the path or query, and these errors get logged. errors.Is/As keep working.
func redactURL(err error) error {
	var ue *url.Error
	if !errors.As(err, &ue) {
		return err
	}
	red := ue.URL
	if u, perr := url.Parse(ue.URL); perr == nil {
		red = u.Scheme + "://" + u.Host
	} else {
		red = "(unparseable url)"
	}
	return &url.Error{Op: ue.Op, URL: red, Err: ue.Err}
}

// CloseIdleConnections closes pooled connections, for example after an integration is edited.
func (c *Client) CloseIdleConnections() { c.hc.CloseIdleConnections() }

func checkURL(u *url.URL, allowHTTP bool) error {
	if u == nil || u.Hostname() == "" {
		return fmt.Errorf("%w: no host", ErrBadRequest)
	}
	if u.User != nil {
		return fmt.Errorf("%w: credentials in the URL", ErrBadRequest)
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
	case "http":
		if !allowHTTP {
			return fmt.Errorf("%w: http to %s (https only)", ErrSchemeDenied, u.Hostname())
		}
	default:
		return fmt.Errorf("%w: %q", ErrSchemeDenied, u.Scheme)
	}
	return nil
}

// redirectPolicy vets each hop. The dial of the hop is vetted again by the dialer.
func redirectPolicy(allowHTTP bool) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return fmt.Errorf("%w: more than %d redirects", ErrRedirectDenied, maxRedirects)
		}
		prev := via[len(via)-1]
		if err := checkURL(req.URL, allowHTTP); err != nil {
			return fmt.Errorf("%w: to %s: %w", ErrRedirectDenied, req.URL.Hostname(), err)
		}
		if prev.URL.Scheme == "https" && req.URL.Scheme != "https" {
			return fmt.Errorf("%w: https to %s downgrade", ErrRedirectDenied, req.URL.Scheme)
		}
		// Compare with the ORIGINAL origin, not the previous hop: net/http re-copies the original
		// request's headers on every hop, so a hop-to-hop comparison would hand them back.
		if origin(via[0].URL) != origin(req.URL) {
			if (req.Response != nil && (req.Response.StatusCode == http.StatusTemporaryRedirect || req.Response.StatusCode == http.StatusPermanentRedirect)) &&
				req.Body != nil && req.Body != http.NoBody {
				return fmt.Errorf("%w: cross-origin %d would re-send the request body", ErrRedirectDenied, req.Response.StatusCode)
			}
			for k := range req.Header {
				switch http.CanonicalHeaderKey(k) {
				case "Accept", "Accept-Language", "User-Agent":
				default:
					delete(req.Header, k)
				}
			}
		}
		return nil
	}
}

func origin(u *url.URL) string {
	p := u.Port()
	if p == "" && strings.EqualFold(u.Scheme, "http") {
		p = "80"
	} else if p == "" {
		p = "443"
	}
	return strings.ToLower(u.Scheme) + "://" + net.JoinHostPort(strings.ToLower(u.Hostname()), p)
}

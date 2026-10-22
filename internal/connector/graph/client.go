// Package graph is the read-only Microsoft Graph client of the connector: app-only access as the
// customer's own app registration with a certificate assertion (threat-model §6.6). It never writes.
package graph

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
)

const (
	DefaultAuthority = "https://login.microsoftonline.com"
	DefaultGraphBase = "https://graph.microsoft.com/v1.0"
	graphScope       = "https://graph.microsoft.com/.default"
	maxBody          = 16 << 20
	maxPages         = 10000
)

// Config configures a Client. TenantID pins every endpoint and is checked against the token's tid.
type Config struct {
	TenantID   string // tenant GUID (a domain is refused)
	ClientID   string // application (client) id GUID
	Credential Credential
	Authority  string        // default DefaultAuthority; must be https
	GraphBase  string        // default DefaultGraphBase; must be https
	HTTPClient *http.Client  // TLS validation stays on; tests pass the fake's client
	Logger     *slog.Logger  // optional; receives method, path template and status only
	MaxRetries int           // throttle/transient retries per request, default 5
	MaxWait    time.Duration // longest single Retry-After honoured, default 5 min
	PageSize   int           // objects per page, default 100
	Now        func() time.Time
	Sleep      func(context.Context, time.Duration) error // tests inject; default honours ctx
}

// Client reads from Graph. Safe for concurrent use.
type Client struct {
	cfg       Config
	clientID  guid.GUID // parsed once from Config.ClientID (R1)
	tokenURL  string
	graphBase *url.URL
	hc        *http.Client
	log       *slog.Logger

	mu      sync.Mutex
	token   string
	expires time.Time
}

// New validates the configuration. It does no I/O.
func New(cfg Config) (*Client, error) {
	// A domain name is DNS-controlled and can move between tenants, so only the tenant GUID is
	// accepted; onboarding resolves a domain once and stores the GUID.
	tenant, err := guid.Parse(cfg.TenantID)
	if err != nil {
		return nil, newErr(CodeInvalidArgument, 0, "tenant id is not a GUID", nil)
	}
	clientID, err := guid.Parse(cfg.ClientID)
	if err != nil {
		return nil, newErr(CodeInvalidArgument, 0, "client id is not a GUID", nil)
	}
	cfg.TenantID, cfg.ClientID = tenant.String(), clientID.String() // canonical form on the wire
	if cfg.Authority == "" {
		cfg.Authority = DefaultAuthority
	}
	if cfg.GraphBase == "" {
		cfg.GraphBase = DefaultGraphBase
	}
	auth, err := url.Parse(cfg.Authority)
	if err != nil || auth.Scheme != "https" || auth.Host == "" {
		return nil, newErr(CodeTransportSec, 0, "authority must be an https URL", nil)
	}
	gb, err := url.Parse(cfg.GraphBase)
	if err != nil || gb.Scheme != "https" || gb.Host == "" {
		return nil, newErr(CodeTransportSec, 0, "graph base must be an https URL", nil)
	}
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = 5
	}
	if cfg.MaxWait <= 0 {
		cfg.MaxWait = 5 * time.Minute
	}
	if cfg.PageSize <= 0 || cfg.PageSize > 999 {
		cfg.PageSize = 100
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Sleep == nil {
		cfg.Sleep = sleepCtx
	}
	hc := &http.Client{Timeout: 60 * time.Second}
	if cfg.HTTPClient != nil {
		c := *cfg.HTTPClient
		hc = &c
	}
	// A redirect would carry the bearer token to wherever it points; never follow one.
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	tokenURL := strings.TrimRight(cfg.Authority, "/") + "/" + tenant.String() + "/oauth2/v2.0/token"
	return &Client{cfg: cfg, clientID: clientID, tokenURL: tokenURL, graphBase: gb, hc: hc, log: log}, nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// classifyTransport maps a net/http failure to a typed error. Certificate failures are
// TRANSPORT_SECURITY and never retried; everything else is UNREACHABLE.
func classifyTransport(err error) error {
	if ctxErr := contextErr(err); ctxErr != nil {
		return ctxErr
	}
	if isTLSError(err) {
		return newErr(CodeTransportSec, 0, "TLS validation of the Microsoft endpoint failed", err)
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return newErr(CodeUnreachable, 0, "request timed out", err)
	}
	return newErr(CodeUnreachable, 0, "endpoint unreachable", err)
}

func contextErr(err error) error {
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return nil
}

const maxDuration = time.Duration(1<<63 - 1)

func parseRetryAfter(h string, now time.Time) (time.Duration, bool) {
	h = strings.TrimSpace(h)
	if h == "" {
		return 0, false
	}
	if n, err := strconv.ParseInt(h, 10, 64); err == nil && n >= 0 {
		if n > int64(maxDuration/time.Second) {
			return maxDuration, true // saturate so the multiply cannot overflow; the caller applies MaxWait
		}
		return time.Duration(n) * time.Second, true
	}
	if _, err := strconv.ParseUint(h, 10, 64); err == nil {
		return maxDuration, true
	}
	if t, err := http.ParseTime(h); err == nil {
		if d := t.Sub(now); d > 0 {
			return d, true
		}
		return 0, true
	}
	return 0, false
}

func backoff(attempt int) time.Duration {
	d := time.Second << min(attempt, 5)
	return d
}

// ---- token ----

type tokenResp struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

func (c *Client) bearer(ctx context.Context, force bool) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !force && c.token != "" && c.cfg.Now().Before(c.expires.Add(-time.Minute)) {
		return c.token, nil
	}
	c.token = ""
	jtiRaw := make([]byte, 16)
	if _, err := rand.Read(jtiRaw); err != nil {
		return "", newErr(CodeProviderFailure, 0, "no entropy for assertion id", err)
	}
	assertion, err := buildAssertion(c.cfg.Credential, c.cfg.ClientID, c.tokenURL, c.cfg.Now(), b64.EncodeToString(jtiRaw))
	if err != nil {
		return "", err
	}
	form := url.Values{
		"client_id":             {c.cfg.ClientID},
		"scope":                 {graphScope},
		"grant_type":            {"client_credentials"},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {assertion},
	}
	var tr tokenResp
	for attempt := 0; ; attempt++ {
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "application/json")
		resp, err := c.hc.Do(req)
		if err != nil {
			return "", classifyTransport(err)
		}
		body, rerr := io.ReadAll(io.LimitReader(resp.Body, maxBody))
		resp.Body.Close()
		c.log.Debug("graph token", "status", resp.StatusCode)
		if rerr != nil {
			return "", newErr(CodeUnreachable, resp.StatusCode, "token response truncated", rerr)
		}
		switch {
		case resp.StatusCode == http.StatusOK:
			if err := json.Unmarshal(body, &tr); err != nil || tr.AccessToken == "" || !strings.EqualFold(tr.TokenType, "Bearer") {
				return "", newErr(CodeProviderFailure, resp.StatusCode, "token response malformed", err)
			}
		case resp.StatusCode == 429 || resp.StatusCode >= 500:
			wait, ok := parseRetryAfter(resp.Header.Get("Retry-After"), c.cfg.Now())
			if !ok {
				wait = backoff(attempt)
			}
			if attempt >= c.cfg.MaxRetries || wait > c.cfg.MaxWait {
				e := newErr(CodeThrottled, resp.StatusCode, "token endpoint throttled", nil)
				e.RetryAfter = wait
				if resp.StatusCode >= 500 && resp.StatusCode != 429 {
					e.Code = CodeUnreachable
					e.Message = "token endpoint unavailable"
				}
				return "", e
			}
			if err := c.cfg.Sleep(ctx, wait); err != nil {
				return "", err
			}
			continue
		default:
			return "", newErr(CodeBindFailed, resp.StatusCode, "the tenant refused the app credential", nil)
		}
		break
	}
	tid, err := tokenTenant(tr.AccessToken)
	if err != nil {
		return "", newErr(CodeProviderFailure, 0, "access token has no readable tenant claim", err)
	}
	if !strings.EqualFold(tid, c.cfg.TenantID) {
		return "", newErr(CodeIdentityMismatch, 0, "token was issued for a different tenant", nil)
	}
	ttl := time.Duration(tr.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	c.token, c.expires = tr.AccessToken, c.cfg.Now().Add(ttl)
	return c.token, nil
}

// tokenTenant reads tid from the (unverified) access token. It is a pinning check against a token
// we just received over validated TLS, not an authentication decision.
func tokenTenant(tok string) (string, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return "", errors.New("not a JWT")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}
	var cl struct {
		Tid string `json:"tid"`
	}
	if err := json.Unmarshal(raw, &cl); err != nil || cl.Tid == "" {
		return "", errors.New("no tid")
	}
	return cl.Tid, nil
}

package graph

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/skenzeriq/activediq/internal/directory/odata"
)

func isTLSError(err error) bool {
	var ua x509.UnknownAuthorityError
	var ci x509.CertificateInvalidError
	var he x509.HostnameError
	return errors.As(err, &ua) || errors.As(err, &ci) || errors.As(err, &he) ||
		strings.Contains(err.Error(), "tls:")
}

// get performs one GET (tpl is the request's value-free path template, the only path form logged) (with throttle retry) against an absolute URL that must be on the pinned
// Graph origin, decoding the JSON body into out.
func (c *Client) get(ctx context.Context, u *url.URL, tpl string, out any) error {
	if u.Scheme != c.graphBase.Scheme || !strings.EqualFold(u.Host, c.graphBase.Host) {
		return newErr(CodeIdentityMismatch, 0, "link points outside the pinned Graph endpoint", nil)
	}
	refreshed := false
	for attempt := 0; ; attempt++ {
		tok, err := c.bearer(ctx, false)
		if err != nil {
			return err
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Accept", "application/json")
		// Advanced queries (filters on isAssignableToRole, counts) need eventual consistency.
		req.Header.Set("ConsistencyLevel", "eventual")
		resp, err := c.hc.Do(req)
		if err != nil {
			return classifyTransport(err)
		}
		body, rerr := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
		resp.Body.Close()
		c.log.Debug("graph get", "path", tpl, "status", resp.StatusCode)
		if rerr != nil {
			return newErr(CodeUnreachable, resp.StatusCode, "response truncated", rerr)
		}
		if len(body) > maxBody {
			return newErr(CodeLimitExceeded, resp.StatusCode, "response exceeds size cap", nil)
		}
		switch st := resp.StatusCode; {
		case st == http.StatusOK:
			if err := json.Unmarshal(body, out); err != nil {
				return newErr(CodeProviderFailure, st, "response is not the expected JSON", err)
			}
			return nil
		case st == http.StatusUnauthorized && !refreshed:
			refreshed = true
			if _, err := c.bearer(ctx, true); err != nil {
				return err
			}
			attempt--
			continue
		case st == http.StatusUnauthorized:
			return newErr(CodeBindFailed, st, "Graph rejected the access token", nil)
		case st == http.StatusForbidden:
			return newErr(CodeInsufficient, st, "the app registration lacks the permission for this read", nil)
		case st == http.StatusNotFound:
			return newErr(CodeNotFound, st, "object not found", nil)
		case st == 429 || st == 503 || st == 504:
			wait, ok := parseRetryAfter(resp.Header.Get("Retry-After"), c.cfg.Now())
			if !ok {
				wait = backoff(attempt)
			}
			if attempt >= c.cfg.MaxRetries || wait > c.cfg.MaxWait {
				e := newErr(CodeThrottled, st, "Graph is throttling this app", nil)
				if st != 429 {
					e.Code, e.Message = CodeUnreachable, "Graph unavailable"
				}
				e.RetryAfter = wait
				return e
			}
			if err := c.cfg.Sleep(ctx, wait); err != nil {
				return err
			}
		case st >= 300 && st < 400:
			return newErr(CodeProviderFailure, st, "unexpected redirect (not followed)", nil)
		default:
			return newErr(CodeProviderFailure, st, "Graph returned an error", nil)
		}
	}
}

// resolve renders req against the pinned Graph base; the odata primitive writes the whole URL.
func (c *Client) resolve(req odata.Request) (*url.URL, error) {
	u, err := req.URL(c.graphBase)
	if err != nil {
		return nil, invalidArg(err)
	}
	return u, nil
}

// invalidArg maps a primitive refusal to INVALID_ARGUMENT; the cause is the odata kind, never the value.
func invalidArg(err error) error {
	return newErr(CodeInvalidArgument, 0, "request refused by the OData builder", err)
}

// read performs one GET of req into out.
func (c *Client) read(ctx context.Context, req odata.Request, out any) error {
	u, err := c.resolve(req)
	if err != nil {
		return err
	}
	return c.get(ctx, u, req.Template(), out)
}

type page[T any] struct {
	Value    []T    `json:"value"`
	NextLink string `json:"@odata.nextLink"`
}

// list follows @odata.nextLink to the end. A broken page is an error, never a short success.
func list[T any](ctx context.Context, c *Client, first odata.Request) ([]T, error) {
	var all []T
	u, err := c.resolve(first)
	if err != nil {
		return nil, err
	}
	for n := 0; ; n++ {
		if n >= maxPages {
			return nil, newErr(CodeLimitExceeded, 0, "too many pages", nil)
		}
		var p page[T]
		if err := c.get(ctx, u, first.Template(), &p); err != nil {
			return nil, err
		}
		all = append(all, p.Value...)
		if p.NextLink == "" {
			return all, nil
		}
		next, err := url.Parse(p.NextLink)
		if err != nil {
			return nil, newErr(CodeProviderFailure, 0, "malformed next link", err)
		}
		u = next
	}
}

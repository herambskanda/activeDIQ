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
)

func isTLSError(err error) bool {
	var ua x509.UnknownAuthorityError
	var ci x509.CertificateInvalidError
	var he x509.HostnameError
	return errors.As(err, &ua) || errors.As(err, &ci) || errors.As(err, &he) ||
		strings.Contains(err.Error(), "tls:")
}

// get performs one GET (with throttle retry) against an absolute URL that must be on the pinned
// Graph origin, decoding the JSON body into out.
func (c *Client) get(ctx context.Context, u *url.URL, out any) error {
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
		// Advanced queries ($filter on isAssignableToRole, $count) need eventual consistency.
		req.Header.Set("ConsistencyLevel", "eventual")
		resp, err := c.hc.Do(req)
		if err != nil {
			return classifyTransport(err)
		}
		body, rerr := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
		resp.Body.Close()
		c.log.Debug("graph get", "path", u.Path, "status", resp.StatusCode)
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

// endpoint builds a pinned URL from path segments (each path-escaped) and query parameters.
func (c *Client) endpoint(q url.Values, segs ...string) *url.URL {
	u := *c.graphBase
	esc := strings.TrimRight(c.graphBase.EscapedPath(), "/")
	raw := strings.TrimRight(c.graphBase.Path, "/")
	for _, s := range segs {
		esc += "/" + url.PathEscape(s)
		raw += "/" + s
	}
	u.Path, u.RawPath = raw, esc
	u.RawQuery = strings.ReplaceAll(q.Encode(), "+", "%20")
	return &u
}

type page[T any] struct {
	Value    []T    `json:"value"`
	NextLink string `json:"@odata.nextLink"`
}

// list follows @odata.nextLink to the end. A broken page is an error, never a short success.
func list[T any](ctx context.Context, c *Client, first *url.URL) ([]T, error) {
	var all []T
	u := first
	for n := 0; ; n++ {
		if n >= maxPages {
			return nil, newErr(CodeLimitExceeded, 0, "too many pages", nil)
		}
		var p page[T]
		if err := c.get(ctx, u, &p); err != nil {
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

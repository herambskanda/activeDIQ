// Package oidchttp adapts the egress client to the net/http-free seam of authn/sso/oidc, so net/http stays
// out of the authn handler packages (ADR-0004 A6).
package oidchttp

import (
	"bytes"
	"context"
	"net/http"

	"github.com/skenzeriq/activediq/internal/platform/authn/sso/oidc"
)

// Doer is what *egress.Client provides.
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

type client struct{ d Doer }

// New returns the oidc.HTTPClient that sends through d (production: an *egress.Client, TM-TB9-T1).
func New(d Doer) oidc.HTTPClient { return client{d} }

func (c client) Do(ctx context.Context, r oidc.Request) (oidc.Response, error) {
	var body *bytes.Reader
	if r.Body != nil {
		body = bytes.NewReader(r.Body)
	}
	var req *http.Request
	var err error
	if body != nil {
		req, err = http.NewRequestWithContext(ctx, r.Method, r.URL, body)
	} else {
		req, err = http.NewRequestWithContext(ctx, r.Method, r.URL, nil)
	}
	if err != nil {
		return oidc.Response{}, err
	}
	for k, v := range r.Header {
		req.Header.Set(k, v)
	}
	resp, err := c.d.Do(req)
	if err != nil {
		return oidc.Response{}, err
	}
	return oidc.Response{Status: resp.StatusCode, Body: resp.Body}, nil
}

package egress

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// ErrBody is wrapped by Fetch when the request was sent but the answer body could not be read within
// the cap. It lets a caller tell "the transport failed" from "the answer is unusable".
var ErrBody = errors.New("egress: answer body unreadable or over the cap")

// Doer sends one HTTP request: *Client in production, an httptest client in tests.
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Request is a bounded outbound call described without net/http types, so a module that is a handler
// package (ADR-0004 A6) can call out without importing net/http.
type Request struct {
	Method string
	URL    string
	Header map[string]string
	Body   []byte
}

// Response is the status and the capped body of an answer. Headers are not exposed.
type Response struct {
	Status int
	Body   []byte
}

// Fetch sends req through d and reads at most maxBody bytes of the answer. A transport error is
// returned as Do returned it (already URL-redacted for *Client); an unreadable or oversized body is
// ErrBody.
func Fetch(ctx context.Context, d Doer, req Request, maxBody int64) (Response, error) {
	if d == nil {
		return Response{}, fmt.Errorf("%w: no client", ErrBadRequest)
	}
	var body io.Reader
	if req.Body != nil {
		body = bytes.NewReader(req.Body)
	}
	hr, err := http.NewRequestWithContext(ctx, req.Method, req.URL, body)
	if err != nil {
		return Response{}, fmt.Errorf("%w: %v", ErrBadRequest, errors.Unwrap(err))
	}
	for k, v := range req.Header {
		hr.Header.Set(k, v)
	}
	resp, err := d.Do(hr)
	if err != nil {
		return Response{}, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil || int64(len(b)) > maxBody {
		return Response{Status: resp.StatusCode}, ErrBody
	}
	return Response{Status: resp.StatusCode, Body: b}, nil
}

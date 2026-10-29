package oidchttp

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/authn/sso/oidc"
)

func TestDoSendsMethodHeadersBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if r.Method != "POST" || r.Header.Get("X-A") != "1" || string(b) != "a=b" {
			w.WriteHeader(400)
			return
		}
		w.WriteHeader(201)
	}))
	defer srv.Close()
	resp, err := New(srv.Client()).Do(t.Context(), oidc.Request{Method: "POST", URL: srv.URL, Header: map[string]string{"X-A": "1"}, Body: []byte("a=b")})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.Status != 201 {
		t.Errorf("status %d", resp.Status)
	}
}

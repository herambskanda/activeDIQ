package apihost

import (
	"net/http"
	"slices"
	"testing"
)

// T-0456: only the header parameters an operation declares reach Request.Header.
func TestDeclaredHeaders(t *testing.T) {
	in := http.Header{}
	in.Set("Cookie", "__Host-adiq_session=CANARY")
	in.Set("Authorization", "Bearer CANARY")
	in.Set("X-CSRF-Token", "csrf")
	in.Set("X-Forwarded-For", "203.0.113.1")
	in.Add("Idempotency-Key", "k1")
	keys := func(h http.Header) []string {
		var ks []string
		for k := range h {
			ks = append(ks, k)
		}
		slices.Sort(ks)
		return ks
	}
	if h := declaredHeaders(in, nil); h == nil || len(h) != 0 {
		t.Fatalf("no declared headers: got %v", h)
	}
	h := declaredHeaders(in, []string{"idempotency-key", "If-Match"})
	if got := keys(h); !slices.Equal(got, []string{"Idempotency-Key"}) || h.Get("Idempotency-Key") != "k1" {
		t.Fatalf("declared Idempotency-Key: got %v", h)
	}
	h["Idempotency-Key"][0] = "changed"
	if in.Get("Idempotency-Key") != "k1" {
		t.Fatal("the copy aliases the request's header values")
	}
}

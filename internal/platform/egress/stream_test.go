package egress

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"sync"
	"testing"
)

// Do and DialStream share one Client; the stream must not inherit the HTTP transport's mutated
// TLS config (ALPN h2/http1.1) and must not race with it.
func TestStreamTLSIndependentOfHTTPTransport(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	c, err := New(Config{Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, RootCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(srv.URL)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if resp, err := get(t, c, srv.URL); err == nil {
				resp.Body.Close()
			}
		}()
		go func() {
			defer wg.Done()
			conn, err := c.DialStream(context.Background(), "127.0.0.1", u.Port(), true)
			if err != nil {
				return // server cert is for example.com/127.0.0.1; errors are checked below
			}
			conn.Close()
		}()
	}
	wg.Wait()
	conn, err := c.DialStream(context.Background(), "127.0.0.1", u.Port(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if p := conn.(*tls.Conn).ConnectionState().NegotiatedProtocol; p != "" {
		t.Fatalf("stream negotiated ALPN %q, want none", p)
	}
}

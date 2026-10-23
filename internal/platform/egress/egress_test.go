package egress

import (
	"context"
	"crypto/x509"
	"errors"
	"strings"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
)

type fakeResolver struct {
	mu      sync.Mutex
	answers [][]netip.Addr // one per call; the last repeats
	calls   int
}

func (f *fakeResolver) LookupNetIP(_ context.Context, _, _ string) ([]netip.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	i := f.calls
	if i >= len(f.answers) {
		i = len(f.answers) - 1
	}
	f.calls++
	return f.answers[i], nil
}

func addrs(s ...string) []netip.Addr {
	var out []netip.Addr
	for _, a := range s {
		out = append(out, netip.MustParseAddr(a))
	}
	return out
}

// recorder is the dial seam: it records the addresses it is asked to connect to and never connects.
type recorder struct {
	mu    sync.Mutex
	addrs []string
}

func (r *recorder) dial(_ context.Context, _, addr string) (net.Conn, error) {
	r.mu.Lock()
	r.addrs = append(r.addrs, addr)
	r.mu.Unlock()
	return nil, errors.New("recorder: not connecting")
}

func get(t *testing.T, c *Client, url string) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	return c.Do(req)
}

func TestBlockedRangesRefusedAfterResolutionAndNeverDialled(t *testing.T) {
	for _, ip := range []string{
		"127.0.0.1", "::1", "169.254.169.254", "169.254.1.1", "fe80::1", "10.1.2.3", "172.16.0.9", "192.168.1.1",
		"100.64.0.1", "100.100.100.200", "0.0.0.0", "224.0.0.1", "fd00:ec2::254", "fc00::1", "::ffff:127.0.0.1",
		"::ffff:169.254.169.254", "64:ff9b::7f00:1", "2002:7f00:1::1", "192.0.0.192", "240.0.0.1", "168.63.129.16", "64:ff9b:1::7f00:1",
	} {
		rec := &recorder{}
		c, err := New(Config{Resolver: &fakeResolver{answers: [][]netip.Addr{addrs(ip)}}, dial: rec.dial})
		if err != nil {
			t.Fatal(err)
		}
		_, err = get(t, c, "https://integration.example/hook")
		if !errors.Is(err, ErrDestinationDenied) {
			t.Errorf("%s: err = %v, want ErrDestinationDenied", ip, err)
		}
		if len(rec.addrs) != 0 {
			t.Errorf("%s: dialled %v", ip, rec.addrs)
		}
	}
}

func TestLiteralBlockedHostRefused(t *testing.T) {
	rec := &recorder{}
	c, _ := New(Config{Resolver: &fakeResolver{answers: [][]netip.Addr{addrs("8.8.8.8")}}, dial: rec.dial})
	for _, u := range []string{"https://127.0.0.1/", "https://[::1]:8443/", "https://169.254.169.254/latest/meta-data/"} {
		if _, err := get(t, c, u); !errors.Is(err, ErrDestinationDenied) {
			t.Errorf("%s: err = %v", u, err)
		}
	}
	if len(rec.addrs) != 0 {
		t.Errorf("dialled %v", rec.addrs)
	}
}

func TestMixedAnswerRefusedWholesale(t *testing.T) {
	rec := &recorder{}
	c, _ := New(Config{Resolver: &fakeResolver{answers: [][]netip.Addr{addrs("8.8.8.8", "10.0.0.1")}}, dial: rec.dial})
	if _, err := get(t, c, "https://x.example/"); !errors.Is(err, ErrDestinationDenied) || len(rec.addrs) != 0 {
		t.Fatalf("err = %v, dialled %v", err, rec.addrs)
	}
}

func TestDialUsesVettedIPLiteralAndResolvesOnce(t *testing.T) {
	rec := &recorder{}
	res := &fakeResolver{answers: [][]netip.Addr{addrs("93.184.216.34"), addrs("169.254.169.254")}} // rebind on the 2nd lookup
	c, _ := New(Config{Resolver: res, dial: rec.dial})
	_, err := get(t, c, "https://rebind.example:8443/")
	if err == nil {
		t.Fatal("expected the recorder's refusal to connect")
	}
	if len(rec.addrs) != 1 || rec.addrs[0] != "93.184.216.34:8443" {
		t.Fatalf("dialled %v, want the vetted IP literal only", rec.addrs)
	}
	if res.calls != 1 {
		t.Fatalf("resolver called %d times, want 1 (no re-resolve between check and dial)", res.calls)
	}
}

func TestAllowListPermitsOperatorRange(t *testing.T) {
	rec := &recorder{}
	res := &fakeResolver{answers: [][]netip.Addr{addrs("10.1.2.3")}}
	c, err := New(Config{Allow: []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16")}, Resolver: res, dial: rec.dial})
	if err != nil {
		t.Fatal(err)
	}
	get(t, c, "https://itsm.corp.example/")
	if len(rec.addrs) != 1 || rec.addrs[0] != "10.1.2.3:443" {
		t.Fatalf("dialled %v", rec.addrs)
	}
	res.answers = [][]netip.Addr{addrs("10.2.0.1")}
	rec.addrs = nil
	if _, err := get(t, c, "https://other.corp.example/"); !errors.Is(err, ErrDestinationDenied) || len(rec.addrs) != 0 {
		t.Fatalf("outside the allow-list: err = %v dialled %v", err, rec.addrs)
	}
}

func TestAllowListCannotCoverMetadata(t *testing.T) {
	for _, p := range []string{"169.254.0.0/16", "0.0.0.0/0", "::/0", "fd00::/8", "100.64.0.0/10", "192.0.0.0/24"} {
		if _, err := New(Config{Allow: []netip.Prefix{netip.MustParsePrefix(p)}}); !errors.Is(err, ErrBadConfig) {
			t.Errorf("%s: err = %v, want ErrBadConfig", p, err)
		}
	}
	if _, err := New(Config{Allow: []netip.Prefix{{}}}); !errors.Is(err, ErrBadConfig) {
		t.Errorf("invalid prefix accepted")
	}
	if _, err := New(Config{Allow: []netip.Prefix{netip.MustParsePrefix("169.254.10.0/24")}}); err != nil {
		t.Errorf("a link-local range that excludes metadata should be allowable: %v", err)
	}
}

func TestSchemeAndRequestChecks(t *testing.T) {
	c, _ := New(Config{Resolver: &fakeResolver{answers: [][]netip.Addr{addrs("8.8.8.8")}}, dial: (&recorder{}).dial})
	for u, want := range map[string]error{
		"http://x.example/":          ErrSchemeDenied,
		"ftp://x.example/":           ErrSchemeDenied,
		"file:///etc/passwd":         ErrBadRequest,
		"https://user:pw@x.example/": ErrBadRequest,
		"https:///nohost":            ErrBadRequest,
	} {
		if _, err := get(t, c, u); !errors.Is(err, want) {
			t.Errorf("%s: err = %v, want %v", u, err, want)
		}
	}
	if _, err := c.Do(nil); !errors.Is(err, ErrBadRequest) {
		t.Errorf("nil request: %v", err)
	}
	ch, _ := New(Config{AllowHTTP: true, Resolver: &fakeResolver{answers: [][]netip.Addr{addrs("8.8.8.8")}}, dial: (&recorder{}).dial})
	if _, err := get(t, ch, "http://x.example/"); errors.Is(err, ErrSchemeDenied) {
		t.Errorf("AllowHTTP should permit http: %v", err)
	}
}

// loopback returns a Config that reaches the httptest server's loopback address, trusting its CA.
func loopback(t *testing.T, srv *httptest.Server) Config {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return Config{
		Allow:    []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
		RootCAs:  pool,
		Resolver: &fakeResolver{answers: [][]netip.Addr{addrs("127.0.0.1")}},
	}
}

func hostPort(srv *httptest.Server, host string) string {
	_, p, _ := net.SplitHostPort(srv.Listener.Addr().String())
	return "https://" + host + ":" + p
}

func TestVerifiedTLSAgainstRealServer(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	defer srv.Close()

	c, err := New(loopback(t, srv))
	if err != nil {
		t.Fatal(err)
	}
	// httptest's certificate is valid for example.com.
	resp, err := get(t, c, hostPort(srv, "example.com")+"/")
	if err != nil {
		t.Fatalf("trusted CA and matching name: %v", err)
	}
	resp.Body.Close()

	if _, err := get(t, c, hostPort(srv, "wrong-name.example")+"/"); err == nil {
		t.Fatal("a certificate for another name must fail")
	}

	cfg := loopback(t, srv)
	cfg.RootCAs = nil // system roots: the httptest CA is unknown
	c2, _ := New(cfg)
	if _, err := get(t, c2, hostPort(srv, "example.com")+"/"); err == nil {
		t.Fatal("an untrusted CA must fail; there is no option to skip verification")
	}
}

func TestRedirectToDisallowedDestinationRefused(t *testing.T) {
	var hits int
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		switch r.URL.Path {
		case "/meta":
			http.Redirect(w, r, "https://169.254.169.254/latest/meta-data/", http.StatusFound)
		case "/downgrade":
			http.Redirect(w, r, "http://example.com/", http.StatusFound)
		case "/scheme":
			http.Redirect(w, r, "file:///etc/passwd", http.StatusFound)
		case "/loop":
			http.Redirect(w, r, "/loop", http.StatusFound)
		case "/cross":
			http.Redirect(w, r, "https://www.example.com:"+portOf(srv)+"/echo", http.StatusFound)
		case "/echo":
			w.Header().Set("X-Seen-Key", r.Header.Get("X-Api-Key")+"|"+r.Header.Get("Authorization")+"|"+r.Header.Get("Accept"))
		}
	}))
	defer srv.Close()
	cfg := loopback(t, srv)
	cfg.AllowHTTP = true // proves a downgrade is refused even when http is allowed
	c, _ := New(cfg)

	for path, want := range map[string]error{"/meta": ErrDestinationDenied, "/downgrade": ErrRedirectDenied, "/scheme": ErrRedirectDenied, "/loop": ErrRedirectDenied} {
		if _, err := get(t, c, hostPort(srv, "example.com")+path); !errors.Is(err, want) {
			t.Errorf("%s: err = %v, want %v", path, err, want)
		}
	}

	req, _ := http.NewRequest(http.MethodGet, hostPort(srv, "example.com")+"/cross", nil)
	req.Header.Set("X-Api-Key", "secret")
	req.Header.Set("Authorization", "Bearer t")
	req.Header.Set("Accept", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("cross-origin redirect to an allowed destination: %v", err)
	}
	resp.Body.Close()
	if got := resp.Header.Get("X-Seen-Key"); got != "||application/json" {
		t.Fatalf("headers after a cross-origin hop = %q, want only Accept kept", got)
	}
}

func portOf(srv *httptest.Server) string {
	_, p, _ := net.SplitHostPort(srv.Listener.Addr().String())
	return p
}

func TestNoProxyAndTLSFloor(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	c, _ := New(Config{})
	tr := c.hc.Transport.(*http.Transport)
	if tr.Proxy != nil {
		t.Error("a proxy would bypass the vetting")
	}
	if tr.TLSClientConfig.InsecureSkipVerify || tr.TLSClientConfig.MinVersion < 0x0303 {
		t.Error("TLS config weakened")
	}
}

func TestTwoHopRedirectNeverReturnsCredentialHeaders(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/hop1":
			http.Redirect(w, r, "https://www.example.com:"+portOf(srv)+"/hop2", http.StatusFound)
		case "/hop2":
			http.Redirect(w, r, "https://www.example.com:"+portOf(srv)+"/echo", http.StatusFound)
		case "/echo":
			w.Header().Set("X-Seen", r.Header.Get("X-Api-Key")+"|"+r.Header.Get("Authorization"))
		}
	}))
	defer srv.Close()
	c, _ := New(loopback(t, srv))
	req, _ := http.NewRequest(http.MethodGet, hostPort(srv, "example.com")+"/hop1", nil)
	req.Header.Set("X-Api-Key", "secret")
	req.Header.Set("Authorization", "Bearer t")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := resp.Header.Get("X-Seen"); got != "|" {
		t.Fatalf("credentials reached the second hop on the foreign origin: %q", got)
	}
}

func TestCrossOriginTemporaryRedirectWithBodyRefused(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://www.example.com:"+portOf(srv)+"/x", http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	c, _ := New(loopback(t, srv))
	req, _ := http.NewRequest(http.MethodPost, hostPort(srv, "example.com")+"/", strings.NewReader("payload"))
	if _, err := c.Do(req); !errors.Is(err, ErrRedirectDenied) {
		t.Fatalf("err = %v, want ErrRedirectDenied", err)
	}
}

func TestErrorsDoNotCarryPathOrQuery(t *testing.T) {
	c, _ := New(Config{Resolver: &fakeResolver{answers: [][]netip.Addr{addrs("10.0.0.1")}}, dial: (&recorder{}).dial})
	_, err := get(t, c, "https://integration.example/hook/PATHSECRET?token=SECRETQUERY")
	if !errors.Is(err, ErrDestinationDenied) {
		t.Fatalf("err = %v", err)
	}
	if s := err.Error(); strings.Contains(s, "PATHSECRET") || strings.Contains(s, "SECRETQUERY") {
		t.Fatalf("error leaks the URL path/query: %s", s)
	}
}

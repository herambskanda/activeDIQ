package egress_test

// TM-F-EGRESS (threat-model §5.9, §15): an outbound integration must not reach loopback,
// link-local, cloud-metadata or private ranges without an allow-list entry; no redirect may
// escape; DNS rebinding must not work; TLS must be verified; no webhook may leave unsigned.
// Covers TM-TB9-T1, TM-TB9-T8 (bounded redirects), TM-TB9-T9 and TM-TB15-T7. Attacker model: X5
// controls an integration URL, the DNS answers for its host, and the redirects its server sends.
// Every case drives the product's own entry points (egress.Client.Do/DialStream, webhook.Sender,
// syslog.Send) against real listeners; a "refused" case also asserts the target saw no traffic.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/egress"
	"github.com/skenzeriq/activediq/internal/platform/notify/syslog"
	"github.com/skenzeriq/activediq/internal/platform/webhook"
)

type seqResolver struct {
	mu      sync.Mutex
	answers map[string][][]netip.Addr // per host: one answer per call; the last repeats
	calls   map[string]int
}

func newResolver(host string, answers ...[]string) *seqResolver {
	r := &seqResolver{answers: map[string][][]netip.Addr{}, calls: map[string]int{}}
	r.set(host, answers...)
	return r
}

func (r *seqResolver) set(host string, answers ...[]string) {
	for _, a := range answers {
		var as []netip.Addr
		for _, s := range a {
			as = append(as, netip.MustParseAddr(s))
		}
		r.answers[host] = append(r.answers[host], as)
	}
}

func (r *seqResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a := r.answers[host]
	if len(a) == 0 {
		return nil, fmt.Errorf("no such host %s", host)
	}
	i := r.calls[host]
	if i >= len(a) {
		i = len(a) - 1
	}
	r.calls[host]++
	return a[i], nil
}

func (r *seqResolver) count(host string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls[host]
}

func pfx(s ...string) []netip.Prefix {
	var o []netip.Prefix
	for _, p := range s {
		o = append(o, netip.MustParsePrefix(p))
	}
	return o
}

func mustClient(t *testing.T, cfg egress.Config) *egress.Client {
	t.Helper()
	c, err := egress.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.CloseIdleConnections)
	return c
}

func get(t *testing.T, c *egress.Client, url string, hdr map[string]string) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	return c.Do(req)
}

// listener counts connections accepted on addr (IP:0); it speaks HTTP via h.
func counted(t *testing.T, addr string, h http.Handler, tlsOn bool) (*httptest.Server, *atomic.Int32, string) {
	t.Helper()
	l, err := net.Listen("tcp", addr+":0")
	if err != nil {
		t.Skipf("cannot listen on %s: %v", addr, err)
	}
	var conns atomic.Int32
	s := httptest.NewUnstartedServer(h)
	s.Listener = l
	s.Config.ConnState = func(_ net.Conn, st http.ConnState) {
		if st == http.StateNew {
			conns.Add(1)
		}
	}
	if tlsOn {
		s.StartTLS()
	} else {
		s.Start()
	}
	t.Cleanup(s.Close)
	_, port, _ := net.SplitHostPort(l.Addr().String())
	return s, &conns, port
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") })
}

// --- 1. Destination ranges ------------------------------------------------------------------

func TestTMFEgress_BlockedRangesRefusedWithoutAllowList(t *testing.T) {
	c := mustClient(t, egress.Config{AllowHTTP: true})
	for name, ip := range map[string]string{
		"loopback v4":            "127.0.0.1",
		"loopback other":         "127.1.2.3",
		"loopback v6":            "::1",
		"unspecified":            "0.0.0.0",
		"link-local":             "169.254.10.10",
		"aws/azure/gcp metadata": "169.254.169.254",
		"ecs task metadata":      "169.254.170.2",
		"alibaba metadata":       "100.100.100.200",
		"oracle metadata":        "192.0.0.192",
		"aws metadata v6":        "fd00:ec2::254",
		"azure wireserver":       "168.63.129.16",
		"rfc1918 10/8":           "10.1.2.3",
		"rfc1918 172.16/12":      "172.16.0.9",
		"rfc1918 192.168/16":     "192.168.1.1",
		"cgnat":                  "100.64.0.1",
		"unique local":           "fc00::1",
		"multicast":              "224.0.0.1",
		"reserved":               "240.0.0.1",
		"v4-mapped loopback":     "::ffff:127.0.0.1",
		"v4-mapped metadata":     "::ffff:169.254.169.254",
		"nat64 metadata":         "64:ff9b::a9fe:a9fe",
		"6to4 loopback":          "2002:7f00:1::1",
	} {
		t.Run(name, func(t *testing.T) {
			host := ip
			if strings.Contains(ip, ":") {
				host = "[" + ip + "]"
			}
			for _, scheme := range []string{"http", "https"} {
				_, err := get(t, c, scheme+"://"+host+":8080/secret?token=abc", nil)
				if !errors.Is(err, egress.ErrDestinationDenied) {
					t.Fatalf("%s: err = %v, want ErrDestinationDenied", scheme, err)
				}
				if err != nil && strings.Contains(err.Error(), "token=abc") {
					t.Fatalf("error leaks the URL query: %v", err)
				}
			}
			if _, err := c.DialStream(context.Background(), ip, "6514", true); !errors.Is(err, egress.ErrDestinationDenied) {
				t.Fatalf("DialStream: err = %v, want ErrDestinationDenied", err)
			}
		})
	}
}

func TestTMFEgress_LoopbackServerSeesNoTraffic(t *testing.T) {
	_, conns, port := counted(t, "127.0.0.1", okHandler(), false)
	c := mustClient(t, egress.Config{AllowHTTP: true})
	for _, h := range []string{"127.0.0.1", "localhost", "2130706433", "0x7f.1", "017700000001"} {
		if _, err := get(t, c, "http://"+h+":"+port+"/", nil); err == nil {
			t.Fatalf("%s: request succeeded", h)
		}
	}
	// A name resolving to loopback is refused as well, wherever the resolver sends it.
	c2 := mustClient(t, egress.Config{AllowHTTP: true, Resolver: newResolver("internal.example", []string{"127.0.0.1"})})
	if _, err := get(t, c2, "http://internal.example:"+port+"/", nil); !errors.Is(err, egress.ErrDestinationDenied) {
		t.Fatalf("name->loopback: %v", err)
	}
	if n := conns.Load(); n != 0 {
		t.Fatalf("loopback server saw %d connection(s), want 0", n)
	}
}

func TestTMFEgress_MixedAnswerIsRefusedWholesale(t *testing.T) {
	_, conns, port := counted(t, "127.0.0.1", okHandler(), false)
	for _, answer := range [][]string{{"127.0.0.1", "169.254.169.254"}, {"169.254.169.254", "127.0.0.1"}} {
		c := mustClient(t, egress.Config{AllowHTTP: true, Allow: pfx("127.0.0.0/8"), Resolver: newResolver("mix.example", answer)})
		if _, err := get(t, c, "http://mix.example:"+port+"/", nil); !errors.Is(err, egress.ErrDestinationDenied) {
			t.Fatalf("answer %v: err = %v", answer, err)
		}
	}
	if n := conns.Load(); n != 0 {
		t.Fatalf("server saw %d connection(s) although an answer was not permitted", n)
	}
}

func TestTMFEgress_AllowListIsExactAndMetadataIsNeverAllowListable(t *testing.T) {
	_, conns, port := counted(t, "127.0.0.1", okHandler(), false)
	// Positive control: the allow-listed range stays reachable by design.
	c := mustClient(t, egress.Config{AllowHTTP: true, Allow: pfx("127.0.0.1/32")})
	resp, err := get(t, c, "http://127.0.0.1:"+port+"/", nil)
	if err != nil {
		t.Fatalf("allow-listed destination refused: %v", err)
	}
	resp.Body.Close()
	// An entry for one range opens no other range.
	other := mustClient(t, egress.Config{AllowHTTP: true, Allow: pfx("10.0.0.0/8")})
	if _, err := get(t, other, "http://127.0.0.1:"+port+"/", nil); !errors.Is(err, egress.ErrDestinationDenied) {
		t.Fatalf("10/8 entry reached loopback: %v", err)
	}
	if n := conns.Load(); n != 1 {
		t.Fatalf("connections = %d, want exactly the allow-listed one", n)
	}
	// Metadata cannot be allow-listed by any prefix that covers it, including mapped/translated forms.
	for _, p := range []string{"169.254.169.254/32", "169.254.0.0/16", "0.0.0.0/0", "100.64.0.0/10", "192.0.0.0/24",
		"fc00::/7", "::/0", "64:ff9b::/96", "2002::/16", "168.63.129.16/32"} {
		if _, err := egress.New(egress.Config{Allow: pfx(p)}); !errors.Is(err, egress.ErrBadConfig) {
			t.Errorf("allow-list %s accepted: err = %v", p, err)
		}
	}
	// A v4-mapped spelling of an entry is not a way round the rule: it neither accepts metadata nor
	// opens the unmapped range.
	if c, err := egress.New(egress.Config{AllowHTTP: true, Allow: pfx("::ffff:169.254.169.254/128", "::ffff:127.0.0.0/104")}); err == nil {
		if _, err := get(t, c, "http://169.254.169.254/", nil); !errors.Is(err, egress.ErrDestinationDenied) {
			t.Fatalf("mapped metadata entry: %v", err)
		}
		if _, err := get(t, c, "http://127.0.0.1:"+port+"/", nil); !errors.Is(err, egress.ErrDestinationDenied) {
			t.Fatalf("mapped loopback entry: %v", err)
		}
	}
	// Even a broad private entry never reaches a metadata address.
	b := mustClient(t, egress.Config{AllowHTTP: true, Allow: pfx("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")})
	if _, err := get(t, b, "http://169.254.169.254/latest/meta-data/", nil); !errors.Is(err, egress.ErrDestinationDenied) {
		t.Fatalf("metadata with RFC1918 allow-list: %v", err)
	}
}

func TestTMFEgress_SchemeAndCredentialsRefusedBeforeAnyLookup(t *testing.T) {
	r := newResolver("x.example", []string{"127.0.0.1"})
	c := mustClient(t, egress.Config{Resolver: r, Allow: pfx("127.0.0.0/8")})
	for u, want := range map[string]error{
		"http://x.example/":          egress.ErrSchemeDenied,
		"ftp://x.example/":           egress.ErrSchemeDenied,
		"file:///etc/passwd":         egress.ErrBadRequest,
		"gopher://x.example:70/_x":   egress.ErrSchemeDenied,
		"https://user:pw@x.example/": egress.ErrBadRequest,
		"https:///nohost":            egress.ErrBadRequest,
	} {
		if _, err := get(t, c, u, nil); !errors.Is(err, want) {
			t.Errorf("%s: err = %v, want %v", u, err, want)
		}
	}
	if n := r.count("x.example"); n != 0 {
		t.Errorf("resolver consulted %d times for refused requests", n)
	}
}

// --- 2. Redirects ---------------------------------------------------------------------------

func TestTMFEgress_RedirectCannotEscapeTheAllowList(t *testing.T) {
	_, evilConns, evilPort := counted(t, "127.0.0.2", okHandler(), false)
	for name, target := range map[string]string{
		"to another loopback address": "http://127.0.0.2:" + evilPort + "/",
		"to cloud metadata":           "http://169.254.169.254/latest/meta-data/iam/",
		"to a private address":        "http://10.0.0.5/admin",
		"to metadata via v4-mapped":   "http://[::ffff:169.254.169.254]/",
		"to a file URL":               "file:///etc/passwd",
		"to gopher":                   "gopher://127.0.0.1:6379/_FLUSHALL",
	} {
		t.Run(name, func(t *testing.T) {
			start, _, port := counted(t, "127.0.0.1", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, target, http.StatusFound)
			}), false)
			_ = start
			c := mustClient(t, egress.Config{AllowHTTP: true, Allow: pfx("127.0.0.1/32")})
			resp, err := get(t, c, "http://127.0.0.1:"+port+"/", nil)
			if err == nil {
				resp.Body.Close()
				t.Fatalf("redirect followed, status %d", resp.StatusCode)
			}
			if !errors.Is(err, egress.ErrRedirectDenied) && !errors.Is(err, egress.ErrDestinationDenied) {
				t.Fatalf("err = %v, want a typed refusal", err)
			}
		})
	}
	if n := evilConns.Load(); n != 0 {
		t.Fatalf("redirect target saw %d connection(s)", n)
	}
}

func TestTMFEgress_RedirectNameRebindsToForbiddenAddress(t *testing.T) {
	// The redirect points at a harmless-looking name whose DNS answer is a metadata address.
	r := newResolver("cdn.example", []string{"169.254.169.254"})
	_, _, port := counted(t, "127.0.0.1", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://cdn.example/x", http.StatusMovedPermanently)
	}), false)
	c := mustClient(t, egress.Config{AllowHTTP: true, Allow: pfx("127.0.0.1/32"), Resolver: r})
	if _, err := get(t, c, "http://127.0.0.1:"+port+"/", nil); !errors.Is(err, egress.ErrDestinationDenied) {
		t.Fatalf("err = %v, want ErrDestinationDenied", err)
	}
}

func TestTMFEgress_HTTPSDowngradeAndLoopsAndChainsRefused(t *testing.T) {
	plain, plainConns, plainPort := counted(t, "127.0.0.1", okHandler(), false)
	_ = plain
	var tlsPort string
	tsrv, _, tp := counted(t, "127.0.0.1", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/down":
			http.Redirect(w, r, "http://127.0.0.1:"+plainPort+"/", http.StatusFound)
		case "/loop":
			http.Redirect(w, r, "/loop", http.StatusFound)
		default:
			_, _ = io.WriteString(w, "ok")
		}
	}), true)
	tlsPort = tp
	roots := x509.NewCertPool()
	roots.AddCert(tsrv.Certificate())
	c := mustClient(t, egress.Config{AllowHTTP: true, Allow: pfx("127.0.0.1/32"), RootCAs: roots})

	if _, err := get(t, c, "https://127.0.0.1:"+tlsPort+"/down", nil); !errors.Is(err, egress.ErrRedirectDenied) {
		t.Fatalf("https->http downgrade: %v", err)
	}
	if n := plainConns.Load(); n != 0 {
		t.Fatalf("downgrade target saw %d connection(s) although AllowHTTP is on", n)
	}
	if _, err := get(t, c, "https://127.0.0.1:"+tlsPort+"/loop", nil); !errors.Is(err, egress.ErrRedirectDenied) {
		t.Fatalf("redirect loop: %v", err)
	}
	resp, err := get(t, c, "https://127.0.0.1:"+tlsPort+"/fine", nil)
	if err != nil {
		t.Fatalf("positive control: %v", err)
	}
	resp.Body.Close()
}

func TestTMFEgress_CrossOriginRedirectDropsCredentialsAndRefusesBodies(t *testing.T) {
	var got atomic.Value
	_, _, bPort := counted(t, "127.0.0.2", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Store(r.Header.Clone())
		_, _ = io.WriteString(w, "b")
	}), false)
	_, _, aPort := counted(t, "127.0.0.1", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.2:"+bPort+"/", http.StatusFound)
	}), false)
	c := mustClient(t, egress.Config{AllowHTTP: true, Allow: pfx("127.0.0.0/8")})
	resp, err := get(t, c, "http://127.0.0.1:"+aPort+"/", map[string]string{
		"Authorization": "Bearer s3cret", "Cookie": "sid=1", "X-Api-Key": "k", "Proxy-Authorization": "x", "User-Agent": "diq"})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	h, _ := got.Load().(http.Header)
	for _, k := range []string{"Authorization", "Cookie", "X-Api-Key", "Proxy-Authorization"} {
		if h.Get(k) != "" {
			t.Errorf("header %s followed the redirect to another origin", k)
		}
	}

	_, bConns, bp2 := counted(t, "127.0.0.2", okHandler(), false)
	_, _, ap2 := counted(t, "127.0.0.1", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.2:"+bp2+"/", http.StatusTemporaryRedirect)
	}), false)
	req, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1:"+ap2+"/", strings.NewReader(`{"secret":1}`))
	if resp, err := c.Do(req); !errors.Is(err, egress.ErrRedirectDenied) {
		if resp != nil {
			resp.Body.Close()
		}
		t.Fatalf("cross-origin 307 with body: %v", err)
	}
	if n := bConns.Load(); n != 0 {
		t.Fatalf("body was re-sent to another origin (%d connections)", n)
	}
}

// --- 3. DNS rebinding -----------------------------------------------------------------------

func TestTMFEgress_RebindingIsNotUsable(t *testing.T) {
	_, conns, port := counted(t, "127.0.0.1", okHandler(), false)

	// Permitted at "check time", forbidden at "use time": a lookup per dial vets the answer that is
	// dialled, so the second connection (new lookup) is refused, and the first lookup is the only
	// one a connection ever uses.
	r := newResolver("rebind.example", []string{"127.0.0.1"}, []string{"169.254.169.254"})
	c := mustClient(t, egress.Config{AllowHTTP: true, Allow: pfx("127.0.0.1/32"), Resolver: r})
	resp, err := get(t, c, "http://rebind.example:"+port+"/", nil)
	if err != nil {
		t.Fatalf("first request: %v", err)
	}
	resp.Body.Close()
	if n := r.count("rebind.example"); n != 1 {
		t.Fatalf("lookups for first request = %d, want exactly 1 (no second lookup between check and dial)", n)
	}
	c.CloseIdleConnections()
	if _, err := get(t, c, "http://rebind.example:"+port+"/", nil); !errors.Is(err, egress.ErrDestinationDenied) {
		t.Fatalf("after rebind: err = %v, want ErrDestinationDenied", err)
	}

	// Forbidden first, permitted later: the attacker cannot get a pass by flipping the answer
	// after we refused; the refused request sends nothing.
	before := conns.Load()
	r2 := newResolver("flip.example", []string{"169.254.169.254"}, []string{"127.0.0.1"})
	c2 := mustClient(t, egress.Config{AllowHTTP: true, Allow: pfx("127.0.0.1/32"), Resolver: r2})
	if _, err := get(t, c2, "http://flip.example:"+port+"/", nil); !errors.Is(err, egress.ErrDestinationDenied) {
		t.Fatalf("forbidden-first: %v", err)
	}
	if conns.Load() != before {
		t.Fatal("a connection was made on a refused lookup")
	}

	// Rebinding through the stream dialer used by syslog.
	r3 := newResolver("siem.example", []string{"127.0.0.1"}, []string{"10.9.9.9"})
	c3 := mustClient(t, egress.Config{Allow: pfx("127.0.0.1/32"), Resolver: r3})
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	_, lp, _ := net.SplitHostPort(l.Addr().String())
	conn, err := c3.DialStream(context.Background(), "siem.example", lp, false)
	if err != nil {
		t.Fatalf("stream first dial: %v", err)
	}
	conn.Close()
	if _, err := c3.DialStream(context.Background(), "siem.example", lp, false); !errors.Is(err, egress.ErrDestinationDenied) {
		t.Fatalf("stream after rebind: %v", err)
	}
}

// --- 4. TLS ---------------------------------------------------------------------------------

func TestTMFEgress_TLSIsAlwaysVerified(t *testing.T) {
	srv, _, port := counted(t, "127.0.0.1", okHandler(), true)
	allow := pfx("127.0.0.0/8")
	url := "https://127.0.0.1:" + port + "/"

	// Untrusted certificate (self-signed, no operator CA): refused.
	c := mustClient(t, egress.Config{Allow: allow})
	var uae x509.UnknownAuthorityError
	if _, err := get(t, c, url, nil); !errors.As(err, &uae) {
		t.Fatalf("untrusted cert: err = %v, want x509.UnknownAuthorityError", err)
	}

	// Positive control: the same server with the operator CA.
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	good := mustClient(t, egress.Config{Allow: allow, RootCAs: roots})
	resp, err := get(t, good, url, nil)
	if err != nil {
		t.Fatalf("trusted cert: %v", err)
	}
	resp.Body.Close()

	// Right CA, wrong host name: refused. The httptest certificate is for example.com and loopback.
	r := newResolver("not-the-cert.test", []string{"127.0.0.1"})
	wrong := mustClient(t, egress.Config{Allow: allow, RootCAs: roots, Resolver: r})
	var hn x509.HostnameError
	if _, err := get(t, wrong, "https://not-the-cert.test:"+port+"/", nil); !errors.As(err, &hn) {
		t.Fatalf("wrong host name: err = %v, want x509.HostnameError", err)
	}

	// Protocol floor: a TLS 1.1-only server is refused even with the right CA.
	old, _, oldPort := counted(t, "127.0.0.1", okHandler(), false)
	_ = old
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tl := tls.NewListener(l, &tls.Config{Certificates: srv.TLS.Certificates, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11})
	go func() {
		for {
			cn, err := tl.Accept()
			if err != nil {
				return
			}
			go func() { defer cn.Close(); _ = cn.(*tls.Conn).Handshake() }()
		}
	}()
	defer tl.Close()
	_, lp, _ := net.SplitHostPort(l.Addr().String())
	if _, err := get(t, good, "https://127.0.0.1:"+lp+"/", nil); err == nil {
		t.Fatal("TLS 1.1 server accepted")
	}
	_ = oldPort
}

func TestTMFEgress_NoSwitchToTurnVerificationOffOrReachAProxy(t *testing.T) {
	ty := reflect.TypeOf(egress.Config{})
	for i := 0; i < ty.NumField(); i++ {
		f := ty.Field(i)
		if !f.IsExported() {
			continue
		}
		n := strings.ToLower(f.Name)
		for _, bad := range []string{"insecure", "skip", "noverify", "verify", "proxy", "tlsconfig", "transport", "dial"} {
			if strings.Contains(n, bad) {
				t.Errorf("egress.Config exposes %q: verification/vetting must not be configurable", f.Name)
			}
		}
	}
	// An environment proxy must not capture the traffic: point one at a counting listener.
	_, proxyConns, pport := counted(t, "127.0.0.1", okHandler(), false)
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:"+pport)
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:"+pport)
	t.Setenv("http_proxy", "http://127.0.0.1:"+pport)
	t.Setenv("NO_PROXY", "")
	_, _, tport := counted(t, "127.0.0.2", okHandler(), false)
	c := mustClient(t, egress.Config{AllowHTTP: true, Allow: pfx("127.0.0.2/32")})
	resp, err := get(t, c, "http://127.0.0.2:"+tport+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if n := proxyConns.Load(); n != 0 {
		t.Fatalf("environment proxy used (%d connections)", n)
	}
}

// --- 5. Webhooks ----------------------------------------------------------------------------

func TestTMFEgress_NoWebhookLeavesUnsigned(t *testing.T) {
	sec, err := webhook.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	g, err := webhook.NewSigner(sec)
	if err != nil {
		t.Fatal(err)
	}
	var unsigned, verified atomic.Int32
	srv, _, port := counted(t, "127.0.0.1", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if webhook.Verify(r.Header, body, time.Now(), 0, sec) != nil {
			unsigned.Add(1)
			http.Error(w, "bad signature", http.StatusUnauthorized)
			return
		}
		verified.Add(1)
	}), false)
	_ = srv
	c := mustClient(t, egress.Config{AllowHTTP: true, Allow: pfx("127.0.0.1/32")})
	s, err := webhook.NewSender(c)
	if err != nil {
		t.Fatal(err)
	}
	url := "http://127.0.0.1:" + port + "/hook"
	m := webhook.Message{ID: "evt_1", Body: []byte(`{"type":"user.created"}`)}
	res, err := s.Send(context.Background(), url, m, g)
	if err != nil || !res.Delivered {
		t.Fatalf("signed delivery: %+v %v", res, err)
	}

	// No signer, an empty signer, a destroyed secret: nothing reaches the receiver.
	if _, err := s.Send(context.Background(), url, m, nil); err == nil {
		t.Error("nil signer sent")
	}
	if _, err := s.Send(context.Background(), url, m, &webhook.Signer{}); !errors.Is(err, webhook.ErrBadSecret) {
		t.Errorf("empty signer: %v", err)
	}
	dead, _ := webhook.NewSecret()
	dg, _ := webhook.NewSigner(dead)
	dead.Destroy()
	if _, err := s.Send(context.Background(), url, m, dg); !errors.Is(err, webhook.ErrBadSecret) {
		t.Errorf("destroyed secret: %v", err)
	}
	if unsigned.Load() != 0 || verified.Load() != 1 {
		t.Fatalf("receiver saw unsigned=%d verified=%d, want 0 and 1", unsigned.Load(), verified.Load())
	}

	// The receiver side refuses everything that is not a fresh, intact, correctly keyed message.
	now := time.Now()
	sig, err := g.Sign("evt_1", now, m.Body)
	if err != nil {
		t.Fatal(err)
	}
	hdr := func(id string, ts time.Time, sig string) http.Header {
		h := http.Header{}
		h.Set(webhook.HeaderID, id)
		h.Set(webhook.HeaderTimestamp, fmt.Sprint(ts.Unix()))
		h.Set(webhook.HeaderSignature, sig)
		return h
	}
	if err := webhook.Verify(hdr("evt_1", now, sig), m.Body, now, 0, sec); err != nil {
		t.Fatalf("control: %v", err)
	}
	other, _ := webhook.NewSecret()
	for name, tc := range map[string]struct {
		h    http.Header
		body []byte
		sec  []interface{}
	}{
		"no headers":   {http.Header{}, m.Body, nil},
		"empty sig":    {hdr("evt_1", now, ""), m.Body, nil},
		"garbage sig":  {hdr("evt_1", now, "v1,AAAA"), m.Body, nil},
		"unversioned":  {hdr("evt_1", now, strings.TrimPrefix(sig, "v1,")), m.Body, nil},
		"altered body": {hdr("evt_1", now, sig), []byte(`{"type":"user.deleted"}`), nil},
		"altered id":   {hdr("evt_2", now, sig), m.Body, nil},
		"altered time": {hdr("evt_1", now.Add(1*time.Second), sig), m.Body, nil},
		"replay (old)": {hdr("evt_1", now.Add(-time.Hour), sig), m.Body, nil},
		"future":       {hdr("evt_1", now.Add(time.Hour), sig), m.Body, nil},
	} {
		if err := webhook.Verify(tc.h, tc.body, now, 0, sec); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := webhook.Verify(hdr("evt_1", now, sig), m.Body, now, 0, other); err == nil {
		t.Error("verified under a different secret")
	}
}

func TestTMFEgress_WebhookToInternalTargetRefusedAndNeverSigned(t *testing.T) {
	sec, _ := webhook.NewSecret()
	g, _ := webhook.NewSigner(sec)
	_, conns, port := counted(t, "127.0.0.1", okHandler(), false)
	c := mustClient(t, egress.Config{AllowHTTP: true}) // empty allow-list
	s, _ := webhook.NewSender(c)
	m := webhook.Message{ID: "evt_2", Body: []byte(`{}`)}
	for _, u := range []string{"http://127.0.0.1:" + port + "/", "http://169.254.169.254/latest/", "https://10.0.0.7/hook", "http://[::1]:" + port + "/"} {
		if _, err := s.Send(context.Background(), u, m, g); !errors.Is(err, egress.ErrDestinationDenied) {
			t.Errorf("%s: err = %v", u, err)
		}
	}
	if conns.Load() != 0 {
		t.Fatal("internal receiver was reached")
	}
	if _, err := webhook.NewSender(nil); err == nil {
		t.Fatal("sender built without the egress client")
	}
}

// --- 6. SIEM syslog -------------------------------------------------------------------------

func TestTMFEgress_SyslogIsVerifiedTLSUnlessExplicitlyOptedIn(t *testing.T) {
	// Default is TLS on 6514.
	d, err := syslog.Destination{ID: "s1", Host: "siem.example"}.Normalize()
	if err != nil || d.Transport != syslog.TLS || d.Port != 6514 || !d.View().TLSVerified {
		t.Fatalf("default destination: %+v %v", d, err)
	}
	// Plaintext only with the opt-in, which is audited, shown with a warning; UDP is not offered.
	if _, err := (syslog.Destination{ID: "s1", Host: "siem.example", Transport: syslog.TCP}).Normalize(); !errors.Is(err, syslog.ErrPlaintextNotOptedIn) {
		t.Fatalf("plaintext without opt-in: %v", err)
	}
	if _, err := (syslog.Destination{ID: "s1", Host: "siem.example", Transport: "udp"}).Normalize(); !errors.Is(err, syslog.ErrBadDestination) {
		t.Fatalf("udp: %v", err)
	}
	if _, err := (syslog.Destination{ID: "s1", Host: "siem.example", PlaintextOptIn: true}).Normalize(); !errors.Is(err, syslog.ErrBadDestination) {
		t.Fatalf("opt-in smuggled onto TLS: %v", err)
	}
	pd, err := syslog.Destination{ID: "s2", Host: "siem.example", Transport: syslog.TCP, PlaintextOptIn: true}.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	if v := pd.View(); v.TLSVerified || v.Warning == "" || !v.PlaintextOptIn {
		t.Fatalf("plaintext view does not warn: %+v", v)
	}

	// A TLS destination whose certificate is not trusted never receives a byte.
	srv := httptest.NewUnstartedServer(nil)
	srv.StartTLS()
	srv.Close()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	var received atomic.Int32
	tl := tls.NewListener(l, &tls.Config{Certificates: srv.TLS.Certificates})
	go func() {
		for {
			cn, err := tl.Accept()
			if err != nil {
				return
			}
			go func() {
				defer cn.Close()
				if cn.(*tls.Conn).Handshake() != nil {
					return
				}
				n, _ := io.Copy(io.Discard, cn)
				received.Add(int32(n))
			}()
		}
	}()
	_, lp, _ := net.SplitHostPort(l.Addr().String())
	var port int
	fmt.Sscan(lp, &port)
	dest := syslog.Destination{ID: "s3", Host: "127.0.0.1", Port: port}
	msg := syslog.Message{Facility: 13, Severity: 5, Hostname: "diq", App: "activediq", ID: "e1", Text: "hello"}

	untrusting := mustClient(t, egress.Config{Allow: pfx("127.0.0.1/32")})
	var uae x509.UnknownAuthorityError
	if err := syslog.Send(context.Background(), untrusting, dest, msg); !errors.As(err, &uae) {
		t.Fatalf("untrusted SIEM certificate: err = %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	if received.Load() != 0 {
		t.Fatal("event bytes were sent to an unverified TLS peer")
	}

	// Without an allow-list entry the internal SIEM is not reachable at all.
	closed := mustClient(t, egress.Config{})
	if err := syslog.Send(context.Background(), closed, dest, msg); !errors.Is(err, egress.ErrDestinationDenied) {
		t.Fatalf("SIEM on loopback without allow-list: %v", err)
	}

	// Positive control: with the operator CA the same destination receives the record.
	roots := x509.NewCertPool()
	for _, der := range srv.TLS.Certificates[0].Certificate {
		if cert, err := x509.ParseCertificate(der); err == nil {
			roots.AddCert(cert)
		}
	}
	trusting := mustClient(t, egress.Config{Allow: pfx("127.0.0.1/32"), RootCAs: roots})
	if err := syslog.Send(context.Background(), trusting, dest, msg); err != nil {
		t.Fatalf("trusted SIEM: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for received.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if received.Load() == 0 {
		t.Fatal("trusted SIEM received nothing")
	}
}

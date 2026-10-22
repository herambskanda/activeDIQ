package server

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/compose/config"
)

// Acceptance 1: a fresh install serves only TLS, with the per-install certificate whose fingerprint
// is the one that would be logged.
func TestAPIListenerSpeaksOnlyTLSWithPerInstallCertificate(t *testing.T) {
	cfg := config.Config{APIAddr: "127.0.0.1:0", APITLSDir: t.TempDir() + "/tls"}
	id, err := apiIdentity(cfg, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", cfg.APIAddr)
	if err != nil {
		t.Fatal(err)
	}
	srv := newAPIServer(cfg.APIAddr, http.NotFoundHandler(), id.TLSConfig())
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	defer srv.Close()

	// Trust exactly the install's own certificate: the client verifies the chain and name normally.
	leaf, err := x509.ParseCertificate(id.Certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)

	// TLS 1.1 is refused by the server: offer only 1.1 (Go's client default floor is 1.2, which
	// would fail client-side without ever reaching the server) and require the server's alert.
	_, err = tls.Dial("tcp", ln.Addr().String(), &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS11, MaxVersion: tls.VersionTLS11})
	if err == nil {
		t.Fatal("TLS 1.1 must be refused")
	}
	if !strings.Contains(err.Error(), "protocol version not supported") {
		t.Fatalf("TLS 1.1 must be refused by the server with a protocol-version alert, got: %v", err)
	}
	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{RootCAs: roots})
	if err != nil {
		t.Fatal(err)
	}
	der := conn.ConnectionState().PeerCertificates[0].Raw
	conn.Close()
	sum := sha256.Sum256(der)
	got := strings.ReplaceAll(id.Fingerprint, ":", "")
	if !strings.EqualFold(got, hex.EncodeToString(sum[:])) {
		t.Fatalf("fingerprint %s does not match the served certificate", id.Fingerprint)
	}

	// Plain HTTP gets no HTTP answer.
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://" + ln.Addr().String() + "/")
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound {
			t.Fatal("plaintext HTTP request was served")
		}
	}

	// Restart reuses the certificate.
	again, err := apiIdentity(cfg, time.Now())
	if err != nil || again.Fingerprint != id.Fingerprint {
		t.Fatalf("restart changed the certificate: %v", err)
	}
}

// Acceptance 2: no TLS configured and a non-loopback address fails startup.
func TestNonLoopbackWithoutTLSFailsStartup(t *testing.T) {
	for _, a := range []string{"0.0.0.0:8443", "10.0.0.5:8443", ":8443"} {
		if _, err := apiIdentity(config.Config{APIAddr: a}, time.Now()); err == nil {
			t.Errorf("%s without TLS must fail", a)
		}
		if _, err := apiIdentity(config.Config{APIAddr: a, APITLSDir: t.TempDir() + "/id"}, time.Now()); err != nil {
			t.Errorf("%s with TLS: %v", a, err)
		}
	}
}

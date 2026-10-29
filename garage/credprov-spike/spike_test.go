package credprovspike

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"credprovspike/importscan"
	"credprovspike/logon"
	"credprovspike/pin"
)

func dialer(addr string, pins []pin.Hash) logon.Dialer {
	return func(ctx context.Context) error {
		cfg, err := pin.Config(pins)
		if err != nil {
			return err
		}
		d := tls.Dialer{Config: cfg}
		c, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			return err
		}
		return c.Close()
	}
}

func srv(t *testing.T) (*httptest.Server, pin.Hash) {
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	s.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	s.StartTLS()
	t.Cleanup(s.Close)
	c, _ := x509.ParseCertificate(s.TLS.Certificates[0].Certificate[0])
	return s, pin.SPKIHash(c)
}

func TestPinnedServerReady(t *testing.T) {
	s, h := srv(t)
	if got := logon.Probe(context.Background(), dialer(s.Listener.Addr().String(), []pin.Hash{h}), []pin.Hash{h}); got != logon.Ready {
		t.Fatalf("got %v", got)
	}
}

func TestUnpinnedServerRefused(t *testing.T) {
	s, _ := srv(t)
	other := pin.Hash{1}
	if got := logon.Probe(context.Background(), dialer(s.Listener.Addr().String(), []pin.Hash{other}), []pin.Hash{other}); got != logon.ServerRefused {
		t.Fatalf("got %v", got)
	}
}

func TestBackupPinAccepted(t *testing.T) {
	s, h := srv(t)
	pins := []pin.Hash{{9}, h}
	if got := logon.Probe(context.Background(), dialer(s.Listener.Addr().String(), pins), pins); got != logon.Ready {
		t.Fatalf("got %v", got)
	}
}

func TestOfflineNeverBlocks(t *testing.T) {
	s, h := srv(t)
	addr := s.Listener.Addr().String()
	s.Close() // server gone
	start := time.Now()
	if got := logon.Probe(context.Background(), dialer(addr, []pin.Hash{h}), []pin.Hash{h}); got != logon.Offline {
		t.Fatalf("got %v", got)
	}
	if time.Since(start) > logon.Deadline+time.Second {
		t.Fatal("probe exceeded deadline")
	}
}

func TestHangIsBoundedAndOffline(t *testing.T) {
	hang := func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }
	start := time.Now()
	if got := logon.Probe(context.Background(), hang, []pin.Hash{{1}}); got != logon.Offline {
		t.Fatalf("got %v", got)
	}
	if time.Since(start) > logon.Deadline+time.Second {
		t.Fatal("not bounded")
	}
}

func TestNoPinsInert(t *testing.T) {
	if _, err := pin.Config(nil); err != pin.ErrNoPins {
		t.Fatal(err)
	}
	if logon.Probe(context.Background(), nil, nil) != logon.Disabled {
		t.Fatal("expected Disabled")
	}
}

func TestTLS12Refused(t *testing.T) {
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	s.TLS = &tls.Config{MaxVersion: tls.VersionTLS12}
	s.StartTLS()
	defer s.Close()
	c, _ := x509.ParseCertificate(s.TLS.Certificates[0].Certificate[0])
	h := pin.SPKIHash(c)
	if got := logon.Probe(context.Background(), dialer(s.Listener.Addr().String(), []pin.Hash{h}), []pin.Hash{h}); got != logon.Offline {
		t.Fatalf("downgrade must not reach Ready, got %v", got)
	}
}

// The import scan, run on a Windows PE we can build on this host: the Go linker emits a
// PE for GOOS=windows. A plain Go program imports kernel32 only; denied lists must catch
// a name when present (checked by Denied lookup, since a real offender needs a Windows build).
func TestImportScanDeniedList(t *testing.T) {
	for _, d := range []string{"ieframe.dll", "mshtml.dll", "comdlg32.dll", "shell32.dll", "webview2loader.dll", "wininet.dll"} {
		if _, ok := importscan.Denied[d]; !ok || strings.ToLower(d) != d {
			t.Fatalf("%s missing", d)
		}
	}
}

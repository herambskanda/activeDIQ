package apitls_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/apitls"
)

func TestGenerateThenReuse(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tls")
	now := time.Now()
	a, err := apitls.LoadOrGenerate(dir, "127.0.0.1:8080", now)
	if err != nil {
		t.Fatal(err)
	}
	b, err := apitls.LoadOrGenerate(dir, "127.0.0.1:8080", now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if a.Fingerprint != b.Fingerprint || len(a.Fingerprint) != 32*3-1 {
		t.Fatalf("fingerprints %q %q", a.Fingerprint, b.Fingerprint)
	}
	st, err := os.Stat(filepath.Join(dir, apitls.KeyFile))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("key file: %v %v", st, err)
	}
	if a.TLSConfig().MinVersion < 0x0303 {
		t.Fatal("TLS 1.2 minimum required")
	}
}

func TestRenewsNearExpiry(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	a, _ := apitls.LoadOrGenerate(dir, "localhost:1", now)
	b, err := apitls.LoadOrGenerate(dir, "localhost:1", now.Add(2*365*24*time.Hour-24*time.Hour))
	if err != nil || a.Fingerprint == b.Fingerprint {
		t.Fatalf("expected renewal: %v", err)
	}
}

func TestCorruptPairRegenerates(t *testing.T) {
	dir := t.TempDir()
	a, _ := apitls.LoadOrGenerate(dir, "localhost:1", time.Now())
	_ = os.WriteFile(filepath.Join(dir, apitls.KeyFile), []byte("junk"), 0o600)
	b, err := apitls.LoadOrGenerate(dir, "localhost:1", time.Now())
	if err != nil || a.Fingerprint == b.Fingerprint {
		t.Fatalf("expected regeneration: %v", err)
	}
}

func TestInMemory(t *testing.T) {
	if _, err := apitls.LoadOrGenerate("", "[::1]:0", time.Now()); err != nil {
		t.Fatal(err)
	}
}

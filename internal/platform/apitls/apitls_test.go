package apitls_test

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/apitls"
)

func TestGenerateThenReuse(t *testing.T) {
	dir := filepath.Join(tdir(t), "tls")
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
	dir := tdir(t)
	now := time.Now()
	a, _ := apitls.LoadOrGenerate(dir, "localhost:1", now)
	b, err := apitls.LoadOrGenerate(dir, "localhost:1", now.Add(2*365*24*time.Hour-24*time.Hour))
	if err != nil || a.Fingerprint == b.Fingerprint {
		t.Fatalf("expected renewal: %v", err)
	}
}

func gen(t *testing.T) (string, apitls.Identity) {
	t.Helper()
	dir := filepath.Join(tdir(t), "tls")
	id, err := apitls.LoadOrGenerate(dir, "localhost:1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return dir, id
}

func snapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, n := range []string{apitls.CertFile, apitls.KeyFile} {
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			t.Fatal(err)
		}
		out[n] = string(b)
	}
	return out
}

// mustFailUntouched asserts startup fails naming wantInErr and that the files keep their content.
func mustFailUntouched(t *testing.T, dir, wantInErr string) {
	t.Helper()
	before := snapshot(t, dir)
	_, err := apitls.LoadOrGenerate(dir, "localhost:1", time.Now())
	if err == nil {
		t.Fatal("expected startup failure")
	}
	if !strings.Contains(err.Error(), wantInErr) {
		t.Fatalf("error %q does not name %q", err, wantInErr)
	}
	_ = os.Chmod(dir, 0o700)
	_ = os.Chmod(filepath.Join(dir, apitls.KeyFile), 0o600)
	if !reflect.DeepEqual(before, snapshot(t, dir)) {
		t.Fatal("files were modified")
	}
}

func TestCorruptKeyFailsAndLeavesFiles(t *testing.T) {
	dir, _ := gen(t)
	_ = os.WriteFile(filepath.Join(dir, apitls.KeyFile), []byte("junk"), 0o600)
	mustFailUntouched(t, dir, apitls.KeyFile)
}

func TestMismatchedPairFails(t *testing.T) {
	dir, _ := gen(t)
	other, _ := gen(t)
	k, _ := os.ReadFile(filepath.Join(other, apitls.KeyFile))
	_ = os.WriteFile(filepath.Join(dir, apitls.KeyFile), k, 0o600)
	mustFailUntouched(t, dir, apitls.KeyFile)
}

func TestMissingKeyFails(t *testing.T) {
	dir, _ := gen(t)
	_ = os.Remove(filepath.Join(dir, apitls.KeyFile))
	if _, err := apitls.LoadOrGenerate(dir, "localhost:1", time.Now()); err == nil {
		t.Fatal("expected failure with certificate but no key")
	}
}

func TestMissingCertGenerates(t *testing.T) {
	dir, a := gen(t)
	_ = os.Remove(filepath.Join(dir, apitls.CertFile))
	b, err := apitls.LoadOrGenerate(dir, "localhost:1", time.Now())
	if err != nil || a.Fingerprint == b.Fingerprint {
		t.Fatalf("expected regeneration after crash between writes: %v", err)
	}
}

func TestUnreadableKeyFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads anything")
	}
	dir, _ := gen(t)
	key := filepath.Join(dir, apitls.KeyFile)
	before := snapshot(t, dir)
	_ = os.Chmod(key, 0)
	_, err := apitls.LoadOrGenerate(dir, "localhost:1", time.Now())
	_ = os.Chmod(key, 0o600)
	if err == nil || !strings.Contains(err.Error(), apitls.KeyFile) {
		t.Fatalf("want error naming key file, got %v", err)
	}
	if !reflect.DeepEqual(before, snapshot(t, dir)) {
		t.Fatal("files were modified")
	}
}

func TestInsecureDirectoryFails(t *testing.T) {
	dir, _ := gen(t)
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	mustFailUntouched(t, dir, "identity directory")
}

func TestWorldReadableKeyFails(t *testing.T) {
	dir, _ := gen(t)
	_ = os.Chmod(filepath.Join(dir, apitls.KeyFile), 0o644)
	mustFailUntouched(t, dir, apitls.KeyFile)
}

func TestSymlinkedFilesFail(t *testing.T) {
	for _, name := range []string{apitls.KeyFile, apitls.CertFile} {
		dir, _ := gen(t)
		p := filepath.Join(dir, name)
		real := p + ".real"
		if err := os.Rename(p, real); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(real, p); err != nil {
			t.Fatal(err)
		}
		if _, err := apitls.LoadOrGenerate(dir, "localhost:1", time.Now()); err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("%s: want symlink refusal, got %v", name, err)
		}
	}
}

func TestRenewalLogsOldAndNewFingerprints(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	dir := tdir(t)
	now := time.Now()
	a, _ := apitls.LoadOrGenerate(dir, "localhost:1", now)
	b, err := apitls.LoadOrGenerate(dir, "localhost:1", now.Add(2*365*24*time.Hour-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "level=WARN") || !strings.Contains(out, a.Fingerprint) || !strings.Contains(out, b.Fingerprint) {
		t.Fatalf("renewal log missing WARN/old/new fingerprints: %s", out)
	}
}

func TestInMemory(t *testing.T) {
	if _, err := apitls.LoadOrGenerate("", "[::1]:0", time.Now()); err != nil {
		t.Fatal(err)
	}
}

// tdir is a private temp directory (t.TempDir follows the umask, which may leave it group-writable).
func tdir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

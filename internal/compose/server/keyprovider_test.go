package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/compose/config"
	"github.com/skenzeriq/activediq/internal/platform/apitls"
)

const (
	kekA = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	kekB = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"
)

func kekCfg(t *testing.T, dir, kekHex string) config.Config {
	t.Helper()
	cfg := config.Config{APIAddr: "127.0.0.1:0", APITLSDir: dir, KEKID: config.DefaultKEKID}
	if kekHex != "" {
		cfg.KEKFile = filepath.Join(t.TempDir(), "kek")
		if err := os.WriteFile(cfg.KEKFile, []byte(kekHex+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return cfg
}

// Acceptance 1: with the KEK profile the key at rest is ciphertext, and a restart reuses the identity.
func TestAPIIdentitySealsKeyWithKEKProfile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tls")
	cfg := kekCfg(t, dir, kekA)
	id, err := apiIdentity(cfg, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, apitls.KeyFile)); !os.IsNotExist(err) {
		t.Fatalf("plaintext key file must not exist: %v", err)
	}
	sealed, err := os.ReadFile(filepath.Join(dir, apitls.SealedKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(sealed), "PRIVATE KEY") {
		t.Fatal("sealed file holds PEM")
	}
	again, err := apiIdentity(cfg, time.Now())
	if err != nil || again.Fingerprint != id.Fingerprint {
		t.Fatalf("restart must unseal the same identity: %v", err)
	}
}

// Acceptance 2: wrong KEK fails closed, leaves the sealed key untouched and leaks nothing.
func TestAPIIdentityWrongKEKFailsClosed(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tls")
	if _, err := apiIdentity(kekCfg(t, dir, kekA), time.Now()); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(dir, apitls.SealedKeyFile))
	_, err := apiIdentity(kekCfg(t, dir, kekB), time.Now())
	if err == nil {
		t.Fatal("wrong KEK must fail startup")
	}
	for _, leak := range []string{kekA, kekB} {
		if strings.Contains(err.Error(), leak) {
			t.Fatalf("error leaks KEK: %v", err)
		}
	}
	after, _ := os.ReadFile(filepath.Join(dir, apitls.SealedKeyFile))
	if string(before) != string(after) {
		t.Fatal("sealed key was modified")
	}
	if _, e := os.Stat(filepath.Join(dir, apitls.KeyFile)); !os.IsNotExist(e) {
		t.Fatal("must not fall back to a plaintext key")
	}
}

// Acceptance 2: no KEK for a sealed directory, or an unusable KEK file, fails closed.
func TestAPIIdentityMissingKEKFailsClosed(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tls")
	if _, err := apiIdentity(kekCfg(t, dir, kekA), time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := apiIdentity(kekCfg(t, dir, ""), time.Now()); err == nil {
		t.Fatal("sealed key with no KEK profile must fail, not regenerate")
	}
	missing := kekCfg(t, filepath.Join(t.TempDir(), "tls2"), "")
	missing.KEKFile = filepath.Join(t.TempDir(), "absent")
	if _, err := apiIdentity(missing, time.Now()); err == nil {
		t.Fatal("configured but missing KEK file must fail")
	}
	if _, err := os.Stat(filepath.Join(missing.APITLSDir, apitls.KeyFile)); err == nil {
		t.Fatal("no plaintext key may be generated")
	}
	for name, content := range map[string]string{"short": "abcd", "nothex": strings.Repeat("zz", 32), "empty": ""} {
		cfg := kekCfg(t, filepath.Join(t.TempDir(), "t"), "x")
		if err := os.WriteFile(cfg.KEKFile, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := apiIdentity(cfg, time.Now())
		if err == nil {
			t.Errorf("%s KEK must fail", name)
		} else if content != "" && strings.Contains(err.Error(), content) {
			t.Errorf("%s: error leaks file content", name)
		}
	}
	loose := kekCfg(t, filepath.Join(t.TempDir(), "t"), kekA)
	if err := os.Chmod(loose.KEKFile, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := apiIdentity(loose, time.Now()); err == nil {
		t.Fatal("group/world-readable KEK file must fail")
	}
}

// A legacy plaintext install is sealed in place on first start with the profile, keeping its identity.
func TestAPIIdentitySealsLegacyPlaintextKey(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tls")
	legacy, err := apiIdentity(kekCfg(t, dir, ""), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	id, err := apiIdentity(kekCfg(t, dir, kekA), time.Now())
	if err != nil || id.Fingerprint != legacy.Fingerprint {
		t.Fatalf("identity must survive sealing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, apitls.KeyFile)); !os.IsNotExist(err) {
		t.Fatal("plaintext key must be removed")
	}
}

func TestKEKFileRefusals(t *testing.T) {
	mk := func(content string) config.Config {
		cfg := kekCfg(t, filepath.Join(t.TempDir(), "t"), "x")
		if err := os.WriteFile(cfg.KEKFile, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return cfg
	}
	if _, err := apiIdentity(mk(strings.Repeat("00", 32)), time.Now()); err == nil {
		t.Error("all-zero KEK must fail")
	}
	// Symlink at the open site is refused even though the target is a valid 0600 KEK.
	cfg := kekCfg(t, filepath.Join(t.TempDir(), "t"), kekA)
	target := cfg.KEKFile
	cfg.KEKFile = filepath.Join(t.TempDir(), "kek-link")
	if err := os.Symlink(target, cfg.KEKFile); err != nil {
		t.Fatal(err)
	}
	if _, err := apiIdentity(cfg, time.Now()); err == nil {
		t.Error("symlinked KEK must fail")
	}
	if err := kekFileSupported("windows"); err == nil {
		t.Error("windows must refuse the file profile")
	}
	if err := kekFileSupported("linux"); err != nil {
		t.Errorf("linux: %v", err)
	}
}

func TestKEKFileOtherOwnerRefused(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to chown")
	}
	cfg := kekCfg(t, filepath.Join(t.TempDir(), "t"), kekA)
	if err := os.Chown(cfg.KEKFile, 12345, -1); err != nil {
		t.Skip(err)
	}
	if _, err := apiIdentity(cfg, time.Now()); err == nil {
		t.Error("KEK owned by another uid must fail")
	}
}

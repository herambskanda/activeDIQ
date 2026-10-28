package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/compose/config"
	"github.com/skenzeriq/activediq/internal/platform/apitls"
	"github.com/skenzeriq/activediq/internal/platform/keys"
)

const testPassphrase = "correct horse battery staple"

// kekEnv builds a getenv over a fresh keystore dir and passphrase file (outside it).
func kekEnv(t *testing.T) (map[string]string, func(string) string) {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "kek")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	pf := filepath.Join(root, "passphrase")
	if err := os.WriteFile(pf, []byte(testPassphrase+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := map[string]string{EnvKEKProvider: ProviderPassphrase, EnvKEKDir: dir, EnvKEKPassphraseFile: pf}
	return m, func(k string) string { return m[k] }
}

// testKEK initialises a passphrase keystore (cheapest KDF) and returns its validated config.
func testKEK(t *testing.T) KEKConfig {
	t.Helper()
	_, get := kekEnv(t)
	return initKEK(t, get)
}

func initKEK(t *testing.T, get func(string) string) KEKConfig {
	t.Helper()
	if err := kekInit(nil, get, &bytes.Buffer{}, keys.FloorKDF); err != nil {
		t.Fatal(err)
	}
	kc, err := LoadKEKConfig(get)
	if err != nil {
		t.Fatal(err)
	}
	return kc
}

func kekCode(err error) string {
	var e *KEKError
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// Acceptance 1: no provider, an unknown one, another provider's key, or a removed setting fails with one code.
func TestLoadKEKConfigRefusals(t *testing.T) {
	cases := map[string]struct {
		set  map[string]string
		code string
	}{
		"unset":          {map[string]string{EnvKEKProvider: ""}, KEKProviderUnset},
		"unknown":        {map[string]string{EnvKEKProvider: "rot13"}, KEKProviderUnknown},
		"not built":      {map[string]string{EnvKEKProvider: ProviderKMS}, KEKProviderUnsupported},
		"foreign kms":    {map[string]string{"ACTIVEDIQ_KEK_KMS_KEY": "k"}, KEKSettingForeign},
		"foreign vault":  {map[string]string{"ACTIVEDIQ_KEK_VAULT_PATH": "p"}, KEKSettingForeign},
		"legacy file":    {map[string]string{"ACTIVEDIQ_KEK_FILE": "/x"}, KEKSettingRemoved},
		"legacy id":      {map[string]string{"ACTIVEDIQ_KEK_ID": "x"}, KEKSettingRemoved},
		"no dir":         {map[string]string{EnvKEKDir: ""}, KEKSettingMissing},
		"no passphrase":  {map[string]string{EnvKEKPassphraseFile: ""}, KEKSettingMissing},
		"passphrase env": {map[string]string{EnvKEKPassphrase: "hunter2hunter2"}, KEKPassphraseRefused},
	}
	for name, c := range cases {
		m, get := kekEnv(t)
		for k, v := range c.set {
			m[k] = v
		}
		_, err := LoadKEKConfig(get)
		if kekCode(err) != c.code {
			t.Errorf("%s: err = %v, want code %s", name, err, c.code)
		}
		if err != nil && strings.Contains(err.Error(), "hunter2") {
			t.Errorf("%s: error leaks the value", name)
		}
	}
}

// Acceptance 4: passphrase file inside the keystore dir, and an unsafe keystore dir, are refused.
func TestLoadKEKConfigPlacement(t *testing.T) {
	m, get := kekEnv(t)
	m[EnvKEKPassphraseFile] = filepath.Join(m[EnvKEKDir], "pass")
	if _, err := LoadKEKConfig(get); kekCode(err) != KEKPlacementUnsafe {
		t.Errorf("passphrase file inside dir: %v", err)
	}
	link := filepath.Join(t.TempDir(), "link")
	m2, get2 := kekEnv(t)
	if err := os.Symlink(m2[EnvKEKDir], link); err != nil {
		t.Fatal(err)
	}
	m2[EnvKEKPassphraseFile] = filepath.Join(link, "pass")
	if _, err := LoadKEKConfig(get2); kekCode(err) != KEKPlacementUnsafe {
		t.Errorf("passphrase file inside dir via symlink: %v", err)
	}
	for _, mode := range []os.FileMode{0o770, 0o702, 0o777} {
		m3, get3 := kekEnv(t)
		if err := os.Chmod(m3[EnvKEKDir], mode); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadKEKConfig(get3); kekCode(err) != KEKDirUnsafe {
			t.Errorf("dir mode %o: %v", mode, err)
		}
	}
	m4, get4 := kekEnv(t)
	notDir := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(notDir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	m4[EnvKEKDir] = notDir // a file, not a directory
	if _, err := LoadKEKConfig(get4); kekCode(err) != KEKDirUnsafe {
		t.Errorf("dir is a file: %v", err)
	}
	// KEK dir and API TLS dir must not share a tree.
	kc := testKEK(t)
	for _, tls := range []string{kc.Dir, filepath.Join(kc.Dir, "tls"), filepath.Dir(kc.Dir)} {
		if err := kc.checkPlacement(tls); kekCode(err) != KEKPlacementUnsafe {
			t.Errorf("tls dir %s: %v", tls, err)
		}
	}
	if err := kc.checkPlacement(filepath.Join(t.TempDir(), "tls")); err != nil {
		t.Errorf("separate dirs: %v", err)
	}
}

// Acceptance 2 and 5: kek init writes a 0600 keystore, never prints the passphrase, and refuses a second run.
func TestKEKInit(t *testing.T) {
	m, get := kekEnv(t)
	var out bytes.Buffer
	if err := kekInit(nil, get, &out, keys.FloorKDF); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(m[EnvKEKDir], "kek.keystore.json")
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("keystore: %v %v", fi, err)
	}
	raw, _ := os.ReadFile(path)
	for what, b := range map[string][]byte{"stdout": out.Bytes(), "file": raw} {
		if bytes.Contains(b, []byte(testPassphrase)) {
			t.Errorf("passphrase in %s", what)
		}
	}
	if !strings.Contains(out.String(), path) {
		t.Errorf("stdout = %q", out.String())
	}
	if ents, _ := os.ReadDir(m[EnvKEKDir]); len(ents) != 1 {
		t.Errorf("stray files after init: %v", ents)
	}
	if err := kekInit(nil, get, &out, keys.FloorKDF); kekCode(err) != KEKKeystoreExists {
		t.Fatalf("second init = %v, want KEKKeystoreExists", err)
	}
	if again, _ := os.ReadFile(path); !bytes.Equal(raw, again) {
		t.Fatal("second init changed the keystore")
	}
}

func TestKEKInitRefusals(t *testing.T) {
	_, get := kekEnv(t)
	for _, args := range [][]string{{"--passphrase=hunter2hunter2"}, {"-passphrase", "hunter2hunter2"}, {"hunter2hunter2"}} {
		err := kekInit(args, get, &bytes.Buffer{}, keys.FloorKDF)
		if kekCode(err) != KEKPassphraseRefused || strings.Contains(err.Error(), "hunter2") {
			t.Errorf("args %v: %v", args, err)
		}
	}
	m, get2 := kekEnv(t)
	if err := os.WriteFile(m[EnvKEKPassphraseFile], []byte("short\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := kekInit(nil, get2, &bytes.Buffer{}, keys.FloorKDF); kekCode(err) != KEKPassphraseRefused {
		t.Errorf("short passphrase: %v", err)
	}
	if err := os.Chmod(m[EnvKEKPassphraseFile], 0o644); err != nil {
		t.Fatal(err)
	}
	if err := kekInit(nil, get2, &bytes.Buffer{}, keys.FloorKDF); kekCode(err) != KEKFileUnsafe {
		t.Errorf("world-readable passphrase file: %v", err)
	}
	if _, err := os.Stat(filepath.Join(m[EnvKEKDir], "kek.keystore.json")); err == nil {
		t.Error("keystore written despite refusal")
	}
	// A missing directory is created 0700.
	m3, get3 := kekEnv(t)
	m3[EnvKEKDir] = filepath.Join(t.TempDir(), "new", "kek")
	initKEK(t, get3)
	if fi, err := os.Stat(m3[EnvKEKDir]); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("created dir: %v %v", fi, err)
	}
}

// Acceptance 3: the right passphrase unlocks the keystore's key; a wrong one or a corrupt file is the same code.
func TestPlatformKeyProviderUnlock(t *testing.T) {
	m, get := kekEnv(t)
	kc := initKEK(t, get)
	p, err := platformKeyProvider(kc)
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		KeyID string `json:"key_id"`
	}
	raw, _ := os.ReadFile(kc.KeystorePath())
	if err := jsonUnmarshal(raw, &f); err != nil || p.Ref().KeyID != f.KeyID {
		t.Fatalf("ref %v, key_id %q (%v)", p.Ref(), f.KeyID, err)
	}

	if err := os.WriteFile(m[EnvKEKPassphraseFile], []byte("a different passphrase\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, wrong := platformKeyProvider(kc)
	if err := os.WriteFile(m[EnvKEKPassphraseFile], []byte(testPassphrase+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kc.KeystorePath(), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, corrupt := platformKeyProvider(kc)
	if keys.Code(wrong) != keys.UnwrapFailed || wrong.Error() != corrupt.Error() {
		t.Fatalf("wrong = %v, corrupt = %v: want the same UnwrapFailed", wrong, corrupt)
	}
}

func TestPlatformKeyProviderRefusals(t *testing.T) {
	_, get := kekEnv(t)
	kc, err := LoadKEKConfig(get)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := platformKeyProvider(kc); kekCode(err) != KEKKeystoreMissing {
		t.Errorf("no keystore: %v", err)
	}
	initKEK(t, get)
	if err := os.Chmod(kc.KeystorePath(), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := platformKeyProvider(kc); kekCode(err) != KEKFileUnsafe {
		t.Errorf("loose keystore: %v", err)
	}
	if _, err := platformKeyProvider(KEKConfig{Provider: "kms"}); kekCode(err) != KEKProviderUnknown {
		t.Errorf("hand-built provider: %v", err)
	}
}

// The API key at rest is sealed under the keystore's KEK; a restart reuses the identity and another KEK
// cannot open it.
func TestAPIIdentitySealedByKeystore(t *testing.T) {
	kc := testKEK(t)
	dir := filepath.Join(t.TempDir(), "tls")
	cfg := config.Config{APIAddr: "127.0.0.1:0", APITLSDir: dir}
	id, err := apiIdentity(cfg, kc, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, apitls.KeyFile)); !os.IsNotExist(err) {
		t.Fatalf("plaintext key file must not exist: %v", err)
	}
	if again, err := apiIdentity(cfg, kc, time.Now()); err != nil || again.Fingerprint != id.Fingerprint {
		t.Fatalf("restart must unseal the same identity: %v", err)
	}
	before, _ := os.ReadFile(filepath.Join(dir, apitls.SealedKeyFile))
	if _, err := apiIdentity(cfg, testKEK(t), time.Now()); err == nil {
		t.Fatal("a different KEK must fail startup")
	}
	if after, _ := os.ReadFile(filepath.Join(dir, apitls.SealedKeyFile)); !bytes.Equal(before, after) {
		t.Fatal("sealed key was modified")
	}
	// The KEK directory may not sit in the TLS directory.
	if _, err := apiIdentity(config.Config{APIAddr: "127.0.0.1:0", APITLSDir: filepath.Dir(kc.Dir)}, kc, time.Now()); err == nil {
		t.Fatal("KEK dir inside the TLS dir must fail")
	}
}

// Run reads the settings itself and stops before serving when they are missing.
func TestRunFailsWithoutKEKProvider(t *testing.T) {
	old := kekGetenv
	kekGetenv = func(string) string { return "" }
	defer func() { kekGetenv = old }()
	err := Run(t.Context(), config.Config{DatabaseDSN: "postgres://unused", APIAddr: "127.0.0.1:0"})
	if kekCode(err) != KEKProviderUnset {
		t.Fatalf("Run = %v, want KEKProviderUnset", err)
	}
}

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

// useKEKEnv points Run's KEK settings at a freshly initialised keystore for the test.
func useKEKEnv(t *testing.T) {
	t.Helper()
	_, get := kekEnv(t)
	initKEK(t, get)
	old := kekGetenv
	kekGetenv = get
	t.Cleanup(func() { kekGetenv = old })
}

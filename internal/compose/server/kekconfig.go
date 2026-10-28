package server

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// The KEK settings (keys-custody-design §2, K1). They are read here and only here: domain and platform
// packages receive a keys.Provider, never the environment or a path. Everything is validated before
// anything is served; the failure is one typed code naming the setting, never a value.
const (
	EnvKEKProvider       = "ACTIVEDIQ_KEK_PROVIDER"
	EnvKEKDir            = "ACTIVEDIQ_KEK_DIR"
	EnvKEKPassphraseFile = "ACTIVEDIQ_KEK_PASSPHRASE_FILE"
	// EnvKEKPassphrase is refused if present: a passphrase value never travels in the environment (TM-TB5-T4).
	EnvKEKPassphrase = "ACTIVEDIQ_KEK_PASSPHRASE"
)

// KEK provider names. Only ProviderPassphrase is built (T-0655); the rest are named so that choosing one
// fails with its own code until its adapter ticket (T-0527) lands.
const (
	ProviderPassphrase = "passphrase"
	ProviderDPAPING    = "dpapi-ng"
	ProviderTPM2       = "tpm2"
	ProviderKMS        = "kms"
	ProviderVault      = "vault"
)

// KEKConfig error codes. They are stable.
const (
	KEKProviderUnset       = "KEKProviderUnset"       // ACTIVEDIQ_KEK_PROVIDER is empty: there is no default custody model
	KEKProviderUnknown     = "KEKProviderUnknown"     // not one of the five providers
	KEKProviderUnsupported = "KEKProviderUnsupported" // a known provider whose adapter this build does not have
	KEKSettingForeign      = "KEKSettingForeign"      // a setting that belongs to another provider
	KEKSettingMissing      = "KEKSettingMissing"      // a required setting is empty
	KEKSettingRemoved      = "KEKSettingRemoved"      // the legacy plaintext KEK file settings
	KEKPassphraseRefused   = "KEKPassphraseRefused"   // a passphrase value in the environment or on a command line
	KEKPlacementUnsafe     = "KEKPlacementUnsafe"     // the passphrase file or a directory is somewhere it must not be
	KEKDirUnsafe           = "KEKDirUnsafe"           // the keystore directory is not owner-only
	KEKKeystoreExists      = "KEKKeystoreExists"      // kek init refuses to overwrite
	KEKKeystoreMissing     = "KEKKeystoreMissing"     // the server found no keystore (run kek init)
	KEKFileUnsafe          = "KEKFileUnsafe"          // a keystore or passphrase file cannot be read safely
)

// KEKError is a failure with a stable code and the name of the offending setting. It never carries a value.
type KEKError struct {
	Code    string
	Setting string
}

func (e *KEKError) Error() string {
	if e.Setting == "" {
		return "kek: " + e.Code
	}
	return "kek: " + e.Code + " (" + e.Setting + ")"
}

func kekErr(code, setting string) error { return &KEKError{Code: code, Setting: setting} }

// KEKConfig is the typed, validated KEK selection.
type KEKConfig struct {
	Provider       string
	Dir            string
	PassphraseFile string
}

// foreignKEKSettings are the other providers' keys (design §2): set under the passphrase provider they are a
// configuration mistake, not something to ignore.
var foreignKEKSettings = []string{"ACTIVEDIQ_KEK_KMS_KEY", "ACTIVEDIQ_KEK_VAULT_ADDR", "ACTIVEDIQ_KEK_VAULT_PATH", "ACTIVEDIQ_KEK_VAULT_AUTH"}

// removedKEKSettings is the interim plaintext-file profile this replaces; silently ignoring them would
// start a server on a different custody model than the operator thinks.
var removedKEKSettings = []string{"ACTIVEDIQ_KEK_FILE", "ACTIVEDIQ_KEK_ID"}

// LoadKEKConfig reads and validates the KEK settings through getenv (os.Getenv in the binary, a map in tests).
// An unset or unknown provider, another provider's key, a passphrase value, a passphrase file inside the keystore
// directory and a keystore directory that is not owner-only are all refused.
func LoadKEKConfig(getenv func(string) string) (KEKConfig, error) {
	for _, k := range removedKEKSettings {
		if getenv(k) != "" {
			return KEKConfig{}, kekErr(KEKSettingRemoved, k)
		}
	}
	if getenv(EnvKEKPassphrase) != "" {
		return KEKConfig{}, kekErr(KEKPassphraseRefused, EnvKEKPassphrase)
	}
	c := KEKConfig{Provider: getenv(EnvKEKProvider), Dir: getenv(EnvKEKDir), PassphraseFile: getenv(EnvKEKPassphraseFile)}
	switch c.Provider {
	case "":
		return KEKConfig{}, kekErr(KEKProviderUnset, EnvKEKProvider)
	case ProviderPassphrase:
	case ProviderDPAPING, ProviderTPM2, ProviderKMS, ProviderVault:
		return KEKConfig{}, kekErr(KEKProviderUnsupported, EnvKEKProvider)
	default:
		return KEKConfig{}, kekErr(KEKProviderUnknown, EnvKEKProvider)
	}
	for _, k := range foreignKEKSettings {
		if getenv(k) != "" {
			return KEKConfig{}, kekErr(KEKSettingForeign, k)
		}
	}
	if c.Dir == "" {
		return KEKConfig{}, kekErr(KEKSettingMissing, EnvKEKDir)
	}
	if c.PassphraseFile == "" {
		return KEKConfig{}, kekErr(KEKSettingMissing, EnvKEKPassphraseFile)
	}
	if inside(c.PassphraseFile, c.Dir) {
		return KEKConfig{}, kekErr(KEKPlacementUnsafe, EnvKEKPassphraseFile)
	}
	if err := checkKEKDir(c.Dir); err != nil {
		return KEKConfig{}, err
	}
	return c, nil
}

// KeystorePath is where the passphrase keystore lives.
func (c KEKConfig) KeystorePath() string { return filepath.Join(c.Dir, "kek.keystore.json") }

// checkPlacement refuses a KEK directory that shares a tree with the API TLS directory: the sealed key and the
// keystore that opens it would then be copied or backed up together (TM-TB5-T4).
func (c KEKConfig) checkPlacement(apiTLSDir string) error {
	if apiTLSDir == "" {
		return nil
	}
	if inside(c.Dir, apiTLSDir) || inside(apiTLSDir, c.Dir) {
		return kekErr(KEKPlacementUnsafe, EnvKEKDir)
	}
	return nil
}

// inside reports whether path is dir or below it, after making both absolute and resolving symlinks in their
// existing part (a missing tail is appended unchanged).
func inside(path, dir string) bool {
	p, err1 := resolveLoose(path)
	d, err2 := resolveLoose(dir)
	if err1 != nil || err2 != nil {
		return true // cannot prove it is outside: refuse
	}
	rel, err := filepath.Rel(d, p)
	return err != nil || rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

func resolveLoose(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	rest, cur := "", abs
	for {
		if r, err := filepath.EvalSymlinks(cur); err == nil {
			return filepath.Join(r, rest), nil
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return abs, nil
		}
		rest = filepath.Join(filepath.Base(cur), rest)
		cur = parent
	}
}

var errNotExist = errors.New("does not exist")

// kekGetenv is how Run reads the KEK settings; tests replace it.
var kekGetenv = os.Getenv

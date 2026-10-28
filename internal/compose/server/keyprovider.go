package server

import (
	"errors"
	"io"
	"runtime"

	"github.com/skenzeriq/activediq/internal/platform/keys"
	"github.com/skenzeriq/activediq/internal/platform/secret"
)

// platformKeyProvider unlocks the configured KEK provider (keys-custody-design §2). There is no nil provider
// and no generation here: a missing keystore, a wrong passphrase and a corrupt file all stop startup, and a
// wrong passphrase and a corrupt file are the same keys.UnwrapFailed (no oracle). Errors never include a file's
// contents or the passphrase.
func platformKeyProvider(kc KEKConfig) (keys.Provider, error) {
	if kc.Provider != ProviderPassphrase { // LoadKEKConfig already refused the rest; a hand-built value is refused too
		return nil, kekErr(KEKProviderUnknown, EnvKEKProvider)
	}
	if err := kekFileSupported(runtime.GOOS); err != nil {
		return nil, err
	}
	pass, err := readPassphrase(kc.PassphraseFile)
	if err != nil {
		return nil, err
	}
	defer pass.Destroy()
	raw, err := readSmallFile(kc.KeystorePath(), keys.MaxKeystoreBytes)
	if err != nil {
		return nil, err
	}
	p, err := keys.OpenKeystore(raw, pass)
	if err != nil {
		return nil, err
	}
	return p, nil
}

const maxPassphraseBytes = 1024

// readPassphrase reads the passphrase file (owner-only, not a link) and strips trailing line endings.
func readPassphrase(path string) (secret.Secret, error) {
	f, err := openSecretFile("passphrase file", path)
	if err != nil {
		return secret.Secret{}, kekErr(KEKFileUnsafe, EnvKEKPassphraseFile)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxPassphraseBytes+1))
	if err != nil || len(raw) > maxPassphraseBytes {
		clear(raw)
		return secret.Secret{}, kekErr(KEKFileUnsafe, EnvKEKPassphraseFile)
	}
	for len(raw) > 0 && (raw[len(raw)-1] == '\n' || raw[len(raw)-1] == '\r') {
		raw = raw[:len(raw)-1]
	}
	if len(raw) == 0 {
		return secret.Secret{}, kekErr(KEKFileUnsafe, EnvKEKPassphraseFile)
	}
	return secret.FromBytes(raw), nil
}

// readSmallFile reads an owner-only regular file of at most limit bytes. A missing file is KEKKeystoreMissing.
func readSmallFile(path string, limit int64) ([]byte, error) {
	f, err := openSecretFile("keystore", path)
	if err != nil {
		if errors.Is(err, errNotExist) {
			return nil, kekErr(KEKKeystoreMissing, EnvKEKDir)
		}
		return nil, kekErr(KEKFileUnsafe, EnvKEKDir)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, kekErr(KEKFileUnsafe, EnvKEKDir)
	}
	return raw, nil
}

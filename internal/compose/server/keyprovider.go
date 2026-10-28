package server

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/skenzeriq/activediq/internal/compose/config"
	"github.com/skenzeriq/activediq/internal/platform/keys"
	"github.com/skenzeriq/activediq/internal/platform/secret"
)

// platformKeyProvider builds the platform key provider for the KEK profile. It returns (nil, nil) only
// when no KEK file is configured (the legacy plaintext profile); a configured profile that cannot be
// loaded is an error, never a nil provider. Errors never include the file's contents.
func platformKeyProvider(cfg config.Config) (keys.Provider, error) {
	if cfg.KEKFile == "" {
		return nil, nil
	}
	kek, err := readKEKFile(cfg.KEKFile)
	if err != nil {
		return nil, err
	}
	defer kek.Destroy()
	p, err := keys.NewLocalProvider(cfg.KEKID, kek)
	if err != nil {
		return nil, errors.New("KEK is not usable (need a 256-bit key and a non-empty key id)")
	}
	return p, nil
}

func readKEKFile(path string) (secret.Secret, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return secret.Secret{}, fmt.Errorf("KEK file %s: %w", path, errors.Unwrap(err))
	}
	if !fi.Mode().IsRegular() {
		return secret.Secret{}, fmt.Errorf("KEK file %s must be a regular file, not a link or device", path)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		return secret.Secret{}, fmt.Errorf("KEK file %s must not be accessible to group or others (chmod 600)", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return secret.Secret{}, fmt.Errorf("KEK file %s: %w", path, errors.Unwrap(err))
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 256))
	if err != nil {
		return secret.Secret{}, fmt.Errorf("KEK file %s: read failed", path)
	}
	defer clear(raw)
	for len(raw) > 0 && (raw[len(raw)-1] == '\n' || raw[len(raw)-1] == '\r' || raw[len(raw)-1] == ' ') {
		raw = raw[:len(raw)-1]
	}
	key := make([]byte, hex.DecodedLen(len(raw)))
	defer clear(key)
	if _, err := hex.Decode(key, raw); err != nil || len(key) != keys.DEKSize {
		return secret.Secret{}, fmt.Errorf("KEK file %s must hold exactly %d hex characters", path, 2*keys.DEKSize)
	}
	return secret.FromBytes(key), nil
}

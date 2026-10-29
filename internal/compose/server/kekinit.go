package server

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/skenzeriq/activediq/internal/platform/keys"
)

// minPassphraseBytes is enforced when a keystore is created, never when one is unlocked.
const minPassphraseBytes = 12

// KEKInit is `activediq-server kek init` (keys-custody-design §2, K2): the only place key material is
// generated. It reads the same ACTIVEDIQ_KEK_* settings as the server, takes the passphrase only from
// ACTIVEDIQ_KEK_PASSPHRASE_FILE, writes kek.keystore.json 0600 into ACTIVEDIQ_KEK_DIR, and refuses to overwrite
// an existing keystore. It takes no arguments, so there is no flag a passphrase could be given on. Output
// names the file and the key id, never the passphrase or the KEK.
func KEKInit(args []string, getenv func(string) string, stdout io.Writer) error {
	return kekInit(args, getenv, stdout, keys.DefaultKDF)
}

func kekInit(args []string, getenv func(string) string, stdout io.Writer, kdf keys.KDFParams) error {
	fs := flag.NewFlagSet("kek init", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		// The flag package reports the flag's name only, but a bare argument could be a typed passphrase:
		// never echo what was given.
		return kekErr(KEKPassphraseRefused, "arguments")
	}
	kc, err := LoadKEKConfig(getenv)
	if err != nil {
		return err
	}
	if err := kekFileSupported(runtime.GOOS); err != nil {
		return err
	}
	pass, err := readPassphrase(kc.PassphraseFile)
	if err != nil {
		return err
	}
	defer pass.Destroy()
	short := true
	pass.Expose(func(b []byte) { short = len(b) < minPassphraseBytes })
	if short {
		return kekErr(KEKPassphraseRefused, EnvKEKPassphraseFile)
	}
	if err := os.MkdirAll(kc.Dir, 0o700); err != nil {
		return kekErr(KEKDirUnsafe, EnvKEKDir)
	}
	if err := checkKEKDir(kc.Dir); err != nil {
		return err
	}
	path := kc.KeystorePath()
	if _, err := os.Lstat(path); err == nil {
		return kekErr(KEKKeystoreExists, EnvKEKDir)
	}
	file, keyID, err := keys.CreateKeystore(pass, kdf)
	if err != nil {
		return err
	}
	if err := publishNew(path, file); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "kek init: wrote %s (key_id %s)\n", path, keyID)
	return nil
}

// publishNew writes data to a private temporary file in the same directory and links it to path, which fails if
// path exists: a concurrent or repeated init never overwrites, and a crash never leaves a partial keystore.
func publishNew(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".kek-init-*") // 0600
	if err != nil {
		return kekErr(KEKDirUnsafe, EnvKEKDir)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return kekErr(KEKDirUnsafe, EnvKEKDir)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return kekErr(KEKDirUnsafe, EnvKEKDir)
	}
	if err := tmp.Close(); err != nil {
		return kekErr(KEKDirUnsafe, EnvKEKDir)
	}
	if err := os.Link(tmp.Name(), path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return kekErr(KEKKeystoreExists, EnvKEKDir)
		}
		return kekErr(KEKDirUnsafe, EnvKEKDir)
	}
	return nil
}

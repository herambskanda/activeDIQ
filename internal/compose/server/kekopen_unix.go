//go:build !windows

package server

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// kekFileSupported reports whether the file profile may be used on goos. Only the Unix profile has an
// access check; Windows uses DPAPI-NG/TPM and refuses the file profile until a DACL check exists (T-0413).
func kekFileSupported(goos string) error {
	if goos == "windows" {
		return errors.New("the KEK file profile is not available on Windows (no DACL check yet): use the DPAPI-NG/TPM profile")
	}
	return nil
}

// checkKEKDir refuses a keystore directory that exists but is not a directory owned by the server user, or is
// writable by group or others: anyone who can write there can replace the keystore. A directory that does not
// exist yet is accepted here (kek init creates it 0700; the server then finds no keystore).
func checkKEKDir(dir string) error {
	fi, err := os.Stat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !fi.IsDir() {
		return kekErr(KEKDirUnsafe, EnvKEKDir)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != os.Geteuid() || fi.Mode().Perm()&0o022 != 0 {
		return kekErr(KEKDirUnsafe, EnvKEKDir)
	}
	return nil
}

// openSecretFile opens path once, refusing a symlink at the final component, and checks the opened handle
// (regular file, owned by the effective uid, 0600) so nothing can be swapped between check and use. what names
// the file in errors.
func openSecretFile(what, path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("%s %s must be a regular file, not a link", what, path)
		}
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%s %s: %w", what, path, errNotExist)
		}
		return nil, fmt.Errorf("%s %s: %w", what, path, errors.Unwrap(err))
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("%s %s: stat failed", what, path)
	}
	if !fi.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("%s %s must be a regular file, not a link or device", what, path)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != os.Geteuid() {
		f.Close()
		return nil, fmt.Errorf("%s %s must be owned by the user running the server", what, path)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		f.Close()
		return nil, fmt.Errorf("%s %s must not be accessible to group or others (chmod 600)", what, path)
	}
	return f, nil
}

//go:build unix

package ownerfile

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func openAppend(path string) (*os.File, error) {
	if _, err := os.Lstat(path); err == nil {
		if err := check(path); err != nil {
			return nil, err
		}
	}
	// O_NOFOLLOW: a symlink planted at the path is refused, never followed.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	if err := checkOpen(f); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

func createTemp(dir, pattern string) (*os.File, error) {
	f, err := os.CreateTemp(dir, pattern) // created 0600 by os.CreateTemp
	if err != nil {
		return nil, err
	}
	if err := f.Chmod(0o600); err != nil {
		name := f.Name()
		_ = f.Close()
		_ = os.Remove(name)
		return nil, err
	}
	return f, nil
}

func check(path string) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	return checkInfo(path, st)
}

func checkOpen(f *os.File) error {
	st, err := f.Stat()
	if err != nil {
		return err
	}
	return checkInfo(f.Name(), st)
}

func checkInfo(path string, st os.FileInfo) error {
	s, ok := st.Sys().(*syscall.Stat_t)
	if !st.Mode().IsRegular() || !ok || int(s.Uid) != os.Geteuid() || st.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: %s", ErrUnsafe, filepath.Base(path))
	}
	return nil
}

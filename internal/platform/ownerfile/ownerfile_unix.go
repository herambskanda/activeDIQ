//go:build !windows

package ownerfile

import (
	"errors"
	"io/fs"
	"os"
)

func ensure(path string) (bool, error) {
	st, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil // OpenFile creates it with 0600 (subject to umask, which only narrows)
	}
	if err != nil {
		return false, err
	}
	return restrictExisting2(path, st)
}

func restrictExisting(path string) (bool, error) {
	st, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	return restrictExisting2(path, st)
}

func restrictExisting2(path string, st fs.FileInfo) (bool, error) {
	if st.Mode().Perm() == 0o600 {
		return false, nil
	}
	return true, os.Chmod(path, 0o600)
}

//go:build !windows

package ownerfile

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
)

// noFollow makes the final open refuse a symlink planted after the check.
const noFollow = syscall.O_NOFOLLOW

// os.CreateTemp creates with 0600 and O_EXCL.
func createTemp(dir, pattern string) (*os.File, error) { return os.CreateTemp(dir, pattern) }

func ensure(path string) (bool, error) {
	st, err := os.Lstat(path) // Lstat: never follow a symlink
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil // OpenFile creates it with 0600 (subject to umask, which only narrows)
	}
	if err != nil {
		return false, err
	}
	if !st.Mode().IsRegular() {
		return false, ErrNotRegular
	}
	if !ownedBy(st, os.Geteuid()) {
		return false, ErrForeignOwner
	}
	if st.Mode().Perm() == 0o600 {
		return false, nil
	}
	return true, os.Chmod(path, 0o600)
}

// ownedBy reports whether st is owned by uid. A missing Stat_t counts as foreign.
func ownedBy(st fs.FileInfo, uid int) bool {
	s, ok := st.Sys().(*syscall.Stat_t)
	return ok && int(s.Uid) == uid
}

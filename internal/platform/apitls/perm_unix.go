//go:build unix

package apitls

import (
	"fmt"
	"os"
	"syscall"
)

// checkDir refuses an identity directory another local user could write into or that someone else
// owns: they could plant a certificate and key of their own (TM-TB1-T2, TM-TB16-T3).
func checkDir(dir string) error {
	st, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("apitls: identity directory %s: %w", dir, err)
	}
	if !st.IsDir() {
		return fmt.Errorf("apitls: identity directory %s is not a directory", dir)
	}
	if !ownedByMe(st) {
		return fmt.Errorf("apitls: identity directory %s is not owned by the server's user", dir)
	}
	if st.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("apitls: identity directory %s is writable by group or others (mode %04o); use 0700", dir, st.Mode().Perm())
	}
	return nil
}

// checkFile refuses a symlink, a non-regular file, a file owned by someone else, or (secret) a file
// with any group/other permission bit, otherwise any write bit for group/other.
func checkFile(path string, secret bool) error {
	st, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("apitls: %s: %w", path, err)
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("apitls: %s is not a regular file (symlinks are refused)", path)
	}
	if !ownedByMe(st) {
		return fmt.Errorf("apitls: %s is not owned by the server's user", path)
	}
	mask := os.FileMode(0o022)
	if secret {
		mask = 0o077
	}
	if st.Mode().Perm()&mask != 0 {
		return fmt.Errorf("apitls: %s has unsafe permissions (mode %04o)", path, st.Mode().Perm())
	}
	return nil
}

func ownedByMe(st os.FileInfo) bool {
	s, ok := st.Sys().(*syscall.Stat_t)
	return ok && int(s.Uid) == os.Geteuid()
}

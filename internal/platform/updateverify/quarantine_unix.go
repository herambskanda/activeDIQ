//go:build unix

package updateverify

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// checkPrivateDir refuses a directory another local user could use to swap a verified artefact.
func checkPrivateDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return errors.New("not a real directory (symlink)")
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Geteuid() {
		return errors.New("not owned by the process user")
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("writable by group or other (mode %o)", fi.Mode().Perm())
	}
	return nil
}

// checkPrivateFile refuses a file another local user could rewrite in place: it must be owned by
// the process user with no group or other write bit.
func checkPrivateFile(fi os.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Geteuid() {
		return errors.New("not owned by the process user")
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("writable by group or other (mode %o)", fi.Mode().Perm())
	}
	return nil
}

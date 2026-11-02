//go:build unix

package dial

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// errAccount: writing state for another account is a Windows mechanism (ACLs name a SID); a POSIX
// directory has one owner, which is the caller.
var errAccount = errors.New("dial: enrolling for another account is supported on Windows only")

func ensureDir(dir, svc string) error {
	if svc != "" {
		return errAccount
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return checkDir(dir, svc)
}

// checkDir refuses a directory another local user could write into or that someone else owns: they
// could replace the pinned CA (TM-TB12-T2).
func checkDir(dir, _ string) error {
	st, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	if !ownedByMe(st) || st.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s must be owned by the component's user with mode 0700", dir)
	}
	return nil
}

// checkFile refuses symlinks, non-regular files, files of other users, and any group or other
// permission bit on a secret (any write bit otherwise).
func checkFile(path string, secret bool, _ string) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	mask := os.FileMode(0o022)
	if secret {
		mask = 0o077
	}
	if !st.Mode().IsRegular() || !ownedByMe(st) || st.Mode().Perm()&mask != 0 {
		return fmt.Errorf("%s is not a regular file of the component's user with safe permissions", filepath.Base(path))
	}
	return nil
}

func ownedByMe(st os.FileInfo) bool {
	s, ok := st.Sys().(*syscall.Stat_t)
	return ok && int(s.Uid) == os.Geteuid()
}

// writeFile writes data to a new 0600 temp file in the same directory and renames it into place.
func writeFile(path string, data []byte, _ string) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name) // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

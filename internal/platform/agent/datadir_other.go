//go:build !windows

package agent

import (
	"fmt"
	"os"
	"syscall"
)

// CheckDataDir refuses a data directory that another user could write into or that someone else owns.
// On Windows the equivalent is a DACL check (datadir_windows.go).
func CheckDataDir(dir string) error {
	st, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is not a plain directory", dir)
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); !ok || int(sys.Uid) != os.Getuid() {
		return fmt.Errorf("%s is not owned by the service identity", dir)
	}
	if st.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s must not be accessible to group or others", dir)
	}
	return nil
}

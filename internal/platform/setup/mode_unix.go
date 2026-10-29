//go:build unix

package setup

import (
	"fmt"
	"io/fs"
)

// checkDirMode refuses a setup directory any other local user could read or enter: the secret file's own
// 0600 is not enough if the directory lets someone replace it.
func checkDirMode(fi fs.FileInfo) error {
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("setup: directory has unsafe permissions (mode %04o); use 0700", fi.Mode().Perm())
	}
	return nil
}

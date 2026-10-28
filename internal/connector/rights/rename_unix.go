//go:build unix

package rights

import (
	"os"
	"path/filepath"
)

// renameDurable replaces dst with src and flushes the directory entry.
func renameDurable(src, dst string) error {
	if err := os.Rename(src, dst); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(dst))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

//go:build !windows

package ownerfile

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

func readFile(path string) ([]byte, error) {
	// O_NOFOLLOW: a symlink at the path is refused (ELOOP), never followed. O_NONBLOCK: open(2) on a
	// planted FIFO must not block before the regular-file check below.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, refuse(path, ErrNotRegular)
		}
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat() // fstat on the open descriptor, not the path
	if err != nil {
		return nil, err
	}
	switch {
	case !st.Mode().IsRegular():
		return nil, refuse(path, ErrNotRegular)
	case !ownedBy(st, os.Geteuid()):
		return nil, refuse(path, ErrForeignOwner)
	case st.Mode().Perm()&0o077 != 0:
		return nil, refuse(path, nil)
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxReadSize+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxReadSize {
		return nil, refuse(path, nil)
	}
	return b, nil
}

// refuse wraps ErrUnsafe (and why, if given) with the base name only: never the full path.
func refuse(path string, why error) error {
	if why == nil {
		return fmt.Errorf("%w: %s", ErrUnsafe, filepath.Base(path))
	}
	return fmt.Errorf("%w: %w: %s", ErrUnsafe, why, filepath.Base(path))
}

func ensureDir(path string) error {
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	return checkDir(path)
}

func checkDir(path string) error {
	// O_DIRECTORY|O_NOFOLLOW: a symlinked state directory is refused; fstat is on the open handle.
	d, err := os.OpenFile(path, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.ENOTDIR) {
			return fmt.Errorf("%w: %s", ErrDirUnsafe, filepath.Base(path))
		}
		return err
	}
	defer d.Close()
	st, err := d.Stat()
	if err != nil {
		return err
	}
	if !st.IsDir() || !ownedBy(st, os.Geteuid()) || st.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: %s", ErrDirUnsafe, filepath.Base(path))
	}
	return nil
}

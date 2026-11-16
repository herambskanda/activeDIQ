//go:build unix

package ownerfile

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

type dirImpl struct {
	f    *os.File // the state directory, opened O_DIRECTORY|O_NOFOLLOW
	name string   // base name, for messages only
}

// openDir resolves the parent by path without following a link at its last element, verifies it on
// the open descriptor, and then opens (or creates) the state directory relative to that descriptor.
// Ancestors above the parent may be links: the checks are on the inodes actually reached, and an
// attacker cannot make an inode owned by us (state directory) or by root/us and unwritable by others
// (parent) out of a place they control.
func openDir(path string, create bool, o dirOptions) (*dirImpl, error) {
	if o.account != "" {
		return nil, ErrAccountUnsupported
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	base := filepath.Base(abs)
	if base == "." || base == ".." || base == string(filepath.Separator) {
		return nil, fmt.Errorf("%w: %s", ErrDirUnsafe, base)
	}
	parent, err := os.OpenFile(filepath.Dir(abs), os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.ENOTDIR) {
			return nil, fmt.Errorf("%w: %s", ErrParentUnsafe, filepath.Base(filepath.Dir(abs)))
		}
		return nil, err
	}
	defer parent.Close()
	if err := verifyParent(parent); err != nil {
		return nil, err
	}
	pfd := int(parent.Fd())
	if create {
		if err := unix.Mkdirat(pfd, base, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
			return nil, err
		}
	}
	fd, err := unix.Openat(pfd, base, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.ENOTDIR) {
			return nil, fmt.Errorf("%w: %s", ErrDirUnsafe, base)
		}
		return nil, err
	}
	f := os.NewFile(uintptr(fd), base)
	st, err := f.Stat() // fstat on the open descriptor
	if err != nil {
		f.Close()
		return nil, err
	}
	if !st.IsDir() || !ownedBy(st, os.Geteuid()) || st.Mode().Perm()&0o077 != 0 {
		f.Close()
		return nil, fmt.Errorf("%w: %s", ErrDirUnsafe, base)
	}
	return &dirImpl{f: f, name: base}, nil
}

// verifyParent: a directory owned by root or the service user that neither group nor others can
// write. Group and other write bits are refused even with the sticky bit: the point is that nobody
// but the owner can rename entries or create siblings.
func verifyParent(p *os.File) error {
	st, err := p.Stat()
	if err != nil {
		return err
	}
	s, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.IsDir() || (s.Uid != 0 && int(s.Uid) != os.Geteuid()) || st.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%w: %s", ErrParentUnsafe, filepath.Base(p.Name()))
	}
	return nil
}

func (d *dirImpl) readFile(name string) ([]byte, error) {
	// O_NOFOLLOW: a symlink is refused (ELOOP), never followed. O_NONBLOCK: a planted FIFO must not
	// block open(2) before the regular-file check.
	fd, err := unix.Openat(int(d.f.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, refuse(name, ErrNotRegular)
		}
		return nil, &fs.PathError{Op: "open", Path: name, Err: err}
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	return readOpened(f, name)
}

func (d *dirImpl) writeFile(name string, data []byte) (err error) {
	dfd := int(d.f.Fd())
	var tmp string
	var f *os.File
	for try := 0; ; try++ {
		var r [8]byte
		if _, err := rand.Read(r[:]); err != nil {
			return err
		}
		tmp = ".tmp-" + hex.EncodeToString(r[:])
		// O_EXCL|O_NOFOLLOW|0600: created owner-only in one call; mode bits only narrow under umask.
		fd, oerr := unix.Openat(dfd, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
		if oerr == nil {
			f = os.NewFile(uintptr(fd), tmp)
			break
		}
		if !errors.Is(oerr, fs.ErrExist) || try >= 100 {
			return oerr
		}
	}
	defer func() {
		if err != nil {
			_ = unix.Unlinkat(dfd, tmp, 0)
		}
	}()
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = unix.Renameat(dfd, tmp, dfd, name); err != nil {
		return err
	}
	_ = d.f.Sync() // make the rename durable; not every filesystem supports fsync on a directory
	return nil
}

func (d *dirImpl) close() error { return d.f.Close() }

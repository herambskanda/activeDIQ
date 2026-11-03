package ownerfile

import (
	"errors"
	"fmt"
	"strings"
)

// ErrParentUnsafe is returned (wrapped) by OpenDir and CreateDir when the directory that holds the
// state directory is a link or reparse point, or is owned by, or writable by (create, delete-child,
// rename, change-permissions), a principal other than the service identity, SYSTEM and, on Windows,
// BUILTIN\Administrators. Whoever can rename the state directory away can put a directory of their
// own in its place and supply the trust anchor (TM-TB12-T2, T-1315).
var ErrParentUnsafe = errors.New("ownerfile: parent of the state directory is not trusted")

// Dir is a state directory that has been verified once and is held open (T-1315). OpenDir and
// CreateDir verify the directory's parent and the directory itself on open handles; ReadFile and
// WriteFile then resolve names relative to that handle, so nothing is checked by path and used by
// path. A path swapped for a link or junction after the open cannot redirect a read or a write.
//
// Unix: a directory file descriptor; names are opened with openat(2) and O_NOFOLLOW.
// Windows: a directory handle without FILE_SHARE_DELETE, so the directory (and its parents) cannot be
// renamed or replaced while it is held; names are opened under the directory's final path and their
// own final path is compared to it.
//
// A Dir is not safe for concurrent writes of the same name. Close it when done: holding it pins the
// directory.
type Dir struct{ impl *dirImpl }

// OpenDir verifies and opens an existing state directory: the directory must be a real directory
// (not a link) owned by the service identity with access for the service identity (and SYSTEM on
// Windows) only (ErrDirUnsafe), and its parent must be trusted (ErrParentUnsafe). Nothing is created
// or repaired. A missing directory satisfies errors.Is(err, fs.ErrNotExist).
func OpenDir(path string) (*Dir, error) {
	i, err := openDir(path, false)
	if err != nil {
		return nil, err
	}
	return &Dir{i}, nil
}

// CreateDir is OpenDir that creates the last path element when it is absent. The parent must exist
// and is verified before anything is created: an untrusted parent is refused and nothing is written.
// The directory is created with its owner-only protection in the same call (Unix: mode 0700; Windows:
// a PROTECTED DACL passed to CreateDirectory, never inherited). An existing directory is never
// adopted or repaired: it is accepted only if it already passes OpenDir.
func CreateDir(path string) (*Dir, error) {
	i, err := openDir(path, true)
	if err != nil {
		return nil, err
	}
	return &Dir{i}, nil
}

// ReadFile reads the file name (a base name, no separators) in the directory through one handle:
// opened without following a link, owner and access verified on that handle (as the package-level
// ReadFile), then read from it. Refusals satisfy errors.Is(err, ErrUnsafe).
func (d *Dir) ReadFile(name string) ([]byte, error) {
	if err := checkName(name); err != nil {
		return nil, err
	}
	return d.impl.readFile(name)
}

// WriteFile durably replaces the file name with data: it creates a uniquely named owner-only
// temporary file in the directory (an explicit descriptor on Windows, 0600 on Unix, never an
// inherited ACL, so there is no instant at which the bytes are readable by anyone else), writes and
// syncs it, and renames it over name. On failure the temporary file is removed and name is unchanged.
func (d *Dir) WriteFile(name string, data []byte) error {
	if err := checkName(name); err != nil {
		return err
	}
	return d.impl.writeFile(name, data)
}

// Close releases the handle.
func (d *Dir) Close() error { return d.impl.close() }

func checkName(name string) error {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\:\x00") {
		return fmt.Errorf("ownerfile: %q is not a plain file name", name)
	}
	return nil
}

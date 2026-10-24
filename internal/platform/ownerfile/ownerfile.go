// Package ownerfile creates and repairs files that only the running service identity may read or
// write (connector contract §8.3a: the shrink baseline).
//
// POSIX: mode 0600, owned by the effective uid. Windows: Go ignores permission bits there, so the
// file would inherit the parent directory's ACL; instead the file gets an explicit, protected
// (non-inheriting) DACL granting FILE_ALL_ACCESS to the process token's user SID and to SYSTEM only,
// built with the typed security-descriptor API (never SDDL strings).
//
// An existing file is trusted only if it is a regular file (no symlink, no reparse point) owned by
// the service identity (Windows: also SYSTEM or BUILTIN\Administrators). Its owner can always
// rewrite its permissions, so a file owned by anyone else is never "corrected": it is refused.
package ownerfile

import (
	"errors"
	"os"
)

var (
	// ErrForeignOwner: the file exists and is owned by an identity we do not trust. Its content is
	// untrusted and its permissions cannot be made safe; the caller must treat the baseline as not
	// durable-and-private (LOCAL_RECORD_FAILED).
	ErrForeignOwner = errors.New("ownerfile: file is owned by another identity")
	// ErrNotRegular: the path is a symlink, reparse point, directory or device.
	ErrNotRegular = errors.New("ownerfile: path is not a regular file")
)

// OpenAppend opens path for appending, creating it owner-only if absent. If it already exists with
// wider access and a trusted owner, the access is corrected (Windows: the DACL is replaced; POSIX:
// chmod 0600) before the handle is returned; corrected reports that, and the caller must record it
// (the content may have been written by someone else). A foreign owner or a non-regular file is an
// error (ErrForeignOwner, ErrNotRegular), as is a failure to correct.
func OpenAppend(path string) (f *os.File, corrected bool, err error) {
	corrected, err = ensure(path)
	if err != nil {
		return nil, false, err
	}
	f, err = os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY|noFollow, 0o600)
	if err != nil {
		return nil, false, err
	}
	return f, corrected, nil
}

// CreateTemp creates a new, uniquely named, write-only file in dir that is owner-only from the
// instant it exists (no window with an inherited ACL), for write-then-rename. pattern is as for
// os.CreateTemp.
func CreateTemp(dir, pattern string) (*os.File, error) { return createTemp(dir, pattern) }

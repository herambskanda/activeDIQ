// Package ownerfile creates and verifies local files that only the component's service identity may
// touch: the rights baseline and shrink-record files (contract §8.3a, TM-D23 rule 8, T-0537).
//
// On Unix that is mode 0600 owned by the effective uid. On Windows Go's modes are no-ops and new files
// inherit the parent ACL (ProgramData grants BUILTIN\Users read), so the file is created with an
// explicit PROTECTED DACL granting access to the service identity and SYSTEM only, and owned by the
// service identity. Check re-verifies owner and DACL on every load, so a file that was pre-created by
// someone else or later widened (an extra ACE for Users) is refused with ErrUnsafe.
package ownerfile

import (
	"errors"
	"os"
)

// ErrUnsafe is returned (wrapped) when a file is not a regular file owned by the service identity
// with access for the service identity (and SYSTEM on Windows) only.
var ErrUnsafe = errors.New("ownerfile: file is not restricted to the service identity")

// OpenAppend opens path for appending, creating it with the restricted ACL if it does not exist.
// An existing file is verified with Check first and refused if it is wider.
func OpenAppend(path string) (*os.File, error) { return openAppend(path) }

// CreateTemp creates a new, uniquely named file in dir with the restricted ACL, for write-then-rename.
func CreateTemp(dir, pattern string) (*os.File, error) { return createTemp(dir, pattern) }

// Check refuses path unless it is a plain (non-link) regular file owned by the service identity whose
// access is limited to the service identity (and SYSTEM on Windows). A missing file returns an error
// satisfying errors.Is(err, fs.ErrNotExist), not ErrUnsafe.
func Check(path string) error { return check(path) }

// ErrDirUnsafe is returned (wrapped) when the state directory is not a real directory owned by the
// service identity with access for the service identity (and SYSTEM on Windows) only.
var ErrDirUnsafe = errors.New("ownerfile: state directory is not restricted to the service identity")

// MaxReadSize bounds ReadFile: the files held here are small identifier lists.
const MaxReadSize = 64 << 20

// ReadFile reads path through a single handle: it opens the path without following a link
// (O_NOFOLLOW / FILE_FLAG_OPEN_REPARSE_POINT), verifies owner and access on that open handle
// (fstat / GetSecurityInfo), and reads from the same handle. A path swapped for a link after any
// earlier Check is therefore refused, and the foreign contents are never read. Errors are ErrUnsafe
// or satisfy errors.Is(err, fs.ErrNotExist).
func ReadFile(path string) ([]byte, error) { return readFile(path) }

// EnsureDir creates the state directory (and only the last element; the parent must exist) with the
// service-identity-only protection, or verifies an existing one, and returns an error wrapping
// ErrDirUnsafe if it is wider. The connector calls it at startup and refuses to start on error.
// Unix: mode 0700, owned by the effective uid. Windows: owner = service identity, PROTECTED DACL of
// the service identity and SYSTEM only.
func EnsureDir(path string) error { return ensureDir(path) }

// CheckDir verifies an existing state directory without creating it.
func CheckDir(path string) error { return checkDir(path) }

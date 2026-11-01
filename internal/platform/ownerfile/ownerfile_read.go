package ownerfile

import "errors"

// ErrUnsafe is the parent of every refusal made by ReadFile (and wrapped, with ErrForeignOwner or
// ErrNotRegular where one applies): the file is not a regular file owned by a trusted identity with
// access for the service identity (and SYSTEM on Windows) only. Its content was not read.
var ErrUnsafe = errors.New("ownerfile: file is not restricted to the service identity")

// ErrDirUnsafe is returned (wrapped) when the state directory is not a real directory owned by the
// service identity with access for the service identity (and SYSTEM on Windows) only.
var ErrDirUnsafe = errors.New("ownerfile: state directory is not restricted to the service identity")

// MaxReadSize bounds ReadFile: the files held here are small identifier lists.
const MaxReadSize = 64 << 20

// ReadFile reads path through a single handle (T-0577): it opens the path without following a link
// (O_NOFOLLOW / FILE_FLAG_OPEN_REPARSE_POINT), verifies owner and access on that open handle
// (fstat / GetSecurityInfo), and reads from the same handle. A path swapped for a link after any
// earlier check is therefore refused and the foreign contents are never read.
//
// Unlike OpenAppend it never corrects a wider file: bytes a wider ACL allowed others to write are
// not trusted, so the file is refused. Refusals satisfy errors.Is(err, ErrUnsafe) and, where they
// apply, ErrForeignOwner or ErrNotRegular. A missing file satisfies errors.Is(err, fs.ErrNotExist).
func ReadFile(path string) ([]byte, error) { return readFile(path) }

// EnsureDir creates the state directory (only the last element; the parent must exist) with the
// service-identity-only protection, or verifies an existing one, and returns an error wrapping
// ErrDirUnsafe if it is wider. The connector calls it at startup and refuses to start on error.
// Unix: mode 0700, owned by the effective uid. Windows: owner = service identity, PROTECTED DACL of
// the service identity and SYSTEM only, inheritable so files created in it start restricted.
func EnsureDir(path string) error { return ensureDir(path) }

// CheckDir verifies an existing state directory without creating it.
func CheckDir(path string) error { return checkDir(path) }

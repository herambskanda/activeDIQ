// Package ownerfile creates and repairs files that only the running service identity may read or
// write (connector contract §8.3a: the shrink baseline).
//
// POSIX: mode 0600. Windows: Go ignores permission bits there, so the file would inherit the parent
// directory's ACL; instead the file gets an explicit, protected (non-inheriting) DACL granting
// FILE_ALL_ACCESS to the process token's user SID and to SYSTEM only, built with the typed
// security-descriptor API (never SDDL strings).
package ownerfile

import "os"

// OpenAppend opens path for appending, creating it owner-only if absent. If it already exists with
// wider access, the access is corrected (Windows: the DACL is replaced; POSIX: chmod 0600) before the
// handle is returned; corrected reports that. A failure to correct is an error: the caller must
// treat the baseline as not durable-and-private (LOCAL_RECORD_FAILED).
func OpenAppend(path string) (f *os.File, corrected bool, err error) {
	corrected, err = ensure(path)
	if err != nil {
		return nil, false, err
	}
	f, err = os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, false, err
	}
	return f, corrected, nil
}

// Restrict makes an existing file owner-only, as OpenAppend does. Used for temp files that are renamed
// over the target.
func Restrict(path string) (corrected bool, err error) { return restrictExisting(path) }

//go:build !unix

package updateverify

import (
	"errors"
	"os"
)

// checkPrivateDir fails closed: the DACL of the quarantine directory is not verified on this
// platform yet (follow-up T-0662, windows-engineer). Inject a Quarantine that checks it meanwhile.
func checkPrivateDir(string) error {
	return errors.New("directory ACL check not implemented on this platform")
}

// checkPrivateFile fails closed for the same reason (T-0662).
func checkPrivateFile(os.FileInfo) error {
	return errors.New("file ACL check not implemented on this platform")
}

//go:build !unix

package updateverify

import "errors"

// checkPrivateDir fails closed: the DACL of the quarantine directory is not verified on this
// platform yet (follow-up T-0662, windows-engineer). Inject a Quarantine that checks it meanwhile.
func checkPrivateDir(string) error {
	return errors.New("directory ACL check not implemented on this platform")
}

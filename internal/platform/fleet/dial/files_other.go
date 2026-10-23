//go:build !unix

package dial

import "errors"

// errNoACL: on non-unix hosts Go's 0600/0700 are no-ops and new files inherit the parent ACL, which
// under ProgramData lets other local users read the private key (TM-TB6-T2, TM-TB12-T2). Until the
// owner-only DACL is implemented (T-0291) the package fails closed: it neither writes nor reads
// enrollment state there.
var errNoACL = errors.New("owner-only ACL not implemented on this OS (T-0291)")

func ensureDir(string) error         { return errNoACL }
func checkDir(string) error          { return errNoACL }
func checkFile(string, bool) error   { return errNoACL }
func writeFile(string, []byte) error { return errNoACL }

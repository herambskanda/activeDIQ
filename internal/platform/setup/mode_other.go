//go:build !unix

package setup

import "io/fs"

// checkDirMode: on Windows access is the ACL the directory inherits from the API TLS directory
// (packaging/windows/Set-ApiTlsDirAcl.ps1); POSIX mode bits carry no meaning there.
func checkDirMode(fs.FileInfo) error { return nil }

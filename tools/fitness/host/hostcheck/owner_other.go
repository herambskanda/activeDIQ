//go:build !unix

package hostcheck

import "os"

func fileOwner(os.FileInfo) int { return -1 }

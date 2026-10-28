//go:build unix

package hostcheck

import (
	"os"
	"syscall"
)

func fileOwner(fi os.FileInfo) int {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid)
	}
	return -1
}

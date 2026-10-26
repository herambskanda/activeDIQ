//go:build !windows

package harnessdocker

import (
	"strconv"
	"strings"
	"syscall"
)

// ownerAlive reports whether the test process that owns a container still runs (signal 0 probe).
func ownerAlive(pid string) bool {
	n, err := strconv.Atoi(strings.TrimSpace(pid))
	if err != nil || n <= 0 {
		return false
	}
	err = syscall.Kill(n, 0)
	return err == nil || err == syscall.EPERM
}

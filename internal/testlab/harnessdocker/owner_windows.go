//go:build windows

package harnessdocker

import (
	"os"
	"strconv"
	"strings"
)

// ownerAlive reports whether the test process that owns a container still runs. On Windows
// os.FindProcess opens a handle and fails when the process does not exist.
func ownerAlive(pid string) bool {
	n, err := strconv.Atoi(strings.TrimSpace(pid))
	if err != nil || n <= 0 {
		return false
	}
	p, err := os.FindProcess(n)
	if err != nil {
		return false
	}
	_ = p.Release()
	return true
}

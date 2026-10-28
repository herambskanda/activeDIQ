//go:build windows

package rights

import (
	"golang.org/x/sys/windows"
)

// renameDurable replaces dst with src and returns after the rename is on disk: Windows cannot fsync a
// directory handle, so MOVEFILE_WRITE_THROUGH is the flush.
// https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-movefileexw
func renameDurable(src, dst string) error {
	s, err := windows.UTF16PtrFromString(src)
	if err != nil {
		return err
	}
	d, err := windows.UTF16PtrFromString(dst)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(s, d, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

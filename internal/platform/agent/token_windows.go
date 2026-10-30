//go:build windows

package agent

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// HeldPrivileges returns the names of every privilege present in this process's token, enabled or not
// (a disabled privilege can be enabled by a compromised process). Contract:
// https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation
func HeldPrivileges() ([]string, error) {
	tok := windows.GetCurrentProcessToken()
	var need uint32
	_ = windows.GetTokenInformation(tok, windows.TokenPrivileges, nil, 0, &need)
	if need == 0 || need > 64<<10 {
		return nil, fmt.Errorf("agent: unexpected token privilege size %d", need)
	}
	buf := make([]byte, need)
	if err := windows.GetTokenInformation(tok, windows.TokenPrivileges, &buf[0], need, &need); err != nil {
		return nil, err
	}
	tp := (*windows.Tokenprivileges)(unsafe.Pointer(&buf[0]))
	privs := unsafe.Slice(&tp.Privileges[0], tp.PrivilegeCount)
	out := make([]string, 0, len(privs))
	for i := range privs {
		name, err := lookupPrivilegeName(&privs[i].Luid)
		if err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, nil
}

var procLookupPrivilegeName = windows.NewLazySystemDLL("advapi32.dll").NewProc("LookupPrivilegeNameW")

// lookupPrivilegeName: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupprivilegenamew
func lookupPrivilegeName(l *windows.LUID) (string, error) {
	buf := make([]uint16, 128)
	n := uint32(len(buf))
	r, _, e := procLookupPrivilegeName.Call(0, uintptr(unsafe.Pointer(l)), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n)))
	if r == 0 {
		return "", e
	}
	return windows.UTF16ToString(buf[:n]), nil
}

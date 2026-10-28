//go:build windows

package agent

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// CheckDataDir refuses a data directory whose DACL grants any access to a principal other than the
// service's own SID, SYSTEM and Administrators (ADR-0006 decision 5), or that is a reparse point.
// It reads the DACL through the typed security APIs; no SDDL string is built or parsed.
// https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getnamedsecurityinfow
func CheckDataDir(dir string) error {
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	attrs, err := windows.GetFileAttributes(p)
	if err != nil {
		return err
	}
	if attrs&windows.FILE_ATTRIBUTE_DIRECTORY == 0 || attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("%s is not a plain directory", dir)
	}
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return errors.New("data directory has no DACL (everyone has access)")
	}
	allowed, err := allowedSIDs()
	if err != nil {
		return err
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			return err
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		ok := false
		for _, a := range allowed {
			if windows.EqualSid(sid, a) {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("data directory grants access to %s", sid.String())
		}
	}
	return nil
}

func allowedSIDs() ([]*windows.SID, error) {
	var out []*windows.SID
	for _, k := range []windows.WELL_KNOWN_SID_TYPE{windows.WinLocalSystemSid, windows.WinBuiltinAdministratorsSid} {
		s, err := windows.CreateWellKnownSid(k)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	tok := windows.GetCurrentProcessToken()
	u, err := tok.GetTokenUser()
	if err != nil {
		return nil, err
	}
	return append(out, u.User.Sid), nil
}

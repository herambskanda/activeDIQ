//go:build windows

package agent

import (
	"errors"
	"fmt"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// CheckDataDir refuses a data directory whose DACL grants any access to a principal other than the
// service's own SID, SYSTEM and Administrators (ADR-0006 decision 5), or that is a reparse point.
// It reads the DACL through the typed security APIs; no SDDL string is built or parsed.
// https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getnamedsecurityinfow
func CheckDataDir(dir string) error {
	allowed, err := allowedSIDs()
	if err != nil {
		return err
	}
	if err := checkOne(dir, allowed); err != nil {
		return err
	}
	// The parent (the agent root) must pass too, or its owner could swap the tree after the check.
	return checkOne(filepath.Dir(filepath.Clean(dir)), allowed)
}

func checkOne(dir string, allowed []*windows.SID) error {
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
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	// The owner holds implicit READ_CONTROL|WRITE_DAC, so it counts as a principal with access.
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !inSet(owner, allowed) {
		return fmt.Errorf("%s has an owner outside SYSTEM, Administrators and the service identity", dir)
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return errors.New("data directory has no DACL (everyone has access)")
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			return err
		}
		// Only plain allow and deny entries are understood. Any other type (callback/conditional,
		// object, compound) could grant access we cannot evaluate, so it is refused.
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
		default:
			return fmt.Errorf("%s has an ACE of unsupported type %d", dir, ace.Header.AceType)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !inSet(sid, allowed) {
			return fmt.Errorf("%s grants access to %s", dir, sid.String())
		}
	}
	return nil
}

func inSet(sid *windows.SID, set []*windows.SID) bool {
	for _, a := range set {
		if windows.EqualSid(sid, a) {
			return true
		}
	}
	return false
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

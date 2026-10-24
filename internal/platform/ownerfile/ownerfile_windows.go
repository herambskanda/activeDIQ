//go:build windows

package ownerfile

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// fileAllAccess is FILE_ALL_ACCESS (explicit, so no generic-right mapping is relied on).
const fileAllAccess = 0x1F01FF

// desiredACL builds the DACL: FILE_ALL_ACCESS for the process user and for SYSTEM. Microsoft Learn:
// ACL_REVISION via ACLFromEntries (https://learn.microsoft.com/windows/win32/api/aclapi/nf-aclapi-setentriesinacla).
func desiredSIDs() (user, system *windows.SID, err error) {
	tok := windows.GetCurrentProcessToken()
	tu, err := tok.GetTokenUser()
	if err != nil {
		return nil, nil, fmt.Errorf("ownerfile: token user: %w", err)
	}
	system, err = windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return nil, nil, fmt.Errorf("ownerfile: system sid: %w", err)
	}
	return tu.User.Sid, system, nil
}

func desiredACL() (*windows.ACL, error) {
	user, system, err := desiredSIDs()
	if err != nil {
		return nil, err
	}
	entry := func(s *windows.SID) windows.EXPLICIT_ACCESS {
		return windows.EXPLICIT_ACCESS{
			AccessPermissions: fileAllAccess,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_UNKNOWN,
				TrusteeValue: windows.TrusteeValueFromSID(s),
			},
		}
	}
	entries := []windows.EXPLICIT_ACCESS{entry(user)}
	if !user.Equals(system) {
		entries = append(entries, entry(system))
	}
	return windows.ACLFromEntries(entries, nil)
}

func ensure(path string) (bool, error) {
	acl, err := desiredACL()
	if err != nil {
		return false, err
	}
	created, err := createNew(path, acl)
	if err != nil {
		return false, err
	}
	if created {
		return false, nil
	}
	return apply(path, acl)
}

func restrictExisting(path string) (bool, error) {
	acl, err := desiredACL()
	if err != nil {
		return false, err
	}
	return apply(path, acl)
}

// createNew creates the file with the protected DACL atomically (no window where the inherited ACL
// applies). It reports false when the file already exists.
func createNew(path string, acl *windows.ACL) (bool, error) {
	sd, err := windows.NewSecurityDescriptor()
	if err != nil {
		return false, err
	}
	if err := sd.SetDACL(acl, true, false); err != nil {
		return false, err
	}
	// Protect the DACL from inheritance in the descriptor control bits.
	if err := sd.SetControl(windows.SE_DACL_PROTECTED, windows.SE_DACL_PROTECTED); err != nil {
		return false, err
	}
	sa := &windows.SecurityAttributes{SecurityDescriptor: sd, InheritHandle: 0}
	sa.Length = uint32(unsafe.Sizeof(*sa))
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_WRITE, 0, sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_EXISTS) {
			return false, nil
		}
		return false, err
	}
	return true, windows.CloseHandle(h)
}

// apply replaces the DACL when it is not exactly the desired one (or is not protected), and reports
// whether it did. Decision (T-0242 AC2): correct, do not merely report: the baseline is detective
// evidence, and a wider-than-contract file is repaired at open.
func apply(path string, want *windows.ACL) (bool, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false, err
	}
	ctrl, _, err := sd.Control()
	if err != nil {
		return false, err
	}
	have, _, err := sd.DACL()
	if err != nil {
		return false, err
	}
	if ctrl&windows.SE_DACL_PROTECTED != 0 && have != nil && sameACL(have, want) {
		return false, nil
	}
	err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, want, nil)
	if err != nil {
		return false, fmt.Errorf("ownerfile: set DACL: %w", err)
	}
	return true, nil
}

// sameACL compares the access-allowed ACE SIDs of two ACLs (same count, same SID set). Access masks
// are compared too: FILE_ALL_ACCESS is stored as is.
func sameACL(a, b *windows.ACL) bool {
	sa, ok := aceSet(a)
	if !ok {
		return false
	}
	sb, ok := aceSet(b)
	if !ok || len(sa) != len(sb) {
		return false
	}
	for k, m := range sa {
		if sb[k] != m {
			return false
		}
	}
	return true
}

func aceSet(a *windows.ACL) (map[string]uint32, bool) {
	out := map[string]uint32{}
	for i := uint32(0); i < uint32(a.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(a, i, &ace); err != nil {
			return nil, false
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return nil, false
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		out[sid.String()] |= uint32(ace.Mask)
	}
	return out, true
}

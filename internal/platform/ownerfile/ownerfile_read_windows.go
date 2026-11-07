//go:build windows

package ownerfile

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Handle-based verification (T-0577). The path is opened once with FILE_FLAG_OPEN_REPARSE_POINT (a
// link is opened as itself, never followed), and owner, DACL and kind are read from that handle with
// GetSecurityInfo / GetFileInformationByHandle. The caller uses only the returned handle.
// https://learn.microsoft.com/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo
// https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-getfileinformationbyhandle

// stateDirSD is the descriptor for the state directory: owner = service identity, PROTECTED DACL,
// FILE_ALL_ACCESS for the service identity and SYSTEM, inherited by files and subdirectories so a
// file created inside starts restricted. Built with the typed ACL API, never an SDDL string.
func stateDirSD(p principals) (*windows.SECURITY_DESCRIPTOR, error) {
	sids := p.sids()
	var entries []windows.EXPLICIT_ACCESS
	for _, s := range sids {
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: fileAllAccess,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_UNKNOWN,
				TrusteeValue: windows.TrusteeValueFromSID(s),
			},
		})
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return nil, err
	}
	sd, err := windows.NewSecurityDescriptor()
	if err != nil {
		return nil, err
	}
	if err := sd.SetOwner(p.owner(), false); err != nil {
		return nil, err
	}
	if err := sd.SetDACL(acl, true, false); err != nil {
		return nil, err
	}
	if err := sd.SetControl(windows.SE_DACL_PROTECTED, windows.SE_DACL_PROTECTED); err != nil {
		return nil, err
	}
	return sd, nil
}

func ensureDir(path string) error {
	pr, err := defaultPrincipals()
	if err != nil {
		return err
	}
	sd, err := stateDirSD(pr)
	if err != nil {
		return err
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	if err := windows.CreateDirectory(p, sa); err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return err
	}
	return checkDir(path)
}

func checkDir(path string) error {
	bad := fmt.Errorf("%w: %s", ErrDirUnsafe, filepath.Base(path))
	h, err := openNoFollow(path, windows.FILE_LIST_DIRECTORY, true)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	p, err := defaultPrincipals()
	if err != nil {
		return err
	}
	return verifyHandle(h, true, bad, p)
}

func readFile(path string) ([]byte, error) {
	h, err := openNoFollow(path, windows.GENERIC_READ, false)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(h), path) // owns h from here
	defer f.Close()
	p, err := defaultPrincipals()
	if err != nil {
		return nil, err
	}
	if err := verifyHandle(h, false, refuse(path, nil), p); err != nil {
		return nil, err
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxReadSize+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxReadSize {
		return nil, refuse(path, nil)
	}
	return b, nil
}

// refuse wraps ErrUnsafe (and why, if given) with the base name only: never the full path.
func refuse(path string, why error) error {
	if why == nil {
		return fmt.Errorf("%w: %s", ErrUnsafe, filepath.Base(path))
	}
	return fmt.Errorf("%w: %w: %s", ErrUnsafe, why, filepath.Base(path))
}

func openNoFollow(path string, access uint32, dir bool) (windows.Handle, error) {
	return openNoFollowShare(path, access, dir, windows.FILE_SHARE_READ)
}

// openNoFollowShare is openNoFollow with an explicit share mode.
func openNoFollowShare(path string, access uint32, dir bool, share uint32) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	flags := uint32(windows.FILE_ATTRIBUTE_NORMAL | windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if dir {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS // required to open a directory
	}
	return windows.CreateFile(p, access|windows.READ_CONTROL, share, nil,
		windows.OPEN_EXISTING, flags, 0)
}

// verifyHandle checks an open handle: not a reparse point, the expected kind, and owner and DACL.
// bad is returned for every refusal. A file's owner may be the token user, SYSTEM or
// BUILTIN\Administrators (trustedOwner, as OpenAppend); the directory's owner must be the token user.
func verifyHandle(h windows.Handle, dir bool, bad error, p principals) error {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return err
	}
	isDir := info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || isDir != dir {
		if !dir {
			return fmt.Errorf("%w: %w", bad, ErrNotRegular)
		}
		return bad
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	return verifySD(sd, dir, bad, p)
}

// verifySD accepts only a PROTECTED DACL of allow ACEs for the service identity and SYSTEM, with an
// acceptable owner. A NULL DACL (everyone), a deny, object or callback ACE, or any other SID is bad.
func verifySD(sd *windows.SECURITY_DESCRIPTOR, dir bool, bad error, p principals) error {
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	if dir {
		if owner == nil || !(owner.Equals(p.user) || (p.admins != nil && owner.Equals(p.admins))) {
			return bad
		}
	} else {
		ok, err := p.trustedOwner(owner)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("%w: %w", bad, ErrForeignOwner)
		}
	}
	ctrl, _, err := sd.Control()
	if err != nil {
		return err
	}
	if ctrl&windows.SE_DACL_PROTECTED == 0 {
		return bad
	}
	// DACL()'s second result is "defaulted" (SE_DACL_DEFAULTED), not "present": false for every
	// explicit DACL. An absent (NULL) DACL comes back as a nil acl and grants everyone full access.
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return bad
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			return err
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return bad
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !p.has(sid) {
			return bad
		}
	}
	return nil
}

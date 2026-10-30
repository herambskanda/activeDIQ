//go:build windows

package dial

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Owner-only state on Windows (TM-TB6-T2, TM-TB12-T2). Go's file modes are no-ops here and
// os.MkdirAll/os.CreateTemp inherit the parent ACL (ProgramData grants BUILTIN\Users read+create),
// so the state directory is created with an explicit, PROTECTED DACL granting full control to
// SYSTEM, BUILTIN\Administrators and the identity the component runs as, and nobody else.
// Every Load re-checks the owner and DACL of the directory and of each file, so a directory that was
// pre-created by another principal (squatting) or later widened is refused.
// Refs: https://learn.microsoft.com/windows/win32/secauthz/access-control-lists ,
// https://learn.microsoft.com/windows/win32/api/aclapi/nf-aclapi-getnamedsecurityinfow

const allowedACE = 0 // ACCESS_ALLOWED_ACE_TYPE

// principals returns the SIDs permitted on the state: SYSTEM, Administrators, and the process
// token's user (the service identity: gMSA, virtual account or the invoking admin).
func principals() (system, admins, self *windows.SID, err error) {
	if system, err = windows.CreateWellKnownSid(windows.WinLocalSystemSid); err != nil {
		return
	}
	if admins, err = windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid); err != nil {
		return
	}
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return
	}
	self = tu.User.Sid
	return
}

// ownerOnlySD builds the protected DACL: three allow-ACEs, inherited by children, no inheritance
// from the parent. Typed ACL API, no SDDL string.
func ownerOnlySD() (*windows.SECURITY_DESCRIPTOR, error) {
	system, admins, self, err := principals()
	if err != nil {
		return nil, err
	}
	entries := []windows.EXPLICIT_ACCESS{}
	for _, s := range []*windows.SID{system, admins, self} {
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.GENERIC_ALL,
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
	if err := sd.SetOwner(self, false); err != nil {
		return nil, err
	}
	if err := sd.SetDACL(acl, true, false); err != nil {
		return nil, err
	}
	// Protected: do not inherit the parent's ACEs.
	if err := sd.SetControl(windows.SE_DACL_PROTECTED, windows.SE_DACL_PROTECTED); err != nil {
		return nil, err
	}
	return sd, nil
}

func ensureDir(dir string) error {
	if _, err := os.Lstat(dir); err == nil {
		return checkDir(dir) // pre-existing: never adopt or repair it, only accept it if already safe
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return err
	}
	sd, err := ownerOnlySD()
	if err != nil {
		return err
	}
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	// Created atomically with the DACL: there is no window with the inherited ACL. Fails if it exists.
	if err := windows.CreateDirectory(p, sa); err != nil {
		return err
	}
	return checkDir(dir)
}

// checkDir refuses a directory not owned by SYSTEM/Administrators/the service identity, whose DACL is
// not protected, or that grants anything to anyone else (TM-TB12-T2).
func checkDir(dir string) error {
	st, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || isReparse(dir) {
		return fmt.Errorf("%s is not a plain directory", dir)
	}
	return checkACL(dir, true)
}

// checkFile refuses reparse points, non-regular files, and files whose owner or DACL is wider.
func checkFile(path string, _ bool) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || isReparse(path) {
		return fmt.Errorf("%s is not a regular file", filepath.Base(path))
	}
	return checkACL(path, false)
}

// isReparse reports whether path is a reparse point (junction, symlink, mount point), read straight
// from the file attributes so it does not depend on Go's winsymlink mapping or on os.FileInfo.Sys()
// (which is *syscall.Win32FileAttributeData, not the x/sys type). GetFileAttributes does not follow
// the final link. Any error is treated as "is a reparse point": fail closed.
// https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-getfileattributesw
func isReparse(path string) bool {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return true
	}
	a, err := windows.GetFileAttributes(p)
	if err != nil {
		return true
	}
	return a&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0
}

func checkACL(path string, needProtected bool) error {
	system, admins, self, err := principals()
	if err != nil {
		return err
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	bad := fmt.Errorf("%s must be owned by SYSTEM, Administrators or the component's identity and grant access to no one else", filepath.Base(path))
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return bad
	}
	if !owner.Equals(system) && !owner.Equals(admins) && !owner.Equals(self) {
		return bad
	}
	ctrl, _, err := sd.Control()
	if err != nil {
		return err
	}
	if needProtected && ctrl&windows.SE_DACL_PROTECTED == 0 {
		return bad
	}
	// DACL()'s second result is "defaulted", NOT "present": ignoring it is deliberate. A missing DACL
	// is reported through err (ERROR_OBJECT_NOT_FOUND); a nil acl is a NULL DACL, which grants everyone
	// full access, so both are refused.
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return bad
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			return err
		}
		if ace.Header.AceType != allowedACE { // deny and special ACEs are not part of our DACL
			return bad
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.Equals(system) && !sid.Equals(admins) && !sid.Equals(self) {
			return bad
		}
	}
	return nil
}

// writeFile writes data to a new temp file in dir (it inherits the protected DACL) and renames it
// into place (MoveFileEx with replace). The result is re-checked so a hostile ACL is never trusted.
func writeFile(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name) // no-op after a successful rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := checkACL(name, false); err != nil {
		return err
	}
	return os.Rename(name, path)
}

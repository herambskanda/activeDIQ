//go:build windows

package dial

import (
	"crypto/rand"
	"encoding/hex"
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

// trust is the set of principals the state may name. When the caller writes for another account
// (svc, T-1249: an administrator enrols for the service) the set is SYSTEM, Administrators and that
// account, and the owner is Administrators; otherwise it is SYSTEM, Administrators and the process
// token's user (the service identity: gMSA, virtual account, or the invoking admin), who is the owner.
// The invoking administrator's own user SID is NOT added in the first case: the service would refuse
// it as "someone else".
type trust struct {
	system, admins, member *windows.SID // member: the account (svc) or the token user
	asService              bool
}

func (t trust) owner() *windows.SID {
	if t.asService {
		return t.admins
	}
	return t.member
}

func (t trust) has(s *windows.SID) bool {
	return s != nil && (s.Equals(t.system) || s.Equals(t.admins) || s.Equals(t.member))
}

// principals resolves the trust set. svc is an account name as LookupAccountName accepts it, such as
// NT SERVICE\activeDIQAgent (resolvable once the service exists).
// https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-lookupaccountnamew
func principals(svc string) (t trust, err error) {
	if t.system, err = windows.CreateWellKnownSid(windows.WinLocalSystemSid); err != nil {
		return
	}
	if t.admins, err = windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid); err != nil {
		return
	}
	if svc != "" {
		t.asService = true
		if t.member, _, _, err = windows.LookupSID("", svc); err != nil {
			err = fmt.Errorf("account %q does not resolve (is the service installed?): %w", svc, err)
		}
		return
	}
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return
	}
	t.member = tu.User.Sid
	return
}

// ownerOnlySD builds the protected DACL: allow-ACEs for the trust set, inherited by children, no
// inheritance from the parent. Typed ACL API, no SDDL string.
func ownerOnlySD(svc string) (*windows.SECURITY_DESCRIPTOR, error) {
	t, err := principals(svc)
	if err != nil {
		return nil, err
	}
	entries := []windows.EXPLICIT_ACCESS{}
	for _, s := range []*windows.SID{t.system, t.admins, t.member} {
		if s == t.member && (s.Equals(t.system) || s.Equals(t.admins)) {
			continue // already covered by an earlier entry
		}
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
	if err := sd.SetOwner(t.owner(), false); err != nil {
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

func ensureDir(dir, svc string) error {
	if _, err := os.Lstat(dir); err == nil {
		return checkDir(dir, svc) // pre-existing: never adopt or repair it, only accept it if already safe
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return err
	}
	sd, err := ownerOnlySD(svc)
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
	return checkDir(dir, svc)
}

// checkDir refuses a directory not owned by SYSTEM/Administrators/the service identity, whose DACL is
// not protected, or that grants anything to anyone else (TM-TB12-T2).
func checkDir(dir, svc string) error {
	st, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || isReparse(dir) {
		return fmt.Errorf("%s is not a plain directory", dir)
	}
	return checkACL(dir, true, svc)
}

// checkFile refuses reparse points, non-regular files, and files whose owner or DACL is wider.
func checkFile(path string, _ bool, svc string) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || isReparse(path) {
		return fmt.Errorf("%s is not a regular file", filepath.Base(path))
	}
	return checkACL(path, false, svc)
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

func checkACL(path string, needProtected bool, svc string) error {
	t, err := principals(svc)
	if err != nil {
		return err
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	// The messages say which rule failed and name the file, never a SID list or content: they reach the
	// Application log (T-1249).
	name := filepath.Base(path)
	badOwner := fmt.Errorf("%s: owner is not SYSTEM, Administrators or the component's identity", name)
	badACL := fmt.Errorf("%s: DACL grants access to someone other than SYSTEM, Administrators and the component's identity", name)
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !t.has(owner) {
		return badOwner
	}
	ctrl, _, err := sd.Control()
	if err != nil {
		return err
	}
	if needProtected && ctrl&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("%s: DACL is not protected from inheritance", name)
	}
	// DACL()'s second result is "defaulted", NOT "present": ignoring it is deliberate. A missing DACL
	// is reported through err (ERROR_OBJECT_NOT_FOUND); a nil acl is a NULL DACL, which grants everyone
	// full access, so both are refused.
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return badACL
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			return err
		}
		if ace.Header.AceType != allowedACE { // deny and special ACEs are not part of our DACL
			return badACL
		}
		if !t.has((*windows.SID)(unsafe.Pointer(&ace.SidStart))) {
			return badACL
		}
	}
	return nil
}

// createTemp makes a new file in dir. For the caller's own state it is os.CreateTemp (default owner,
// inherited DACL). When writing for another account the file is created with an explicit owner,
// Administrators, and the DACL it inherits from the protected directory: the token's default owner
// may be the invoking administrator's user SID, which the service would refuse (T-1249).
// https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-createfilew
func createTemp(dir, svc string) (*os.File, error) {
	if svc == "" {
		return os.CreateTemp(dir, ".tmp-*")
	}
	t, err := principals(svc)
	if err != nil {
		return nil, err
	}
	sd, err := windows.NewSecurityDescriptor()
	if err != nil {
		return nil, err
	}
	if err := sd.SetOwner(t.admins, false); err != nil {
		return nil, err
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	for range 16 {
		var r [8]byte
		if _, err := rand.Read(r[:]); err != nil {
			return nil, err
		}
		name := filepath.Join(dir, ".tmp-"+hex.EncodeToString(r[:]))
		p, err := windows.UTF16PtrFromString(name)
		if err != nil {
			return nil, err
		}
		h, err := windows.CreateFile(p, windows.GENERIC_WRITE, 0, sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if errors.Is(err, windows.ERROR_FILE_EXISTS) {
			continue
		}
		if err != nil {
			return nil, err
		}
		return os.NewFile(uintptr(h), name), nil
	}
	return nil, errors.New("could not create a temporary file")
}

// writeFile writes data to a new temp file in dir (it inherits the protected DACL) and renames it
// into place (MoveFileEx with replace). The result is re-checked so a hostile ACL is never trusted.
func writeFile(path string, data []byte, svc string) error {
	tmp, err := createTemp(filepath.Dir(path), svc)
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
	if err := checkACL(name, false, svc); err != nil {
		return err
	}
	return os.Rename(name, path)
}

//go:build windows

package ownerfile

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows: owner = service identity (the process token's user: gMSA, virtual account or the invoking
// account); DACL = service identity and SYSTEM, full control, PROTECTED so nothing is inherited from
// the parent. The file is created with the descriptor in CreateFile, so there is no window in which
// it carries the inherited ACL. Built with the typed ACL API, never an SDDL string.
// Refs: https://learn.microsoft.com/windows/win32/secauthz/access-control-lists ,
// https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-createfilew ,
// https://learn.microsoft.com/windows/win32/api/aclapi/nf-aclapi-getnamedsecurityinfow

const allowedACE = 0 // ACCESS_ALLOWED_ACE_TYPE

func principals() (system, self *windows.SID, err error) {
	if system, err = windows.CreateWellKnownSid(windows.WinLocalSystemSid); err != nil {
		return
	}
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return
	}
	self = tu.User.Sid
	return
}

func descriptor(inherit uint32) (*windows.SECURITY_DESCRIPTOR, error) {
	system, self, err := principals()
	if err != nil {
		return nil, err
	}
	sids := []*windows.SID{self}
	if !self.Equals(system) {
		sids = append(sids, system)
	}
	var entries []windows.EXPLICIT_ACCESS
	for _, s := range sids {
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       inherit,
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
	if err := sd.SetControl(windows.SE_DACL_PROTECTED, windows.SE_DACL_PROTECTED); err != nil {
		return nil, err
	}
	return sd, nil
}

// create opens path with the restricted descriptor. disposition is CREATE_NEW or OPEN_ALWAYS (the
// descriptor only applies when the file is created).
func create(path string, disposition uint32, access uint32) (*os.File, error) {
	sd, err := descriptor(windows.NO_INHERITANCE)
	if err != nil {
		return nil, err
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	// FILE_FLAG_OPEN_REPARSE_POINT: a link planted at the path is opened as itself, then refused by the check.
	h, err := windows.CreateFile(p, access|windows.READ_CONTROL, windows.FILE_SHARE_READ, sa, disposition,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	// Verify the handle we write through, not the path (no check-then-use window).
	if err := verifyHandle(h, false, fmt.Errorf("%w: %s", ErrUnsafe, filepath.Base(path))); err != nil {
		_ = windows.CloseHandle(h)
		return nil, err
	}
	return os.NewFile(uintptr(h), path), nil
}

func openAppend(path string) (*os.File, error) {
	if _, err := os.Lstat(path); err == nil {
		if err := check(path); err != nil {
			return nil, err
		}
	}
	// GENERIC_WRITE (not FILE_APPEND_DATA alone) so FlushFileBuffers works; append by seeking to the end.
	// Writers are serialised by the caller.
	f, err := create(path, windows.OPEN_ALWAYS, windows.GENERIC_WRITE)
	if err != nil {
		return nil, err
	}
	if _, err := f.Seek(0, 2); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

func createTemp(dir, pattern string) (*os.File, error) {
	prefix, suffix, _ := strings.Cut(pattern, "*")
	for range 16 {
		var b [8]byte
		if _, err := rand.Read(b[:]); err != nil {
			return nil, err
		}
		name := filepath.Join(dir, prefix+hex.EncodeToString(b[:])+suffix)
		f, err := create(name, windows.CREATE_NEW, windows.GENERIC_WRITE)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			_ = os.Remove(name)
			return nil, err
		}
		return f, nil
	}
	return nil, fmt.Errorf("ownerfile: no unused temp name in %s", dir)
}

func check(path string) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	bad := fmt.Errorf("%w: %s", ErrUnsafe, filepath.Base(path))
	if !st.Mode().IsRegular() || isReparse(path) {
		return bad
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	return verifySD(sd, bad)
}

// verifySD accepts only: owner = service identity, PROTECTED DACL, allow ACEs for the service
// identity and SYSTEM. Inheritance flags on the ACEs are irrelevant to the principal check.
func verifySD(sd *windows.SECURITY_DESCRIPTOR, bad error) error {
	system, self, err := principals()
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !owner.Equals(self) {
		return bad
	}
	ctrl, _, err := sd.Control()
	if err != nil {
		return err
	}
	if ctrl&windows.SE_DACL_PROTECTED == 0 {
		return bad
	}
	// The second return value of DACL() is "defaulted" (SE_DACL_DEFAULTED), NOT "present": it is
	// false for every explicit DACL. A NULL/absent DACL comes back as a nil acl.
	acl, _, err := sd.DACL()
	if err != nil || acl == nil { // a NULL DACL grants everyone full access
		return bad
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			return err
		}
		if ace.Header.AceType != allowedACE {
			return bad
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.Equals(self) && !sid.Equals(system) {
			return bad
		}
	}
	return nil
}

// isReparse reads the attribute directly (GetFileAttributes does not follow the final link). Any
// error counts as a reparse point: fail closed.
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

// openChecked opens path without following a reparse point (FILE_FLAG_OPEN_REPARSE_POINT), then
// verifies the open handle: not a reparse point, expected kind, owner and DACL read with
// GetSecurityInfo on the handle itself. The caller works only with the returned handle, so a swap
// of the path after this point cannot change what is read.
// https://learn.microsoft.com/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo
// https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-getfileinformationbyhandle
func openChecked(path string, access uint32, dir bool, bad error) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	flags := uint32(windows.FILE_ATTRIBUTE_NORMAL | windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if dir {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
	}
	h, err := windows.CreateFile(p, access|windows.READ_CONTROL, windows.FILE_SHARE_READ, nil,
		windows.OPEN_EXISTING, flags, 0)
	if err != nil {
		return 0, err
	}
	if err := verifyHandle(h, dir, bad); err != nil {
		_ = windows.CloseHandle(h)
		return 0, err
	}
	return h, nil
}

// verifyHandle checks an already-open handle: not a reparse point, expected kind, owner and DACL.
func verifyHandle(h windows.Handle, dir bool, bad error) error {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return err
	}
	isDir := info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || isDir != dir {
		return bad
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	return verifySD(sd, bad)
}

func readFile(path string) ([]byte, error) {
	bad := fmt.Errorf("%w: %s", ErrUnsafe, filepath.Base(path))
	h, err := openChecked(path, windows.GENERIC_READ, false, bad)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(h), path)
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, MaxReadSize+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxReadSize {
		return nil, bad
	}
	return b, nil
}

func ensureDir(path string) error {
	sd, err := descriptor(windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT)
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
	h, err := openChecked(path, windows.FILE_LIST_DIRECTORY, true, fmt.Errorf("%w: %s", ErrDirUnsafe, filepath.Base(path)))
	if err != nil {
		return err
	}
	return windows.CloseHandle(h)
}

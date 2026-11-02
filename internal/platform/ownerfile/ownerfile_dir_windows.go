//go:build windows

package ownerfile

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Handle-held state directory (T-1315). Microsoft Learn:
//   - CreateFile, FILE_FLAG_OPEN_REPARSE_POINT: a link is opened as itself, never followed:
//     https://learn.microsoft.com/windows/win32/fileio/reparse-points-and-file-operations
//   - A handle opened without FILE_SHARE_DELETE makes a rename or delete of that directory fail with a
//     sharing violation for as long as it is open:
//     https://learn.microsoft.com/windows/win32/fileio/creating-and-opening-files (dwShareMode)
//   - GetFinalPathNameByHandle gives the path of the object the handle really refers to:
//     https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew

type dirImpl struct {
	h     windows.Handle
	final string // final path of the state directory, as GetFinalPathNameByHandle returns it (\\?\C:\...)
}

// Rights in an allow ACE that let a principal rename, delete or replace entries of a directory, add
// entries to it, or change its security. Any of them for an untrusted SID makes the directory
// untrustworthy as the parent of the state directory. Read-only rights are harmless.
const (
	fileWriteData     = 0x0002 // FILE_ADD_FILE on a directory
	fileAppendData    = 0x0004 // FILE_ADD_SUBDIRECTORY
	fileWriteEA       = 0x0010
	fileDeleteChild   = 0x0040
	fileWriteAttrs    = 0x0100
	accessDelete      = 0x00010000
	accessWriteDAC    = 0x00040000
	accessWriteOwner  = 0x00080000
	accessSystemSec   = 0x01000000
	accessMaximum     = 0x02000000
	genericAll        = 0x10000000
	genericWrite      = 0x40000000
	parentUntrustedOn = fileWriteData | fileAppendData | fileWriteEA | fileDeleteChild | fileWriteAttrs |
		accessDelete | accessWriteDAC | accessWriteOwner | accessSystemSec | accessMaximum | genericAll | genericWrite

	aceInheritOnly = 0x08 // INHERIT_ONLY_ACE: does not apply to the object itself
)

func openDir(path string, create bool) (*dirImpl, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	parentPath, base := filepath.Dir(abs), filepath.Base(abs)
	if base == "." || base == ".." || parentPath == abs {
		return nil, fmt.Errorf("%w: %s", ErrDirUnsafe, base)
	}
	// 1. The parent, opened without following a link at its last element and held (no FILE_SHARE_DELETE)
	//    until the state directory is open and tied to it.
	ph, err := openNoFollow(parentPath, windows.FILE_LIST_DIRECTORY, true)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(ph)
	if err := verifyParentHandle(ph); err != nil {
		return nil, err
	}
	// 2. Create (only after the parent is trusted) with the protected descriptor, or open what is there.
	if create {
		sd, err := stateDirSD()
		if err != nil {
			return nil, err
		}
		p, err := windows.UTF16PtrFromString(abs)
		if err != nil {
			return nil, err
		}
		sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
		if err := windows.CreateDirectory(p, sa); err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			return nil, err
		}
	}
	h, err := openNoFollow(abs, windows.FILE_LIST_DIRECTORY, true)
	if err != nil {
		return nil, err
	}
	bad := fmt.Errorf("%w: %s", ErrDirUnsafe, base)
	if err := verifyHandle(h, true, bad); err != nil {
		windows.CloseHandle(h)
		return nil, err
	}
	// 3. The parent that was verified must be the real parent of the directory that was opened: a
	//    parent swapped between the two opens, or reached through a link, shows up as a different path.
	final, err := finalPath(h)
	if err != nil {
		windows.CloseHandle(h)
		return nil, err
	}
	pfinal, err := finalPath(ph)
	if err != nil || !strings.EqualFold(pfinal, filepath.Dir(final)) {
		windows.CloseHandle(h)
		return nil, fmt.Errorf("%w: %s", ErrParentUnsafe, filepath.Base(parentPath))
	}
	return &dirImpl{h: h, final: final}, nil
}

// finalPath returns the normalized final path of the object h refers to.
func finalPath(h windows.Handle) (string, error) {
	buf := make([]uint16, 512)
	for {
		n, err := windows.GetFinalPathNameByHandle(h, &buf[0], uint32(len(buf)), 0) // FILE_NAME_NORMALIZED|VOLUME_NAME_DOS
		if err != nil {
			return "", err
		}
		if int(n) < len(buf) {
			return windows.UTF16ToString(buf[:n]), nil
		}
		buf = make([]uint16, n+1)
	}
}

// verifyParentHandle accepts a real directory (not a reparse point) owned by the service identity,
// SYSTEM or BUILTIN\Administrators whose DACL is present and gives no write, delete-child, create,
// delete or change-permissions right to anyone else.
func verifyParentHandle(h windows.Handle) error {
	bad := ErrParentUnsafe
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return bad
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	ok, err := trustedOwner(owner)
	if err != nil {
		return err
	}
	if !ok {
		return bad
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil { // a NULL DACL grants everyone everything
		return bad
	}
	user, system, err := desiredSIDs()
	if err != nil {
		return err
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	return checkParentACL(acl, []*windows.SID{user, system, admins}, bad)
}

// checkParentACL walks the DACL. Deny ACEs only narrow access and are skipped; an allow ACE of a kind
// this code does not model (callback, object) is refused; inherit-only ACEs do not apply to the
// directory itself.
func checkParentACL(acl *windows.ACL, trusted []*windows.SID, bad error) error {
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			return err
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE, 6, 10, 12: // denied, denied object, denied callback, denied callback object
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
		default:
			return bad
		}
		if ace.Header.AceFlags&aceInheritOnly != 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		isTrusted := false
		for _, t := range trusted {
			isTrusted = isTrusted || sid.Equals(t)
		}
		if !isTrusted && ace.Mask&parentUntrustedOn != 0 {
			return bad
		}
	}
	return nil
}

// childPath names a file inside the held directory by its final path, so that no component is resolved
// through a link that could have been placed since.
func (d *dirImpl) childPath(name string) string { return d.final + `\` + name }

func (d *dirImpl) readFile(name string) ([]byte, error) {
	path := d.childPath(name)
	h, err := openNoFollow(path, windows.GENERIC_READ, false)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(h), name) // owns h from here
	defer f.Close()
	if err := verifyHandle(h, false, refuse(name, nil)); err != nil {
		return nil, err
	}
	// The object opened must be this directory's child of that name (a hard link elsewhere or a path
	// resolved through a link would report a different final path).
	if fp, err := finalPath(h); err != nil || !strings.EqualFold(fp, path) {
		return nil, refuse(name, ErrNotRegular)
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxReadSize+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxReadSize {
		return nil, refuse(name, nil)
	}
	return b, nil
}

func (d *dirImpl) writeFile(name string, data []byte) (err error) {
	// createTemp gives the file an explicit protected descriptor in the CreateFile call itself.
	f, err := createTemp(d.final, ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmp)
		}
	}()
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, d.childPath(name)) // MoveFileEx with MOVEFILE_REPLACE_EXISTING
}

func (d *dirImpl) close() error { return windows.CloseHandle(d.h) }

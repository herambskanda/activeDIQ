//go:build windows

package ownerfile

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// fileAllAccess is FILE_ALL_ACCESS (explicit, so no generic-right mapping is relied on).
const fileAllAccess = 0x1F01FF

// noFollow is a POSIX concept; on Windows reparse points are refused by attribute check in apply.
const noFollow = 0

// desiredSIDs returns the token user and SYSTEM.
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

// principals is the set of identities a state directory may name. Default: the token user and SYSTEM.
// With Administrators trusted (admins != nil) BUILTIN\Administrators is a third. When the state is
// written for another account (asService, T-1249) user is that account and the owner is Administrators.
type principals struct {
	user, system, admins *windows.SID
	asService            bool
}

func defaultPrincipals() (principals, error) { return resolvePrincipals(dirOptions{}) }

// resolvePrincipals resolves the trust set for o. An account name is resolved with LookupAccountName,
// so it fails unless the account (for example the installed service) exists.
// https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-lookupaccountnamew
func resolvePrincipals(o dirOptions) (p principals, err error) {
	if p.system, err = windows.CreateWellKnownSid(windows.WinLocalSystemSid); err != nil {
		return p, fmt.Errorf("ownerfile: system sid: %w", err)
	}
	if o.admins {
		if p.admins, err = windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid); err != nil {
			return p, fmt.Errorf("ownerfile: administrators sid: %w", err)
		}
	}
	if o.account != "" {
		p.asService = true
		if p.user, _, _, err = windows.LookupSID("", o.account); err != nil {
			return p, fmt.Errorf("ownerfile: account %q does not resolve (is the service installed?): %w", o.account, err)
		}
		return p, nil
	}
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return p, fmt.Errorf("ownerfile: token user: %w", err)
	}
	p.user = tu.User.Sid
	return p, nil
}

// owner is who owns what is created: Administrators when writing for another account (the caller's
// default owner may be the administrator's own user SID, which the service would refuse), else the user.
func (p principals) owner() *windows.SID {
	if p.asService {
		return p.admins
	}
	return p.user
}

// has reports whether s is one of the principals an ACE may name.
func (p principals) has(s *windows.SID) bool {
	return s != nil && (s.Equals(p.user) || s.Equals(p.system) || (p.admins != nil && s.Equals(p.admins)))
}

// sids lists the principals once each.
func (p principals) sids() []*windows.SID {
	out := []*windows.SID{p.user}
	for _, s := range []*windows.SID{p.system, p.admins} {
		if s == nil {
			continue
		}
		dup := false
		for _, o := range out {
			dup = dup || o.Equals(s)
		}
		if !dup {
			out = append(out, s)
		}
	}
	return out
}

// trustedOwner: a file owner we accept is a principal of the set or BUILTIN\Administrators.
func (p principals) trustedOwner(owner *windows.SID) (bool, error) {
	if owner == nil {
		return false, nil
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return false, fmt.Errorf("ownerfile: administrators sid: %w", err)
	}
	return owner.Equals(p.user) || owner.Equals(p.system) || owner.Equals(admins), nil
}

// desiredACL builds the DACL: FILE_ALL_ACCESS for the process user and for SYSTEM. Microsoft Learn:
// https://learn.microsoft.com/windows/win32/api/aclapi/nf-aclapi-setentriesinacla
func desiredACL() (*windows.ACL, error) {
	p, err := defaultPrincipals()
	if err != nil {
		return nil, err
	}
	return aclFor(p)
}

func aclFor(p principals) (*windows.ACL, error) {
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
	var entries []windows.EXPLICIT_ACCESS
	for _, s := range p.sids() {
		entries = append(entries, entry(s))
	}
	return windows.ACLFromEntries(entries, nil)
}

// trustedOwner reports whether owner is the token user, SYSTEM or BUILTIN\Administrators. The
// owner holds implicit READ_CONTROL and WRITE_DAC, so only these may own a file we trust.
func trustedOwner(owner *windows.SID) (bool, error) {
	p, err := defaultPrincipals()
	if err != nil {
		return false, err
	}
	return p.trustedOwner(owner)
}

func ensure(path string) (bool, error) {
	acl, err := desiredACL()
	if err != nil {
		return false, err
	}
	created, err := createNewAt(path, acl)
	if err != nil {
		return false, err
	}
	if created {
		return false, nil
	}
	return apply(path, acl)
}

func securityAttributes(acl *windows.ACL, owner *windows.SID) (*windows.SecurityAttributes, error) {
	sd, err := windows.NewSecurityDescriptor()
	if err != nil {
		return nil, err
	}
	if owner != nil {
		if err := sd.SetOwner(owner, false); err != nil {
			return nil, err
		}
	}
	if err := sd.SetDACL(acl, true, false); err != nil {
		return nil, err
	}
	// Protect the DACL from inheritance in the descriptor control bits.
	if err := sd.SetControl(windows.SE_DACL_PROTECTED, windows.SE_DACL_PROTECTED); err != nil {
		return nil, err
	}
	sa := &windows.SecurityAttributes{SecurityDescriptor: sd, InheritHandle: 0}
	sa.Length = uint32(unsafe.Sizeof(*sa))
	return sa, nil
}

// createNewAt creates the file with the protected DACL atomically (no window where the inherited ACL
// applies). It reports false when the file already exists.
func createNewAt(path string, acl *windows.ACL) (bool, error) {
	h, err := createHandle(path, acl, nil)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_EXISTS) {
			return false, nil
		}
		return false, err
	}
	return true, windows.CloseHandle(h)
}

func createHandle(path string, acl *windows.ACL, owner *windows.SID) (windows.Handle, error) {
	sa, err := securityAttributes(acl, owner)
	if err != nil {
		return 0, err
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	// Share mode 0: nobody else can hold the file open while we write it.
	return windows.CreateFile(p, windows.GENERIC_WRITE, 0, sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
}

func createTemp(dir, pattern string) (*os.File, error) {
	p, err := defaultPrincipals()
	if err != nil {
		return nil, err
	}
	return createTempFor(dir, pattern, p)
}

// createTempFor creates the temp file with the DACL and owner p names, in the CreateFile call itself.
func createTempFor(dir, pattern string, p principals) (*os.File, error) {
	acl, err := aclFor(p)
	if err != nil {
		return nil, err
	}
	var owner *windows.SID
	if p.asService {
		owner = p.owner()
	}
	prefix, suffix := pattern, ""
	if i := strings.LastIndex(pattern, "*"); i >= 0 {
		prefix, suffix = pattern[:i], pattern[i+1:]
	}
	for try := 0; try < 100; try++ {
		var r [8]byte
		if _, err := rand.Read(r[:]); err != nil {
			return nil, err
		}
		name := filepath.Join(dir, prefix+hex.EncodeToString(r[:])+suffix)
		h, err := createHandle(name, acl, owner)
		if errors.Is(err, windows.ERROR_FILE_EXISTS) {
			continue
		}
		if err != nil {
			return nil, err
		}
		return os.NewFile(uintptr(h), name), nil
	}
	return nil, errors.New("ownerfile: no free temp name")
}

// apply refuses a reparse point or a foreign owner, and otherwise replaces the DACL when it is not
// exactly the desired one (or is not protected), reporting whether it did. Decision (T-0242 AC2): a
// wider file with a trusted owner is corrected at open, and the caller records that; a file owned by
// anyone else is refused, because its owner can undo any correction.
func apply(path string, want *windows.ACL) (bool, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false, err
	}
	attrs, err := windows.GetFileAttributes(p)
	if err != nil {
		return false, err
	}
	if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || attrs&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		return false, ErrNotRegular
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false, err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return false, err
	}
	ok, err := trustedOwner(owner)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, ErrForeignOwner
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

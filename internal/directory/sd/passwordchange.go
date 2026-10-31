package sd

import (
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
)

// PasswordChange is what the DACL of a user object says about the "Cannot Change Password" setting
// (reports-2-second-slice §4.2 rule 1). It is a four-valued state, not a boolean: "no deny ACE" is
// not "can change", and an unreadable descriptor is not "no deny ACE". The zero value is
// PasswordChangeNotConfirmed, so a forgotten assignment can never read as a clean bill.
type PasswordChange uint8

const (
	// PasswordChangeNotConfirmed: the descriptor was unreadable, malformed, had no DACL or was not
	// read. Always accompanied by an error from ClassifyPasswordChange.
	PasswordChangeNotConfirmed PasswordChange = iota
	// PasswordChangeBlocked: both explicit deny ACEs (Everyone and SELF) are present.
	PasswordChangeBlocked
	// PasswordChangeBlockedOneACE: exactly one of the two is present. The user still cannot change
	// the password (the user matches both Everyone and SELF), but the AD tools show the box unticked.
	PasswordChangeBlockedOneACE
	// PasswordChangeNoDenyACE: neither explicit deny ACE is present. Inherited denies, plain denies
	// of all control rights and allow ACEs are not evaluated, so this never means "can change".
	PasswordChangeNoDenyACE
)

func (p PasswordChange) String() string {
	switch p {
	case PasswordChangeBlocked:
		return "blocked"
	case PasswordChangeBlockedOneACE:
		return "blocked_one_ace"
	case PasswordChangeNoDenyACE:
		return "no_deny_ace"
	}
	return "not_confirmed"
}

// Blocks reports whether the state proves the user cannot change the password.
func (p PasswordChange) Blocks() bool {
	return p == PasswordChangeBlocked || p == PasswordChangeBlockedOneACE
}

// userChangePassword is the control-access right GUID of User-Change-Password
// (ab721a53-1e2f-11d0-9819-00aa0040529b), the object type of the two ACEs the AD tools write
// (https://learn.microsoft.com/en-us/windows/win32/adsi/reading-user-cannot-change-password-ldap-provider).
var userChangePassword = func() guid.GUID {
	g, err := guid.Parse("ab721a53-1e2f-11d0-9819-00aa0040529b")
	if err != nil {
		panic(err)
	}
	return g
}()

// ClassifyPasswordChange decodes a user's nTSecurityDescriptor (DACL part is enough) and reports the
// Cannot Change Password state. It reads the decoded DACL only, never bytes, and never the SACL.
//
// An ACE counts when it is an object-form ACCESS_DENIED ACE (type 0x06) with exactly the
// User-Change-Password object type, the CONTROL_ACCESS bit, trustee Everyone (S-1-1-0) or SELF
// (S-1-5-10), and it is neither inherited nor inherit-only nor carries an inherited-object type: the
// explicit, non-inherited ACEs the AD tools write. Callback ACEs are decoded but never counted.
//
// Any decode failure, or a descriptor with no DACL at all (the DC withheld it), returns
// PasswordChangeNotConfirmed and a typed error (the sd.* / acl.* / ace.* / sid.* codes, readable
// with codec.Code); no partial value is ever reported. A NULL DACL is a real DACL with no ACEs.
func ClassifyPasswordChange(r Raw) (PasswordChange, error) {
	d, err := Decode(r)
	if err != nil {
		return PasswordChangeNotConfirmed, err
	}
	return d.PasswordChange()
}

// PasswordChange classifies an already decoded descriptor; see ClassifyPasswordChange.
func (s SD) PasswordChange() (PasswordChange, error) {
	if s.DACL.Kind == Absent {
		return PasswordChangeNotConfirmed, fail(ErrNotReturned)
	}
	var everyone, self bool
	for _, a := range s.DACL.ACEs { // Null DACL has no ACEs
		if !isChangePasswordDeny(a) {
			continue
		}
		switch a.Trustee {
		case sidEveryone:
			everyone = true
		case sidSelf:
			self = true
		}
	}
	switch {
	case everyone && self:
		return PasswordChangeBlocked, nil
	case everyone || self:
		return PasswordChangeBlockedOneACE, nil
	}
	return PasswordChangeNoDenyACE, nil
}

func isChangePasswordDeny(a ACE) bool {
	return a.Kind == Object && a.Type == TypeAccessDeniedObject &&
		a.Flags&(FlagInherited|FlagInheritOnly) == 0 &&
		a.Mask&MaskControlAccess != 0 &&
		a.ObjectType != nil && *a.ObjectType == userChangePassword &&
		a.InheritedObjectType == nil
}

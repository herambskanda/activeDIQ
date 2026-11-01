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

// Blocks reports whether the state proves the user cannot change the password. A DACL that is not
// in canonical order is NotConfirmed, so it never blocks.
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
//
// Windows evaluates ACEs in stored order (SD-R11), so an allow that precedes a deny can let the user
// change the password. A DACL with an outcome-changing ordering anomaly (acl.order_outcome, rules 1 and
// 2) or a conditional allow ahead of a counted deny is therefore NotConfirmed with that code, never
// Blocked. The other decode anomalies are tolerated: see safe-primitives-security-descriptor §14.
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
	for _, an := range s.Anomalies {
		if an.Code == AnomalyOrderOutcome {
			return PasswordChangeNotConfirmed, fail(AnomalyOrderOutcome)
		}
	}
	var everyone, self, condAllow bool
	for _, a := range s.DACL.ACEs { // Null DACL has no ACEs
		if isConditionalAllow(a) {
			condAllow = true
		}
		if !isChangePasswordDeny(a) {
			continue
		}
		if condAllow {
			// A conditional allow is never evaluated here; ahead of a deny it may grant the right.
			return PasswordChangeNotConfirmed, fail(AnomalyCallbackPresent)
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

// isConditionalAllow is an allow-type callback ACE that applies to this object. It is decoded but its
// condition is never evaluated, so it might grant the right.
func isConditionalAllow(a ACE) bool {
	return a.Kind == Callback && !a.InheritOnly() &&
		(a.Type == TypeAllowedCallback || a.Type == TypeAllowedCallbackObject)
}

func isChangePasswordDeny(a ACE) bool {
	return a.Kind == Object && a.Type == TypeAccessDeniedObject &&
		a.Flags&(FlagInherited|FlagInheritOnly) == 0 &&
		a.Mask&MaskControlAccess != 0 &&
		a.ObjectType != nil && *a.ObjectType == userChangePassword &&
		a.InheritedObjectType == nil
}

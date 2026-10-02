// Package flags is the one codec for the flag integers of AD: userAccountControl (UAC),
// msDS-User-Account-Control-Computed (UACComputed) and groupType (GroupType); safe-primitives §5.5.
// They are Integer syntax (2.5.5.9), signed 32-bit on the wire, and are held here as the uint32 bit
// pattern. Bit maths on these attributes lives only in this package.
//
// Unknown bits survive decode and encode: newer Windows versions add bits, and a write never drops
// one we do not know. The stored UAC has no lockout or password-expired accessor, because those
// bits are unreliable there; UACComputed exposes exactly those two.
package flags

import (
	"strconv"

	"github.com/skenzeriq/activediq/internal/directory/attr/codec"
)

// Error codes.
const (
	BadInteger        = codec.BadInteger
	Overflow          = codec.Overflow
	NotSettable       = "NotSettable"       // LOCKOUT, PASSWD_CANT_CHANGE, PASSWORD_EXPIRED, account-type bits
	PrivilegeRequired = "PrivilegeRequired" // a delegation or security-weakening change without the capability
	InvalidScope      = "InvalidScope"      // groupType without exactly one of GLOBAL, DOMAIN_LOCAL, UNIVERSAL
	UnknownFlag       = "UnknownFlag"       // a change names something that is not one known flag
	ConflictingChange = "ConflictingChange" // the same flag in set and clear
)

// decode reads the signed 32-bit integer and returns its bit pattern.
func decode(raw string) (uint32, error) {
	n, err := codec.ParseInteger(raw, 32)
	if err != nil {
		return 0, err
	}
	return uint32(int32(n)), nil
}

// encode renders the bit pattern as AD does: a signed decimal.
func encode(bits uint32) string { return strconv.FormatInt(int64(int32(bits)), 10) }

// flagName pairs a bit with its Microsoft name, in bit order.
type flagName struct {
	bit  uint32
	name string
}

func namesOf(table []flagName, bits uint32) []string {
	out := []string{}
	for _, f := range table {
		if bits&f.bit != 0 {
			out = append(out, f.name)
		}
	}
	return out
}

func lookup(table []flagName, name string) (uint32, bool) {
	for _, f := range table {
		if f.name == name {
			return f.bit, true
		}
	}
	return 0, false
}

func knownMask(table []flagName) uint32 {
	var m uint32
	for _, f := range table {
		m |= f.bit
	}
	return m
}

// ---- userAccountControl ----

// UACFlag is one stored userAccountControl bit. LOCKOUT (0x10) and PASSWORD_EXPIRED (0x800000) are
// deliberately not constants: the stored bits are unreliable (use UACComputed). Their names are
// still understood by ParseUACFlag so that a change that names them is refused with NotSettable.
type UACFlag uint32

// The stored flags (ad-engineering reference/uac-flags.md; Microsoft Learn "useraccountcontrol").
const (
	UACScript                     UACFlag = 0x1
	UACAccountDisable             UACFlag = 0x2
	UACHomedirRequired            UACFlag = 0x8
	UACPasswdNotReqd              UACFlag = 0x20
	UACPasswdCantChange           UACFlag = 0x40
	UACEncryptedTextPwdAllowed    UACFlag = 0x80
	UACTempDuplicateAccount       UACFlag = 0x100
	UACNormalAccount              UACFlag = 0x200
	UACInterdomainTrustAccount    UACFlag = 0x800
	UACWorkstationTrustAccount    UACFlag = 0x1000
	UACServerTrustAccount         UACFlag = 0x2000
	UACDontExpirePassword         UACFlag = 0x10000
	UACMnsLogonAccount            UACFlag = 0x20000
	UACSmartcardRequired          UACFlag = 0x40000
	UACTrustedForDelegation       UACFlag = 0x80000
	UACNotDelegated               UACFlag = 0x100000
	UACUseDesKeyOnly              UACFlag = 0x200000
	UACDontReqPreauth             UACFlag = 0x400000
	UACTrustedToAuthForDelegation UACFlag = 0x1000000
	UACPartialSecretsAccount      UACFlag = 0x4000000
)

const (
	bitLockout         = 0x10
	bitPasswordExpired = 0x800000
)

var uacTable = []flagName{
	{0x1, "SCRIPT"}, {0x2, "ACCOUNTDISABLE"}, {0x8, "HOMEDIR_REQUIRED"}, {0x20, "PASSWD_NOTREQD"},
	{0x40, "PASSWD_CANT_CHANGE"}, {0x80, "ENCRYPTED_TEXT_PWD_ALLOWED"}, {0x100, "TEMP_DUPLICATE_ACCOUNT"},
	{0x200, "NORMAL_ACCOUNT"}, {0x800, "INTERDOMAIN_TRUST_ACCOUNT"}, {0x1000, "WORKSTATION_TRUST_ACCOUNT"},
	{0x2000, "SERVER_TRUST_ACCOUNT"}, {0x10000, "DONT_EXPIRE_PASSWORD"}, {0x20000, "MNS_LOGON_ACCOUNT"},
	{0x40000, "SMARTCARD_REQUIRED"}, {0x80000, "TRUSTED_FOR_DELEGATION"}, {0x100000, "NOT_DELEGATED"},
	{0x200000, "USE_DES_KEY_ONLY"}, {0x400000, "DONT_REQ_PREAUTH"},
	{0x1000000, "TRUSTED_TO_AUTH_FOR_DELEGATION"}, {0x4000000, "PARTIAL_SECRETS_ACCOUNT"},
}

var uacKnown = knownMask(uacTable)

// ParseUACFlag maps a Microsoft flag name to its bit, including the two unreliable ones.
func ParseUACFlag(name string) (UACFlag, bool) {
	switch name {
	case "LOCKOUT":
		return bitLockout, true
	case "PASSWORD_EXPIRED":
		return bitPasswordExpired, true
	}
	b, ok := lookup(uacTable, name)
	return UACFlag(b), ok
}

// UAC is a stored userAccountControl value.
type UAC struct{ bits uint32 }

// DecodeUAC reads the raw LDAP octets of userAccountControl.
func DecodeUAC(raw string) (UAC, error) {
	b, err := decode(raw)
	return UAC{b}, err
}

// Encode is the raw LDAP octets, signed decimal, every bit preserved.
func (u UAC) Encode() string { return encode(u.bits) }

// Has reports whether the flag is set.
func (u UAC) Has(f UACFlag) bool { return uint32(f) != 0 && u.bits&uint32(f) == uint32(f) }

// Names lists the known flags that are set, in bit order, by Microsoft name.
func (u UAC) Names() []string { return namesOf(uacTable, u.bits) }

// Unknown is every set bit this type does not interpret: bits newer than the table and the two
// unreliable stored bits (LOCKOUT, PASSWORD_EXPIRED). They are carried through encode unchanged.
func (u UAC) Unknown() uint32 { return u.bits &^ uacKnown }

// Privileges are the capabilities a caller holds that gate risky flag changes.
type Privileges struct {
	// EnableDelegation allows setting TRUSTED_FOR_DELEGATION and TRUSTED_TO_AUTH_FOR_DELEGATION
	// (SeEnableDelegationPrivilege on the DC; the caller's own authorisation here).
	EnableDelegation bool
	// WeakenAccountSecurity allows the changes that make an account easier to attack: setting
	// PASSWD_NOTREQD, ENCRYPTED_TEXT_PWD_ALLOWED, USE_DES_KEY_ONLY or DONT_REQ_PREAUTH, and clearing
	// NOT_DELEGATED or SMARTCARD_REQUIRED. The DC asks only for write access to userAccountControl,
	// so this is the one place the capability is enforced before the write.
	WeakenAccountSecurity bool
}

// Change is a set of flags to set and a set to clear.
type Change struct{ Set, Clear []UACFlag }

// Edit is the result of applying a Change to the value read: the old and new raw values for a
// compare-and-swap (delete old, add new) modify.
type Edit struct{ Old, New UAC }

// accountType is every bit that fixes what kind of object the account is. It is set by the create
// path and never toggled: turning a computer into a DC (SERVER_TRUST), an RODC (PARTIAL_SECRETS) or a
// trust account would hand its holder replication rights.
const accountType = uint32(UACTempDuplicateAccount) | uint32(UACNormalAccount) | uint32(UACInterdomainTrustAccount) |
	uint32(UACWorkstationTrustAccount) | uint32(UACServerTrustAccount) | uint32(UACPartialSecretsAccount)

const notSettable = bitLockout | uint32(UACPasswdCantChange) | bitPasswordExpired | accountType

const privileged = uint32(UACTrustedForDelegation) | uint32(UACTrustedToAuthForDelegation)

// weakeningSet are bits whose setting weakens an account; weakeningClear are bits whose clearing does.
const (
	weakeningSet = uint32(UACPasswdNotReqd) | uint32(UACEncryptedTextPwdAllowed) | uint32(UACUseDesKeyOnly) | uint32(UACDontReqPreauth)

	weakeningClear = uint32(UACNotDelegated) | uint32(UACSmartcardRequired)
)

// Apply applies c to the value read. LOCKOUT, PASSWD_CANT_CHANGE and PASSWORD_EXPIRED can be neither
// set nor cleared (unlock is lockoutTime=0; the others are ACEs or computed); nor can the account
// type bits (NORMAL, TEMP_DUPLICATE, INTERDOMAIN_TRUST, WORKSTATION_TRUST, SERVER_TRUST,
// PARTIAL_SECRETS). The delegation flags can be set only with Privileges.EnableDelegation (clearing
// them is always allowed). The weakening changes (see Privileges.WeakenAccountSecurity) need that
// capability; the hardening directions are free. Each flag in the change must be exactly one known bit.
func (u UAC) Apply(c Change, p Privileges) (Edit, error) {
	set, err := mask(c.Set)
	if err != nil {
		return Edit{}, err
	}
	clr, err := mask(c.Clear)
	if err != nil {
		return Edit{}, err
	}
	switch {
	case (set|clr)&notSettable != 0:
		return Edit{}, codec.New(NotSettable)
	case set&clr != 0:
		return Edit{}, codec.New(ConflictingChange)
	case set&privileged != 0 && !p.EnableDelegation:
		return Edit{}, codec.New(PrivilegeRequired)
	case (set&weakeningSet != 0 || clr&weakeningClear != 0) && !p.WeakenAccountSecurity:
		return Edit{}, codec.New(PrivilegeRequired)
	}
	return Edit{Old: u, New: UAC{(u.bits | set) &^ clr}}, nil
}

func mask(fs []UACFlag) (uint32, error) {
	var m uint32
	for _, f := range fs {
		b := uint32(f)
		if b == 0 || b&(b-1) != 0 || (b&uacKnown == 0 && b != bitLockout && b != bitPasswordExpired) {
			return 0, codec.New(UnknownFlag)
		}
		m |= b
	}
	return m, nil
}

// ---- msDS-User-Account-Control-Computed ----

// UACComputed is a computed userAccountControl value. It is the source of lockout and
// password-expired state.
type UACComputed struct{ bits uint32 }

// DecodeUACComputed reads the raw LDAP octets of msDS-User-Account-Control-Computed.
func DecodeUACComputed(raw string) (UACComputed, error) {
	b, err := decode(raw)
	return UACComputed{b}, err
}

// Encode is the raw LDAP octets, every bit preserved.
func (u UACComputed) Encode() string { return encode(u.bits) }

// LockedOut is LOCKOUT (0x10).
func (u UACComputed) LockedOut() bool { return u.bits&bitLockout != 0 }

// PasswordExpired is PASSWORD_EXPIRED (0x800000).
func (u UACComputed) PasswordExpired() bool { return u.bits&bitPasswordExpired != 0 }

// Unknown is every set bit other than the two MS-ADTS defines for this attribute on AD DS.
func (u UACComputed) Unknown() uint32 { return u.bits &^ (bitLockout | bitPasswordExpired) }

// ---- groupType ----

// GroupType is a groupType value.
type GroupType struct{ bits uint32 }

// Scope is a group's scope.
type Scope string

// The three scopes.
const (
	ScopeGlobal      Scope = "global"
	ScopeDomainLocal Scope = "domainLocal"
	ScopeUniversal   Scope = "universal"
)

const (
	gtBuiltin     = 0x1
	gtGlobal      = 0x2
	gtDomainLocal = 0x4
	gtUniversal   = 0x8
	gtSecurity    = 0x80000000
)

var groupTable = []flagName{
	{gtBuiltin, "BUILTIN_LOCAL_GROUP"}, {gtGlobal, "GLOBAL"}, {gtDomainLocal, "DOMAIN_LOCAL"},
	{gtUniversal, "UNIVERSAL"}, {0x10, "APP_BASIC"}, {0x20, "APP_QUERY"}, {gtSecurity, "SECURITY"},
}

var groupKnown = knownMask(groupTable)

// DecodeGroupType reads the raw LDAP octets of groupType. AD sends it signed (a security group is
// negative), so an unsigned value above 2^31-1 is Overflow.
func DecodeGroupType(raw string) (GroupType, error) {
	b, err := decode(raw)
	return GroupType{b}, err
}

// Encode is the raw LDAP octets, signed decimal, every bit preserved.
func (g GroupType) Encode() string { return encode(g.bits) }

// Names lists the known flags that are set, in bit order, by Microsoft name.
func (g GroupType) Names() []string { return namesOf(groupTable, g.bits) }

// Unknown is every set bit outside the known table.
func (g GroupType) Unknown() uint32 { return g.bits &^ groupKnown }

// IsSecurity reports a security group (as opposed to a distribution group).
func (g GroupType) IsSecurity() bool { return g.bits&gtSecurity != 0 }

// IsBuiltin reports the BUILTIN_LOCAL_GROUP bit.
func (g GroupType) IsBuiltin() bool { return g.bits&gtBuiltin != 0 }

// Scope requires exactly one of GLOBAL, DOMAIN_LOCAL, UNIVERSAL; anything else is InvalidScope.
func (g GroupType) Scope() (Scope, error) {
	switch g.bits & (gtGlobal | gtDomainLocal | gtUniversal) {
	case gtGlobal:
		return ScopeGlobal, nil
	case gtDomainLocal:
		return ScopeDomainLocal, nil
	case gtUniversal:
		return ScopeUniversal, nil
	}
	return "", codec.New(InvalidScope)
}

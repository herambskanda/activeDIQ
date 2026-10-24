package sd

// SDFlagsOID is the SD_FLAGS LDAP control (MS-ADTS 3.1.1.3.4.1.11).
const SDFlagsOID = "1.2.840.113556.1.4.801"

// Parts selects components of a security descriptor: the four SECURITY_INFORMATION bits and
// nothing else.
type Parts uint8

const (
	PartOwner Parts = 1
	PartGroup Parts = 2
	PartDACL  Parts = 4
	PartSACL  Parts = 8
)

// SACLCap is the capability to read a SACL (SeSecurityPrivilege, Tier-0). It cannot be built
// outside this package; the issuer for a Tier-0 connector identity is a later ticket (§8), so
// today no caller can read a SACL.
type SACLCap struct{ ok bool }

// Control is an encoded LDAP control, always critical so a server that ignores it fails instead of
// applying its default of 15 (all four parts, SACL included).
type LDAPControl struct {
	OID      string
	Critical bool
	Value    []byte
}

// ReadControl encodes the SD_FLAGS control for a read. Zero parts, unknown bits, and a SACL
// without capability are refused: the server treats zero as 15 and ignores unknown bits.
func ReadControl(p Parts, caps ...SACLCap) (LDAPControl, error) {
	if p == 0 {
		return LDAPControl{}, fail(ErrFlagsEmpty)
	}
	if p&^(PartOwner|PartGroup|PartDACL|PartSACL) != 0 {
		return LDAPControl{}, fail(ErrFlagsUnknownBits)
	}
	if p&PartSACL != 0 {
		granted := false
		for _, c := range caps {
			granted = granted || c.ok
		}
		if !granted {
			return LDAPControl{}, fail(ErrSACLNeedsCapability)
		}
	}
	return LDAPControl{OID: SDFlagsOID, Critical: true, Value: []byte{0x30, 0x03, 0x02, 0x01, byte(p)}}, nil
}

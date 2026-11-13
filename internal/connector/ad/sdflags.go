package ad

import (
	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

// SDPart is one part of a security descriptor the connector may request. There is deliberately no
// SACL member: reading the SACL needs SeSecurityPrivilege, the connector never asks for it and a
// request for it cannot be constructed (safe-primitives-security-descriptor §3.6).
type SDPart uint8

const (
	SDOwner SDPart = 1 // OWNER_SECURITY_INFORMATION
	SDGroup SDPart = 2 // GROUP_SECURITY_INFORMATION
	SDDACL  SDPart = 4 // DACL_SECURITY_INFORMATION
)

// sdAll is the whole set of requestable bits. SACL (8) is outside it.
const sdAll = uint8(SDOwner) | uint8(SDGroup) | uint8(SDDACL)

// SDFlags is a validated selection of SD parts. The zero value selects nothing and sends no control.
type SDFlags struct{ bits uint8 }

// NewSDFlags selects the given parts. An empty list, an unknown part or SACL (8) is refused.
func NewSDFlags(parts ...SDPart) (SDFlags, error) {
	var b uint8
	for _, p := range parts {
		if uint8(p)&^sdAll != 0 || p == 0 || p&(p-1) != 0 {
			return SDFlags{}, fail(CodeInvalidArgument, "sd part not requestable", nil)
		}
		b |= uint8(p)
	}
	if b == 0 {
		return SDFlags{}, fail(CodeInvalidArgument, "no sd part selected", nil)
	}
	return SDFlags{bits: b}, nil
}

// DefaultSDFlags is owner, group and DACL: what the tier-0 classifier and the rights check read.
func DefaultSDFlags() SDFlags { return SDFlags{bits: sdAll} }

// IsZero reports whether nothing is selected.
func (f SDFlags) IsZero() bool { return f.bits == 0 }

// Value is the integer sent in the control.
func (f SDFlags) Value() int32 { return int32(f.bits) }

// sdControl is the SD flags control (1.2.840.113556.1.4.801). Sent critical. Without it the DC
// applies the default of 15 (MS-ADTS 3.1.1.3.4.1.11), which INCLUDES the SACL, so a server that
// ignored a non-critical control would hand over SACLs. Critical makes it fail instead.
type sdControl struct{ v int32 }

func (c sdControl) GetControlType() string { return ldap.ControlTypeMicrosoftSDFlags }

func (c sdControl) Encode() *ber.Packet {
	p := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, ldap.ControlTypeMicrosoftSDFlags, "Control Type (SD Flags)"))
	p.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, true, "Criticality"))
	val := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "Control Value")
	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "SDFlags")
	seq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, c.v, "Flags"))
	val.AppendChild(seq)
	p.AppendChild(val)
	return p
}

func (c sdControl) String() string { return "SD Flags control" }

func (f SDFlags) control() ldap.Control {
	if f.IsZero() {
		return nil
	}
	return sdControl{v: f.Value()}
}

// berPacket aliases the BER packet type so control files share one import.
type berPacket = ber.Packet

// encodeCriticalValuelessControl is encodeValuelessControl with the criticality flag set: a DC that
// does not support the control fails the request instead of silently ignoring it.
func encodeCriticalValuelessControl(oid string) *ber.Packet {
	p := encodeValuelessControl(oid)
	p.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, true, "Criticality"))
	return p
}

func encodeValuelessControl(oid string) *ber.Packet {
	p := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, oid, "Control Type"))
	return p
}

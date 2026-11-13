// Package scope is the named-operation table of the escape controls (safe-primitives §3.5, LF-30):
// the only place their OIDs are written. A caller asks for an operation by name and gets a control;
// no caller supplies an OID.
package scope

import (
	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

// oidShowDeleted is LDAP_SERVER_SHOW_DELETED_OID, the control that makes deleted objects visible
// (MS-ADTS 3.1.1.3.4.1.14).
const oidShowDeleted = "1.2.840.113556.1.4.417"

// oidShowDeactivatedLink is LDAP_SERVER_SHOW_DEACTIVATED_LINK_OID: without it, link values (memberOf)
// stored on a deleted object are not returned (MS-ADTS 3.1.1.3.4.1.25), so a deleted Domain Admin
// would read as a member of nothing.
const oidShowDeactivatedLink = "1.2.840.113556.1.4.2065"

type valueless struct {
	oid      string
	name     string
	critical bool
}

func (v valueless) GetControlType() string { return v.oid }
func (v valueless) String() string         { return v.name }
func (v valueless) Encode() *ber.Packet {
	p := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, v.oid, "Control Type"))
	if v.critical {
		p.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, true, "Criticality"))
	}
	return p
}

// ShowDeleted is the named operation "read deleted objects": a critical show-deleted control, so a
// DC that does not support it fails the request instead of ignoring it.
func ShowDeleted() ldap.Control {
	return valueless{oid: oidShowDeleted, name: "Show deleted control", critical: true}
}

// ShowDeactivatedLink is the named operation "read link values of a deleted object".
func ShowDeactivatedLink() ldap.Control {
	return valueless{oid: oidShowDeactivatedLink, name: "Show deactivated link control"}
}

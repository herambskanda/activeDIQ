// Package scope is the only place the escape-control OIDs are written (safe-primitives §3.6, LF-30,
// fitness rule FF-SP2 escape-control-oid). A control constructor here is a named operation's, never a
// caller's: each takes the least a caller can influence and fixes the rest.
//
// Today it holds the two controls of the ChangeTracking named operation (connector-contract §6.2):
// DirSync, in object-security mode with incremental values and nothing else, and show-deleted.
// ADM-038 RestoreDeleted and the other named operations add theirs here.
package scope

import (
	"encoding/binary"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

const (
	oidDirSync     = "1.2.840.113556.1.4.841"
	oidShowDeleted = "1.2.840.113556.1.4.417"
)

// The DirSync flags are a constant of this package, not a parameter of anything: object-security
// mode (0x1) so the DC returns only what the bound identity may read and no replication right is
// needed or held, plus incremental values (0x80000000) so a link attribute reports the changed
// value, not the whole set. Replication-rights mode, ancestors-first, public-data-only and DirSync EX
// (…2090) are unrepresentable here (threat-model §6.3 R2).
const (
	dirSyncObjectSecurity   uint32 = 0x00000001
	dirSyncIncrementalValue uint32 = 0x80000000

	// DirSyncFlags is the one flags value the connector ever sends.
	DirSyncFlags = dirSyncObjectSecurity | dirSyncIncrementalValue

	// dirSyncMaxBytes is the per-response byte budget: the Windows minimum (0x100000), which is what
	// a smaller request is raised to anyway (contract §6.5 item 5). Samba ignores it.
	dirSyncMaxBytes int64 = 0x100000
)

// DirSync returns the critical DirSync request control carrying cookie (nil on the first request).
func DirSync(cookie []byte) ldap.Control { return dirSyncReq{cookie: cookie} }

// ShowDeleted returns the critical show-deleted control: tombstones and deleted objects become
// visible to the search. Raw LDAP does not include them on its own.
func ShowDeleted() ldap.Control { return showDeleted{} }

// Response is the DirSync response control of one search.
type Response struct {
	Cookie      []byte // the position after this response; opaque
	MoreResults bool   // the DC has more to send from this cycle
}

// DirSyncResponse finds the DirSync response control among a search result's controls. ok is false
// when the DC sent none, which the caller treats as a protocol error: a feed without a cookie cannot
// be resumed.
func DirSyncResponse(ctrls []ldap.Control) (r Response, ok bool) {
	for _, c := range ctrls {
		d, is := c.(*ldap.ControlDirSync)
		if !is {
			continue
		}
		// The response's first integer is MoreData: non-zero while the cycle continues.
		return Response{Cookie: append([]byte(nil), d.Cookie...), MoreResults: d.Flags != 0}, true
	}
	return Response{}, false
}

type dirSyncReq struct{ cookie []byte }

func (dirSyncReq) GetControlType() string { return oidDirSync }
func (dirSyncReq) String() string         { return "DirSync (object security, incremental values)" }

func (c dirSyncReq) Encode() *ber.Packet {
	cookie := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "Cookie")
	cookie.Value = c.cookie
	cookie.Data.Write(c.cookie)

	p := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, oidDirSync, "Control Type (DirSync)"))
	p.AppendChild(ber.NewLDAPBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, true, "Criticality"))
	val := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "Control Value (DirSync)")
	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "DirSync Control Value")

	// AD reads the flags as a 4-byte unsigned integer. ASN.1 integers are signed, so the generic
	// encoder would write 0x80000001 as five bytes; write exactly four.
	flags := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, nil, "Flags")
	flags.Value = int64(DirSyncFlags)
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, DirSyncFlags)
	flags.Data.Write(b)
	seq.AppendChild(flags)
	seq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, dirSyncMaxBytes, "MaxBytes"))
	seq.AppendChild(cookie)
	val.AppendChild(seq)
	p.AppendChild(val)
	return p
}

type showDeleted struct{}

func (showDeleted) GetControlType() string { return oidShowDeleted }
func (showDeleted) String() string         { return "Show deleted objects" }

func (showDeleted) Encode() *ber.Packet {
	p := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, oidShowDeleted, "Control Type (Show Deleted)"))
	p.AppendChild(ber.NewLDAPBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, true, "Criticality"))
	return p
}

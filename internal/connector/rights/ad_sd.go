package rights

import (
	"encoding/binary"
	"errors"

	adguid "github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/attr/sid"
)

// A read-only security descriptor reader for the rights check (TM §6.5 steps 3 and 4). It decodes
// owner and DACL only (the SACL is never requested, so never parsed), allow and deny ACEs of both
// plain and object form, and fails closed on any malformed byte. The typed writer primitive is
// T-0149; nothing here writes.

var errSD = errors.New("rights: malformed security descriptor")
var errNullDACL = errors.New("rights: security descriptor has a NULL DACL")

// Access mask bits of a directory object (MS-ADTS 5.1.3.2).
const (
	dsCreateChild   = 0x00000001
	dsDeleteChild   = 0x00000002
	dsSelf          = 0x00000008 // validated write
	dsReadProp      = 0x00000010
	dsWriteProp     = 0x00000020
	dsDeleteTree    = 0x00000040
	dsControlAccess = 0x00000100
	maskWriteDAC    = 0x00040000
	maskWriteOwner  = 0x00080000
	maskGenericAll  = 0x10000000
	maskGenericWr   = 0x40000000
	// dsGenericWrite is what GENERIC_WRITE maps to in a stored ACE: READ_CONTROL | SELF | WRITE_PROP.
	dsGenericWrite = 0x00020028
	// dsFullControl is every right of a directory object: GENERIC_ALL after mapping.
	dsFullControl = 0x000F01FF
)

const (
	aceTypeAllowed       = 0x00
	aceTypeDenied        = 0x01
	aceTypeAllowedObject = 0x05
	aceTypeDeniedObject  = 0x06

	aceFlagInheritOnly = 0x08
	aceFlagInherited   = 0x10

	aceObjectTypePresent = 0x1
	aceInheritedPresent  = 0x2
)

type ace struct {
	deny      bool
	flags     byte
	mask      uint32
	objType   adguid.GUID
	hasType   bool
	inhType   adguid.GUID
	hasInh    bool
	trustee   sid.SID
	inherited bool
}

func (a ace) inheritOnly() bool { return a.flags&aceFlagInheritOnly != 0 }

type descriptor struct {
	owner    sid.SID
	hasOwner bool
	aces     []ace
}

func parseSD(sd []byte) (*descriptor, error) {
	if len(sd) < 20 || sd[0] != 1 {
		return nil, errSD
	}
	control := binary.LittleEndian.Uint16(sd[2:4])
	d := &descriptor{}
	if off := int(binary.LittleEndian.Uint32(sd[4:8])); off != 0 {
		if off < 20 || off+8 > len(sd) {
			return nil, errSD
		}
		s, err := sidAt(sd[off:])
		if err != nil {
			return nil, errSD
		}
		d.owner, d.hasOwner = s, true
	}
	off := int(binary.LittleEndian.Uint32(sd[16:20]))
	if control&0x4 == 0 || off == 0 {
		return nil, errNullDACL
	}
	if off < 20 || off+8 > len(sd) {
		return nil, errSD
	}
	acl := sd[off:]
	size := int(binary.LittleEndian.Uint16(acl[2:4]))
	count := int(binary.LittleEndian.Uint16(acl[4:6]))
	if size < 8 || size > len(acl) {
		return nil, errSD
	}
	acl = acl[:size]
	p := 8
	for i := 0; i < count; i++ {
		if p+8 > len(acl) {
			return nil, errSD
		}
		typ, flags := acl[p], acl[p+1]
		sz := int(binary.LittleEndian.Uint16(acl[p+2 : p+4]))
		if sz < 8 || p+sz > len(acl) {
			return nil, errSD
		}
		raw := acl[p : p+sz]
		p += sz
		var a ace
		switch typ {
		case aceTypeAllowed, aceTypeAllowedObject:
		case aceTypeDenied, aceTypeDeniedObject:
			a.deny = true
		default:
			continue // audit, callback and compound ACEs grant nothing we evaluate
		}
		a.flags, a.inherited = flags, flags&aceFlagInherited != 0
		a.mask = binary.LittleEndian.Uint32(raw[4:8])
		q := 8
		if typ == aceTypeAllowedObject || typ == aceTypeDeniedObject {
			if q+4 > len(raw) {
				return nil, errSD
			}
			of := binary.LittleEndian.Uint32(raw[q : q+4])
			q += 4
			if of&aceObjectTypePresent != 0 {
				if q+16 > len(raw) {
					return nil, errSD
				}
				g, err := adguid.FromBytes(raw[q : q+16])
				if err != nil {
					return nil, errSD
				}
				a.objType, a.hasType = g, true
				q += 16
			}
			if of&aceInheritedPresent != 0 {
				if q+16 > len(raw) {
					return nil, errSD
				}
				g, err := adguid.FromBytes(raw[q : q+16])
				if err != nil {
					return nil, errSD
				}
				a.inhType, a.hasInh = g, true
				q += 16
			}
		}
		s, err := sidAt(raw[q:])
		if err != nil {
			return nil, errSD
		}
		a.trustee = s
		d.aces = append(d.aces, a)
	}
	return d, nil
}

func sidAt(b []byte) (sid.SID, error) {
	if len(b) < 8 {
		return sid.SID{}, errSD
	}
	end := 8 + 4*int(b[1])
	if end > len(b) {
		return sid.SID{}, errSD
	}
	return sid.FromBytes(b[:end])
}

// grant is one allow ACE that applies to the trustee set, with the bits no earlier deny removed.
type grant struct {
	ace  ace
	bits uint32
}

// grants returns the allow ACEs whose trustee is in sids. Inherit-only ACEs are skipped unless
// withInheritOnly (a managed OU's delegation lives in inherit-only ACEs that apply to its children).
//
// Deny ACEs for the trustee set remove the bits they cover, per object type, in stored order (the
// canonical order puts denies first). A typed deny does not reduce an untyped allow and an allow
// is never reduced by a later deny: both only widen the answer, which is the safe direction here.
func (d *descriptor) grants(sids map[string]bool, withInheritOnly bool) []grant {
	denied := map[adguid.GUID]uint32{}
	var deniedAll uint32
	var out []grant
	for _, a := range d.aces {
		if !sids[a.trustee.String()] || (a.inheritOnly() && !withInheritOnly) {
			continue
		}
		if a.deny {
			if a.hasType {
				denied[a.objType] |= a.mask
			} else {
				deniedAll |= a.mask
			}
			continue
		}
		bits := a.mask &^ deniedAll
		if a.hasType {
			bits &^= denied[a.objType]
		}
		if bits != 0 {
			out = append(out, grant{ace: a, bits: bits})
		}
	}
	return out
}

// has reports whether the bits cover want.
func (g grant) has(want uint32) bool { return g.bits&want == want }

func (g grant) genericAll() bool {
	return g.bits&maskGenericAll != 0 || g.bits&dsFullControl == dsFullControl
}

func (g grant) genericWrite() bool {
	return !g.ace.hasType && (g.bits&maskGenericWr != 0 || g.bits&dsGenericWrite == dsGenericWrite)
}

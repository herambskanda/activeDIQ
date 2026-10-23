package tier0

import (
	"encoding/binary"
	"errors"

	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/attr/sid"
)

// A minimal, read-only DACL reader for the two places the classifier must look inside a security
// descriptor (C11 domain-root DACL, C12 RBCD). It decodes allow ACEs only and fails closed on any
// malformed byte. The full typed descriptor primitive is T-0149; this reader never writes.

var errSD = errors.New("tier0: malformed security descriptor")

const (
	aceAllowed       = 0x00
	aceAllowedObject = 0x05
	aceInheritOnly   = 0x08 // flag: applies to children, not to the object itself

	maskControlAccess = 0x00000100
	maskGenericAll    = 0x10000000
	maskAllExtended   = maskControlAccess

	aceObjectTypePresent = 0x1
	aceInheritedTypeSet  = 0x2
)

type allowACE struct {
	mask       uint32
	objectType guid.GUID
	hasType    bool
	sid        sid.SID
}

// allowACEs returns the ACEs of the DACL that grant access to the object itself. Deny ACEs are not
// subtracted: ignoring a deny can only widen the answer (fail closed). A NULL DACL (everyone has
// every right) is an error.
func allowACEs(sd []byte) ([]allowACE, error) {
	if len(sd) < 20 || sd[0] != 1 {
		return nil, errSD
	}
	control := binary.LittleEndian.Uint16(sd[2:4])
	off := int(binary.LittleEndian.Uint32(sd[16:20]))
	if control&0x4 == 0 || off == 0 {
		return nil, errors.New("tier0: security descriptor has a NULL DACL")
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
	var out []allowACE
	for i := 0; i < count; i++ {
		if p+8 > len(acl) {
			return nil, errSD
		}
		typ, flags := acl[p], acl[p+1]
		sz := int(binary.LittleEndian.Uint16(acl[p+2 : p+4]))
		if sz < 8 || p+sz > len(acl) {
			return nil, errSD
		}
		ace := acl[p : p+sz]
		p += sz
		if typ != aceAllowed && typ != aceAllowedObject {
			continue
		}
		a := allowACE{mask: binary.LittleEndian.Uint32(ace[4:8])}
		q := 8
		if typ == aceAllowedObject {
			if q+4 > len(ace) {
				return nil, errSD
			}
			of := binary.LittleEndian.Uint32(ace[q : q+4])
			q += 4
			if of&aceObjectTypePresent != 0 {
				if q+16 > len(ace) {
					return nil, errSD
				}
				g, err := guid.FromBytes(ace[q : q+16])
				if err != nil {
					return nil, errSD
				}
				a.objectType, a.hasType = g, true
				q += 16
			}
			if of&aceInheritedTypeSet != 0 {
				q += 16
			}
		}
		if q+2 > len(ace) {
			return nil, errSD
		}
		end := q + 8 + 4*int(ace[q+1])
		if end > len(ace) {
			return nil, errSD
		}
		s, err := sid.FromBytes(ace[q:end])
		if err != nil {
			return nil, errSD
		}
		a.sid = s
		if flags&aceInheritOnly != 0 {
			continue
		}
		out = append(out, a)
	}
	return out, nil
}

// grants reports whether the ACE grants the extended right g on the object itself: GenericAll, or
// CONTROL_ACCESS with no object type (all extended rights) or with exactly g.
func (a allowACE) grants(g guid.GUID) bool {
	if a.mask&maskGenericAll != 0 {
		return true
	}
	if a.mask&maskAllExtended == 0 {
		return false
	}
	return !a.hasType || a.objectType == g
}

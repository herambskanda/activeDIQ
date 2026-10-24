package tier0

import (
	"errors"
	"fmt"

	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/attr/sid"
	"github.com/skenzeriq/activediq/internal/directory/sd"
)

// Descriptors are read through the typed security-descriptor primitive (T-0149, internal/directory/
// sd). The classifier asks one question of a DACL: who holds an allow ACE that applies to the object
// itself, and with which mask. Deny ACEs are not subtracted (ignoring a deny can only widen the
// answer, which is the safe side), and the primitive's Anomalies only gate editing, not this read.
// Anything the classifier cannot show harmless fails closed: a descriptor that does not decode, a NULL
// or absent DACL, and an ACE of a type the primitive does not know (TM-D26 rule 8).

// Access-mask bits (MS-ADTS 5.1.3.2 and MS-DTYP 2.4.3) the root-of-trust rule reads.
const (
	maskWriteProp    = sd.MaskWriteProp
	maskControlAcc   = sd.MaskControlAccess
	maskWriteDACL    = sd.MaskWriteDACL
	maskWriteOwner   = sd.MaskWriteOwner
	maskGenericAll   = 0x10000000
	maskGenericWrite = 0x40000000
)

// aceGrant is one allow ACE that applies to the object itself.
type aceGrant struct {
	trustee    sid.SID
	mask       uint32
	objectType *guid.GUID
}

// grantsOf decodes a descriptor and returns its owner and the allow ACEs that apply to the object.
// Allow callback ACEs (0x09, 0x0B) count as unconditional (TM-D26 rule 4: a condition can only narrow
// a grant); deny callbacks (0x0A, 0x0C) are ignored: never assumed to apply.
func grantsOf(raw []byte) (d sd.SD, grants []aceGrant, err error) {
	d, err = sd.Decode(sd.Raw(raw))
	if err != nil {
		return d, nil, fmt.Errorf("tier0: security descriptor: %w", err)
	}
	if d.DACL.Kind != sd.List {
		return d, nil, errors.New("tier0: security descriptor has a NULL or absent DACL")
	}
	for _, a := range d.DACL.ACEs {
		if a.Kind == sd.Opaque {
			return d, nil, errors.New("tier0: security descriptor holds an ACE of an unknown type")
		}
		if a.InheritOnly() {
			continue
		}
		switch a.Type {
		case sd.TypeAccessAllowed, sd.TypeAccessAllowedObject, sd.TypeAllowedCallback, sd.TypeAllowedCallbackObject:
			grants = append(grants, aceGrant{trustee: a.Trustee, mask: a.Mask, objectType: a.ObjectType})
		}
	}
	return d, grants, nil
}

// grants reports whether the ACE grants the extended right g on the object itself: GenericAll, or
// CONTROL_ACCESS with no object type (all extended rights) or with exactly g.
func (a aceGrant) grants(g guid.GUID) bool {
	if a.mask&maskGenericAll != 0 {
		return true
	}
	if a.mask&maskControlAcc == 0 {
		return false
	}
	return a.objectType == nil || *a.objectType == g
}

// controlsRoot reports whether the ACE gives control of a root of trust (TM-D26 rule 2): WRITE_DAC,
// WRITE_OWNER, GENERIC_ALL or GENERIC_WRITE; WriteProperty on all properties or on gPLink; or all
// extended rights. Any one is enough. Mapped bits are covered: GENERIC_ALL maps to a mask holding
// WRITE_DAC, GENERIC_WRITE to one holding WriteProperty (no object type = all properties).
func (a aceGrant) controlsRoot(gpLink guid.GUID) bool {
	if a.mask&(maskWriteDACL|maskWriteOwner|maskGenericAll|maskGenericWrite) != 0 {
		return true
	}
	if a.mask&maskWriteProp != 0 && (a.objectType == nil || *a.objectType == gpLink) {
		return true
	}
	return a.mask&maskControlAcc != 0 && a.objectType == nil
}

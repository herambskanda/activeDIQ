package sd

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/attr/sid"
)

// Write-half error codes, stable (R6).
const (
	ErrInheritedACEImmutable = "sd.inherited_ace_immutable"
	ErrInheritedFlagOnNew    = "sd.inherited_flag_on_new"
	ErrGenericMask           = "sd.generic_mask"
	ErrMaskUnsupportedBits   = "sd.mask_unsupported_bits"
	ErrMaskEmpty             = "sd.mask_empty"
	ErrUnsupportedFlags      = "sd.unsupported_flags"
	ErrUnknownObjectType     = "sd.unknown_object_type"
	ErrObjectTypeMismatch    = "sd.object_type_mismatch"
	ErrInertACE              = "sd.inert_ace"
	ErrBaseNonCanonical      = "sd.base_non_canonical"
	ErrACLTooLarge           = "sd.acl_too_large"
	ErrACEDigestMismatch     = "sd.ace_digest_mismatch"
	ErrACEIndexOutOfRange    = "sd.ace_index_out_of_range"
	ErrDuplicateRemove       = "sd.duplicate_remove"
	ErrStaleBase             = "sd.stale_base"
	ErrSDPropWillRevert      = "sd.sdprop_will_revert"
	ErrSelfLockout           = "sd.self_lockout"
	ErrProtectFlagChange     = "sd.protect_flag_change"
	ErrNotEditable           = "sd.not_editable"
	ErrTrusteeNotSID         = "sd.trustee_not_sid"
	ErrEmptyDiff             = "sd.empty_diff"
	ErrNoCatalog             = "sd.catalog_required"
	ErrConnectorRequired     = "sd.connector_required"
	ErrInheritanceUnchanged  = "sd.inheritance_unchanged"
	ErrBadInheritanceOp      = "sd.bad_inheritance_op"
	ErrObjectRequired        = "sd.object_required"
)

// Limits of the 16-bit ACL fields (MS-DTYP 2.4.5).
const (
	maxACLSize = 0xFFFF
	// MaxACEsPerACL is the most ACEs an ACL can hold: (65535-8)/16.
	MaxACEsPerACL = (maxACLSize - aclHeaderLen) / minACELen
)

// Access-mask bits an AD DACL stores for a newly written ACE: the object-specific rights, DELETE,
// READ_CONTROL, WRITE_DAC and WRITE_OWNER. Generic bits are never stored, SYNCHRONIZE is ignored in
// AD DACLs, and ACCESS_SYSTEM_SECURITY and MAXIMUM_ALLOWED are not DACL bits.
const storedMaskBits = 0x1FF | MaskDelete | MaskReadControl | MaskWriteDACL | MaskWriteOwner

// Digest is a SHA-256 over bytes the caller saw; it ties an edit to the state it was planned on.
type Digest [sha256.Size]byte

// DigestACE is the digest of one ACE's stored bytes. A removal names an ACE by index and this digest.
func DigestACE(a ACE) Digest { return sha256.Sum256(a.Raw) }

// DigestDACL is the digest of a DACL's state, the PD and DI control bits and every ACE's bytes, in order. It is what
// DACLWrite.VerifyBase compares.
func DigestDACL(s SD) Digest {
	h := sha256.New()
	h.Write([]byte{byte(s.DACL.Kind), s.DACL.Revision})
	var c [2]byte
	binary.LittleEndian.PutUint16(c[:], uint16(s.Control&(ControlDACLProtected|ControlDACLAutoInh)))
	h.Write(c[:])
	var n [4]byte
	binary.LittleEndian.PutUint32(n[:], uint32(len(s.DACL.ACEs)))
	h.Write(n[:])
	for _, a := range s.DACL.ACEs {
		binary.LittleEndian.PutUint32(n[:], uint32(len(a.Raw)))
		h.Write(n[:])
		h.Write(a.Raw)
	}
	var d Digest
	copy(d[:], h.Sum(nil))
	return d
}

// RightsCatalog says what an object-ACE GUID names. It is filled from the schema cache
// (schemaIDGUID of classes and attributes, rightsGuid of control rights); never from a literal table.
type RightsCatalog interface {
	Kind(g guid.GUID) (RightKind, bool)
}

// ParseTrustee is the one place a string becomes an ACE trustee: the S-1-... form only. Names and
// SDDL aliases (DA, BA, WD) are refused; callers resolve names against the directory, display
// them, and hand this package SIDs.
func ParseTrustee(text string) (sid.SID, error) {
	v, err := sid.Parse(text)
	if err != nil {
		return sid.SID{}, fail(ErrTrusteeNotSID)
	}
	return v, nil
}

// NewACE is an ACE the caller wants to add. Allow or deny, a SID trustee, a specific mask,
// optional object scoping and inheritance flags; the wire type and revision are derived, never
// supplied.
type NewACE struct {
	Deny                bool
	Trustee             sid.SID
	Mask                uint32
	ObjectType          *guid.GUID
	InheritedObjectType *guid.GUID
	Flags               uint8 // FlagObjectInherit | FlagContainerInherit | FlagNoPropagateInherit | FlagInheritOnly
}

// ACERef names an existing ACE: its index and the digest of its bytes, both of which must match.
type ACERef struct {
	Index  int
	Digest Digest
}

// ACEDiff is an edit: ACEs to add and ACEs to remove. It is never a whole DACL.
type ACEDiff struct {
	Add    []NewACE
	Remove []ACERef
	// WantControl is the control the caller expects after the edit, when it has an opinion. PD and
	// DI are not editable by diff: any difference from the base is refused (use PlanInheritance).
	WantControl *Control
}

// ObjectCtx is what the caller knows about the object being edited, from the directory.
type ObjectCtx struct {
	// ObjectGUID keys the object (DN and sAMAccountName are mutable).
	ObjectGUID guid.GUID
	// ProtectedBySDProp comes from the computed protected set, never from adminCount.
	ProtectedBySDProp bool
	// Connector is the token of the identity that will perform the write. The lockout check needs it.
	Connector Principal
}

// PlanOpts are the explicit knobs of a plan.
type PlanOpts struct {
	// Normalize permits fixing an outcome-changing order violation (rules 1 and 2) in the base,
	// and reports the effective-rights change the reorder causes. It never touches rules 3 and 4.
	Normalize bool
	// ExpectBase, when set, is the DACL digest the caller showed the admin; a different base is stale.
	ExpectBase *Digest
}

// Move is one reordered ACE of a normalized base.
type Move struct{ From, To int }

// RightsChange is the effective-rights consequence of a reorder for one trustee on one right.
type RightsChange struct {
	Trustee       sid.SID
	Mask          uint32
	Object        *guid.GUID
	Before, After Decision
}

// Plan is what an edit will do, for the approval screen and the audit record.
type Plan struct {
	// Inserted are the indexes in the new DACL of the added ACEs, in the order of the diff.
	Inserted []int
	// Removed are the indexes in the base DACL of the removed ACEs.
	Removed []int
	// Moves are set only by Normalize.
	Moves []Move
	// Changes are the effective-rights differences a Normalize reorder causes (evaluated per
	// trustee in isolation). ChangesIncomplete is set when the bound was reached or a GUID has no catalog kind.
	Changes           []RightsChange
	ChangesIncomplete bool
	// NonCanonicalResult lists outcome-changing order violations the new DACL has. Only
	// PlanInheritance can produce it (converting inherited ACEs to explicit ones keeps their order,
	// so effective rights do not change).
	NonCanonicalResult []OrderViolation
}

// DACLWrite is the only thing the connector may send for nTSecurityDescriptor. Every field is
// unexported and only PlanDACL and PlanInheritance fill it: the zero value is invalid and
// Valid() is false.
type DACLWrite struct {
	ok         bool
	object     guid.GUID
	baseDigest Digest
	value      []byte
}

// Valid reports whether the write came from a planner. The connector refuses an invalid one.
func (w DACLWrite) Valid() bool { return w.ok }

// ObjectGUID is the object the plan was made for.
func (w DACLWrite) ObjectGUID() guid.GUID { return w.object }

// BaseDigest is the digest of the DACL the plan was made on.
func (w DACLWrite) BaseDigest() Digest { return w.baseDigest }

// Control is the SD_FLAGS control to send: DACL only, critical.
func (w DACLWrite) Control() LDAPControl {
	c, _ := ReadControl(PartDACL) // PartDACL alone never fails
	return c
}

// Value is the attribute value: a self-relative SD whose owner, group and SACL offsets are zero, SP
// is clear and DP is set. An invalid (zero) write has no value.
func (w DACLWrite) Value() Raw {
	if !w.ok {
		return nil
	}
	return Raw(append([]byte(nil), w.value...))
}

// VerifyBase is called immediately before the write with a fresh read of the object: if its DACL
// is no longer the one the plan was made on, the write must not go out (sd.stale_base). It narrows
// the lost-update window, it does not close it (no compare-and-swap exists).
func (w DACLWrite) VerifyBase(current SD) error {
	if !w.ok {
		return fail(ErrNotEditable)
	}
	t, err := current.trusted()
	if err != nil {
		return err
	}
	if DigestDACL(t) != w.baseDigest {
		return fail(ErrStaleBase)
	}
	return nil
}

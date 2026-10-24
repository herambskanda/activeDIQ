package sd

import (
	"encoding/binary"
	"sort"

	"github.com/skenzeriq/activediq/internal/directory/attr/codec"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/attr/sid"
)

// Bounds (provisional until load tests; safe-primitives-security-descriptor §2).
const (
	MaxSDBytes   = 256 << 10
	maxSubAuth   = 15
	sdHeaderLen  = 20
	aclHeaderLen = 8
	minACELen    = 16
)

// Control bits (MS-DTYP 2.4.6).
const (
	ControlOwnerDefaulted = 0x0001
	ControlGroupDefaulted = 0x0002
	ControlDACLPresent    = 0x0004
	ControlSACLPresent    = 0x0010
	ControlDACLAutoInh    = 0x0400
	ControlDACLProtected  = 0x1000
	ControlSACLProtected  = 0x2000
	ControlRMControlValid = 0x4000
	ControlSelfRelative   = 0x8000
)

// Control is the 16-bit SECURITY_DESCRIPTOR_CONTROL word.
type Control uint16

// Protected reports DACL protected (PD): inheritance from the parent is blocked.
func (c Control) Protected() bool { return c&ControlDACLProtected != 0 }

// AutoInherited reports DACL auto-inherited (DI).
func (c Control) AutoInherited() bool { return c&ControlDACLAutoInh != 0 }

// Error codes, stable (R6). They are the codec.Error codes, so codec.Code(err) reads them.
const (
	ErrTruncatedHeader     = "sd.truncated_header"
	ErrTruncated           = "sd.truncated"
	ErrTooLarge            = "sd.too_large"
	ErrBadRevision         = "sd.bad_revision"
	ErrNotSelfRelative     = "sd.not_self_relative"
	ErrOffsetOutOfRange    = "sd.offset_out_of_range"
	ErrComponentsOverlap   = "sd.components_overlap"
	ErrDACLOffsetNoFlag    = "sd.dacl_offset_without_flag"
	ErrSACLOffsetNoFlag    = "sd.sacl_offset_without_flag"
	ErrACLBadRevision      = "acl.bad_revision"
	ErrACLRevisionType     = "acl.revision_type_mismatch"
	ErrACLSizeOutOfRange   = "acl.size_out_of_range"
	ErrACLCountMismatch    = "acl.count_mismatch"
	ErrACLTrailingBytes    = "acl.trailing_bytes"
	ErrACESizeUnaligned    = "ace.size_unaligned"
	ErrACESizeTooSmall     = "ace.size_too_small"
	ErrACESizeOverrun      = "ace.size_overrun"
	ErrACEObjectOverrun    = "ace.object_overrun"
	ErrACEObjectFlagsUnk   = "ace.object_flags_unknown"
	ErrSIDBadRevision      = "sid.bad_revision"
	ErrSIDBadSubAuthCount  = "sid.bad_subauth_count"
	ErrSIDOverrun          = "sid.overrun"
	ErrNotReturned         = "sd.not_returned"
	ErrFlagsEmpty          = "sd.flags_empty"
	ErrFlagsUnknownBits    = "sd.flags_unknown_bits"
	ErrSACLNeedsCapability = "sd.sacl_requires_capability"
	AnomalyZeroSlack       = "acl.zero_slack"
	AnomalySbzNonZero      = "acl.sbz_nonzero"
	AnomalyOpaque          = "ace.opaque"
	AnomalyMisplaced       = "ace.misplaced_type"
	AnomalyOrderOutcome    = "acl.order_outcome"
	AnomalyCallbackPresent = "ace.callback_present"
	AnomalyUnknownFlags    = "ace.unknown_flags"
	AnomalyRMBitsSet       = "sd.rm_bits_set"
	AnomalyNullDACL        = "sd.null_dacl"
	NoteOrderCosmetic      = "acl.order_cosmetic"
)

// auditOnlyFlags are SUCCESSFUL_ACCESS and FAILED_ACCESS: defined for audit ACEs only.
const auditOnlyFlags = FlagSuccessfulAccess | FlagFailedAccess

// Raw is the value of nTSecurityDescriptor as the connector returned it. It is opaque: the only
// function that reads it is Decode.
type Raw []byte

// ACLKind is the three states of a DACL or SACL, which mean opposite things.
type ACLKind uint8

const (
	// Absent: the component is not in this SD.
	Absent ACLKind = iota
	// Null: present flag set with offset 0. Everyone has full access. Never confused with empty.
	Null
	// List: an ACL, possibly with zero ACEs (empty DACL: nobody has access).
	List
)

// ACL is a DACL or SACL.
type ACL struct {
	Kind     ACLKind
	Revision uint8
	ACEs     []ACE
}

// Anomaly is a non-fatal oddity. An SD with anomalies is viewable and not editable.
type Anomaly struct {
	Code  string
	Index int // ACE index, -1 when the anomaly concerns the SD or ACL as a whole
	Rule  int // ordering rule (1 or 2) for acl.order_outcome, else 0
}

// Note is informational; it never gates a read, Grants or an edit.
type Note struct {
	Code  string
	Index int
	Rule  int
}

// SD is a decoded security descriptor. Treat it as immutable.
type SD struct {
	Owner, Group       sid.SID
	HasOwner, HasGroup bool
	DACL, SACL         ACL
	Control            Control
	RMBits             uint8
	Anomalies          []Anomaly
	Notes              []Note
}

// Editable reports whether the SD has no anomalies.
func (s SD) Editable() bool { return len(s.Anomalies) == 0 }

func fail(code string) error { return codec.New(code) }

type extent struct{ off, end uint64 }

// Decode reads a self-relative security descriptor. It is strict: anything that makes the
// structure ambiguous is an error with a stable code; legal oddities come back as Anomalies.
func Decode(r Raw) (SD, error) {
	b := []byte(r)
	var s SD
	if len(b) > MaxSDBytes {
		return s, fail(ErrTooLarge)
	}
	if len(b) < sdHeaderLen {
		return s, fail(ErrTruncatedHeader)
	}
	if b[0] != 1 {
		return s, fail(ErrBadRevision)
	}
	ctl := Control(binary.LittleEndian.Uint16(b[2:4]))
	if ctl&ControlSelfRelative == 0 {
		return s, fail(ErrNotSelfRelative)
	}
	s.Control = ctl
	s.RMBits = b[1]
	offOwner := binary.LittleEndian.Uint32(b[4:8])
	offGroup := binary.LittleEndian.Uint32(b[8:12])
	offSACL := binary.LittleEndian.Uint32(b[12:16])
	offDACL := binary.LittleEndian.Uint32(b[16:20])

	if offDACL != 0 && ctl&ControlDACLPresent == 0 {
		return s, fail(ErrDACLOffsetNoFlag)
	}
	if offSACL != 0 && ctl&ControlSACLPresent == 0 {
		return s, fail(ErrSACLOffsetNoFlag)
	}
	// A SACL flagged present with no offset has no defined meaning (unlike the NULL DACL): refuse.
	if offSACL == 0 && ctl&ControlSACLPresent != 0 {
		return s, fail(ErrOffsetOutOfRange)
	}

	// Phase A: where does each component claim to live, and does it fit in the buffer?
	var exts []extent
	order := []struct {
		off uint32
		acl bool
	}{{offDACL, true}, {offSACL, true}, {offOwner, false}, {offGroup, false}}
	n := uint64(len(b))
	for _, c := range order {
		if c.off == 0 {
			continue
		}
		off := uint64(c.off)
		if off < sdHeaderLen || off+8 > n { // both ACL and SID headers are 8 bytes
			return s, fail(ErrOffsetOutOfRange)
		}
		var end uint64
		if c.acl {
			size := uint64(binary.LittleEndian.Uint16(b[off+2 : off+4]))
			if size < aclHeaderLen {
				return s, fail(ErrACLSizeOutOfRange)
			}
			end = off + size
			if end > n {
				return s, fail(ErrTruncated)
			}
		} else {
			end = off + 8 + 4*uint64(b[off+1])
			if end > n {
				return s, fail(ErrSIDOverrun)
			}
		}
		exts = append(exts, extent{off, end})
	}
	// Phase B: components must not overlap one another (our strictness, §4).
	sort.Slice(exts, func(i, j int) bool { return exts[i].off < exts[j].off })
	for i := 1; i < len(exts); i++ {
		if exts[i].off < exts[i-1].end {
			return s, fail(ErrComponentsOverlap)
		}
	}

	// Phase C: decode the contents.
	var err error
	if s.DACL, err = decodeACL(b, offDACL, ctl&ControlDACLPresent != 0, true, &s); err != nil {
		return SD{}, err
	}
	if s.SACL, err = decodeACL(b, offSACL, ctl&ControlSACLPresent != 0, false, &s); err != nil {
		return SD{}, err
	}
	if offOwner != 0 {
		if s.Owner, _, err = parseSID(b[offOwner:]); err != nil {
			return SD{}, err
		}
		s.HasOwner = true
	}
	if offGroup != 0 {
		if s.Group, _, err = parseSID(b[offGroup:]); err != nil {
			return SD{}, err
		}
		s.HasGroup = true
	}
	if ctl&ControlRMControlValid != 0 {
		s.Anomalies = append(s.Anomalies, Anomaly{AnomalyRMBitsSet, -1, 0})
	}
	order1, notes := orderReport(s.DACL)
	s.Anomalies = append(s.Anomalies, order1...)
	s.Notes = append(s.Notes, notes...)
	return s, nil
}

func decodeACL(b []byte, off uint32, present, isDACL bool, s *SD) (ACL, error) {
	if !present {
		return ACL{Kind: Absent}, nil
	}
	if off == 0 { // DACL only: the SACL case was refused above
		s.Anomalies = append(s.Anomalies, Anomaly{AnomalyNullDACL, -1, 0})
		return ACL{Kind: Null}, nil
	}
	rev := b[off]
	if rev != 2 && rev != 4 {
		return ACL{}, fail(ErrACLBadRevision)
	}
	if b[off+1] != 0 || binary.LittleEndian.Uint16(b[off+6:off+8]) != 0 {
		s.Anomalies = append(s.Anomalies, Anomaly{AnomalySbzNonZero, -1, 0})
	}
	size := uint64(binary.LittleEndian.Uint16(b[off+2 : off+4]))
	count := uint64(binary.LittleEndian.Uint16(b[off+4 : off+6]))
	// The smallest ACE is 16 bytes, so a count the size cannot hold is refused before any allocation.
	if count > (size-aclHeaderLen)/minACELen {
		return ACL{}, fail(ErrACLCountMismatch)
	}
	acl := ACL{Kind: List, Revision: rev, ACEs: make([]ACE, 0, count)}
	body := b[uint64(off)+aclHeaderLen : uint64(off)+size]
	pos := uint64(0)
	for i := uint64(0); i < count; i++ {
		if uint64(len(body))-pos < 4 {
			return ACL{}, fail(ErrACLCountMismatch)
		}
		ace, n, an, err := decodeACE(body[pos:], rev, isDACL, int(i))
		if err != nil {
			return ACL{}, err
		}
		s.Anomalies = append(s.Anomalies, an...)
		acl.ACEs = append(acl.ACEs, ace)
		pos += n
	}
	for _, c := range body[pos:] {
		if c != 0 {
			return ACL{}, fail(ErrACLTrailingBytes)
		}
	}
	if pos < uint64(len(body)) {
		s.Anomalies = append(s.Anomalies, Anomaly{AnomalyZeroSlack, -1, 0})
	}
	return acl, nil
}

func decodeACE(b []byte, rev uint8, isDACL bool, idx int) (ACE, uint64, []Anomaly, error) {
	var an []Anomaly
	t, fl := b[0], b[1]
	size := uint64(binary.LittleEndian.Uint16(b[2:4]))
	if size%4 != 0 {
		return ACE{}, 0, nil, fail(ErrACESizeUnaligned)
	}
	if size < minACELen {
		return ACE{}, 0, nil, fail(ErrACESizeTooSmall)
	}
	if size > uint64(len(b)) {
		return ACE{}, 0, nil, fail(ErrACESizeOverrun)
	}
	ace := ACE{Type: t, Flags: fl, Raw: append([]byte(nil), b[:size]...)}
	if rev == 2 && (objectForm(t) || callbackType(t)) {
		return ACE{}, 0, nil, fail(ErrACLRevisionType)
	}
	switch {
	case t == TypeAccessAllowed || t == TypeAccessDenied || t == TypeSystemAudit ||
		t == TypeMandatoryLabel || t == TypeResourceAttribute || t == TypeScopedPolicyID:
		ace.Kind = Basic
	case objectForm(t) && !callbackType(t):
		ace.Kind = Object
	case callbackType(t):
		ace.Kind = Callback
	default:
		ace.Kind = Opaque
	}
	if ace.Kind == Opaque {
		an = append(an, Anomaly{AnomalyOpaque, idx, 0})
	} else {
		body := b[4:size]
		ace.Mask = binary.LittleEndian.Uint32(body[0:4])
		body = body[4:]
		if objectForm(t) {
			if len(body) < 4 {
				return ACE{}, 0, nil, fail(ErrACEObjectOverrun)
			}
			of := binary.LittleEndian.Uint32(body[0:4])
			if of&^3 != 0 {
				return ACE{}, 0, nil, fail(ErrACEObjectFlagsUnk)
			}
			body = body[4:]
			for _, bit := range []uint32{1, 2} {
				if of&bit == 0 {
					continue
				}
				if len(body) < guid.Size {
					return ACE{}, 0, nil, fail(ErrACEObjectOverrun)
				}
				g, err := guid.FromBytes(body[:guid.Size])
				if err != nil {
					return ACE{}, 0, nil, err
				}
				if bit == 1 {
					ace.ObjectType = &g
				} else {
					ace.InheritedObjectType = &g
				}
				body = body[guid.Size:]
			}
		}
		tr, _, err := parseSID(body)
		if err != nil {
			return ACE{}, 0, nil, err
		}
		ace.Trustee = tr
		if ace.Kind == Callback {
			an = append(an, Anomaly{AnomalyCallbackPresent, idx, 0})
		}
	}
	if (isDACL && saclType(t)) || (!isDACL && daclType(t)) {
		an = append(an, Anomaly{AnomalyMisplaced, idx, 0})
	}
	if fl&auditOnlyFlags != 0 && !auditType(t) {
		an = append(an, Anomaly{AnomalyUnknownFlags, idx, 0})
	}
	return ace, size, an, nil
}

// parseSID reads one SID from the front of b and returns it with its length. A SID with no
// sub-authority is refused as bad_subauth_count: the SID type cannot represent it.
func parseSID(b []byte) (sid.SID, int, error) {
	if len(b) < 8 {
		return sid.SID{}, 0, fail(ErrSIDOverrun)
	}
	if b[0] != 1 {
		return sid.SID{}, 0, fail(ErrSIDBadRevision)
	}
	n := int(b[1])
	if n == 0 || n > maxSubAuth {
		return sid.SID{}, 0, fail(ErrSIDBadSubAuthCount)
	}
	l := 8 + 4*n
	if len(b) < l {
		return sid.SID{}, 0, fail(ErrSIDOverrun)
	}
	v, err := sid.FromBytes(b[:l])
	if err != nil {
		return sid.SID{}, 0, err
	}
	return v, l, nil
}

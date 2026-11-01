package sd

import (
	"encoding/binary"
	"sort"

	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/attr/sid"
)

// maxChangeEvals bounds the work of the Normalize rights-change report.
const maxChangeEvals = 2048

const newACEFlags = FlagObjectInherit | FlagContainerInherit | FlagNoPropagateInherit | FlagInheritOnly

// InheritanceOp is a change of the DACL-protected (PD) flag. PlanInheritance is the only way to
// change it, and each option is a separate, explicit operation class for approvals.
type InheritanceOp uint8

const (
	// BlockKeepInherited sets PD and turns the inherited ACEs into explicit copies.
	BlockKeepInherited InheritanceOp = iota + 1
	// BlockRemoveInherited sets PD and drops the inherited ACEs.
	BlockRemoveInherited
	// RestoreInheritance clears PD. The ACEs stay as they are; the DC adds the inherited ones
	// [UNVERIFIED on Windows: whether it does so for a DACL write without further action].
	RestoreInheritance
)

// editableBase checks the base SD may be planned on. Order violations that change outcomes are
// tolerated only when allowOrder is set (Normalize); every other anomaly refuses.
func editableBase(base SD, allowOrder bool) error {
	if base.DACL.Kind != List {
		return fail(ErrNotEditable)
	}
	order := false
	for _, a := range base.Anomalies {
		if a.Code == AnomalyOrderOutcome {
			order = true
			continue
		}
		return fail(ErrNotEditable)
	}
	if order && !allowOrder {
		return fail(ErrBaseNonCanonical)
	}
	return nil
}

// PlanDACL turns an ACE diff against a base SD into a DACLWrite. Existing ACEs keep their
// positions; new ACEs go to their canonical position. Nothing is repaired silently: a base that is
// not editable, a diff that would write an inert or unstorable ACE, a stale reference or a result
// that would lock the connector out is an error with a stable code.
func PlanDACL(in SD, d ACEDiff, cat RightsCatalog, o ObjectCtx, opt PlanOpts) (DACLWrite, Plan, error) {
	var plan Plan
	base, err := in.trusted()
	if err != nil {
		return DACLWrite{}, plan, err
	}
	if o.ObjectGUID == (guid.GUID{}) {
		return DACLWrite{}, plan, fail(ErrObjectRequired)
	}
	if o.ProtectedBySDProp {
		return DACLWrite{}, plan, fail(ErrSDPropWillRevert)
	}
	if err = editableBase(base, opt.Normalize); err != nil {
		return DACLWrite{}, plan, err
	}
	if d.WantControl != nil && (*d.WantControl^base.Control)&(ControlDACLProtected|ControlDACLAutoInh) != 0 {
		return DACLWrite{}, plan, fail(ErrProtectFlagChange)
	}
	baseDigest := DigestDACL(base)
	if opt.ExpectBase != nil && *opt.ExpectBase != baseDigest {
		return DACLWrite{}, plan, fail(ErrStaleBase)
	}
	if len(d.Add) == 0 && len(d.Remove) == 0 {
		return DACLWrite{}, plan, fail(ErrEmptyDiff)
	}
	if len(o.Connector.sids) == 0 {
		return DACLWrite{}, plan, fail(ErrConnectorRequired)
	}

	// Removals are resolved against the base exactly as the admin saw it.
	removed := make(map[int]bool, len(d.Remove))
	for _, r := range d.Remove {
		if r.Index < 0 || r.Index >= len(base.DACL.ACEs) {
			return DACLWrite{}, plan, fail(ErrACEIndexOutOfRange)
		}
		if removed[r.Index] {
			return DACLWrite{}, plan, fail(ErrDuplicateRemove)
		}
		a := base.DACL.ACEs[r.Index]
		if DigestACE(a) != r.Digest {
			return DACLWrite{}, plan, fail(ErrACEDigestMismatch)
		}
		if a.Inherited() {
			return DACLWrite{}, plan, fail(ErrInheritedACEImmutable)
		}
		removed[r.Index] = true
	}
	adds := make([]ACE, 0, len(d.Add))
	for _, n := range d.Add {
		a, err := encodeNew(n, cat)
		if err != nil {
			return DACLWrite{}, plan, err
		}
		adds = append(adds, a)
	}
	for i := range base.DACL.ACEs {
		if removed[i] {
			plan.Removed = append(plan.Removed, i)
		}
	}
	sort.Ints(plan.Removed)

	kept := make([]ACE, 0, len(base.DACL.ACEs))
	for i, a := range base.DACL.ACEs {
		if !removed[i] {
			kept = append(kept, a)
		}
	}
	if opt.Normalize {
		var moves []Move
		kept, moves = normalizeOrder(kept)
		plan.Moves = moves
		if len(moves) > 0 {
			orig := withDACL(base, base.DACL.Revision, filterACEs(base.DACL.ACEs, removed))
			norm := withDACL(base, base.DACL.Revision, kept)
			plan.Changes, plan.ChangesIncomplete = rightsChanges(orig, norm, moves, cat)
		}
	}

	final := append([]ACE(nil), kept...)
	origin := make([]int, len(final)) // index into adds, -1 for an existing ACE
	for i := range origin {
		origin[i] = -1
	}
	for i, a := range adds {
		pos := canonicalPosition(final, a)
		final = append(final, ACE{})
		copy(final[pos+1:], final[pos:])
		final[pos] = a
		origin = append(origin, 0)
		copy(origin[pos+1:], origin[pos:])
		origin[pos] = i
	}
	plan.Inserted = make([]int, len(adds))
	for i, oi := range origin {
		if oi >= 0 {
			plan.Inserted[oi] = i
		}
	}
	rev := base.DACL.Revision
	for _, a := range final {
		if a.Kind == Object {
			rev = 4
		}
	}
	return finish(base, o, baseDigest, rev, final, base.Control&(ControlDACLProtected|ControlDACLAutoInh), plan)
}

// PlanInheritance changes the DACL-protected flag. It is the only function that does.
//
// BlockKeepInherited turns inherited ACEs into explicit ones in their old order. That list can be
// non-canonical (an inherited deny now sits after an explicit allow), and a Windows DC re-sorts a DACL
// on write (T-0606, T-0727), so the stored order, and with it the effective rights, would differ from the
// preview. Such a plan is refused with sd.plan_non_canonical (Plan.NonCanonicalResult names the
// violations) unless the caller passes PlanOpts{Normalize: true}: the plan then holds the canonical
// order the DC will store (explicit before inherited, denies before allows) and reports the
// effective-rights change of the reorder in Plan.Moves/Changes, for the admin to confirm. Only
// Normalize is read from opt.
func PlanInheritance(in SD, op InheritanceOp, o ObjectCtx, opt ...PlanOpts) (DACLWrite, Plan, error) {
	var plan Plan
	normalize := len(opt) > 0 && opt[0].Normalize
	base, err := in.trusted()
	if err != nil {
		return DACLWrite{}, plan, err
	}
	if o.ObjectGUID == (guid.GUID{}) {
		return DACLWrite{}, plan, fail(ErrObjectRequired)
	}
	if o.ProtectedBySDProp {
		return DACLWrite{}, plan, fail(ErrSDPropWillRevert)
	}
	if err = editableBase(base, false); err != nil {
		return DACLWrite{}, plan, err
	}
	if len(o.Connector.sids) == 0 {
		return DACLWrite{}, plan, fail(ErrConnectorRequired)
	}
	ctl := base.Control & (ControlDACLProtected | ControlDACLAutoInh)
	var out []ACE
	switch op {
	case BlockKeepInherited, BlockRemoveInherited:
		if base.Control.Protected() {
			return DACLWrite{}, plan, fail(ErrInheritanceUnchanged)
		}
		ctl |= ControlDACLProtected
		for i, a := range base.DACL.ACEs {
			switch {
			case !a.Inherited():
				out = append(out, a)
			case op == BlockKeepInherited:
				c := a
				c.Raw = append([]byte(nil), a.Raw...)
				c.Raw[1] &^= FlagInherited
				c.Flags &^= FlagInherited
				out = append(out, c)
			default:
				plan.Removed = append(plan.Removed, i)
			}
		}
	case RestoreInheritance:
		if !base.Control.Protected() {
			return DACLWrite{}, plan, fail(ErrInheritanceUnchanged)
		}
		ctl &^= ControlDACLProtected
		out = append(out, base.DACL.ACEs...)
	default:
		return DACLWrite{}, plan, fail(ErrBadInheritanceOp)
	}
	if normalize && len(ACL{Kind: List, ACEs: out}.Order().Outcome) > 0 {
		sorted, moves := normalizeOrder(out)
		plan.Moves = moves
		plan.Changes, plan.ChangesIncomplete = rightsChanges(
			withDACL(base, base.DACL.Revision, out), withDACL(base, base.DACL.Revision, sorted), moves, nil)
		out = sorted
	}
	return finish(base, o, DigestDACL(base), base.DACL.Revision, out, ctl, plan)
}

// finish runs the checks that need the final list, then encodes it.
func finish(base SD, o ObjectCtx, baseDigest Digest, rev uint8, aces []ACE, ctl Control, plan Plan) (DACLWrite, Plan, error) {
	size := aclHeaderLen
	for _, a := range aces {
		size += len(a.Raw)
	}
	if size > maxACLSize || len(aces) > MaxACEsPerACL {
		return DACLWrite{}, plan, fail(ErrACLTooLarge)
	}
	plan.NonCanonicalResult = ACL{Kind: List, ACEs: aces}.Order().Outcome
	if len(plan.NonCanonicalResult) > 0 {
		// A DC stores a DACL in canonical order (T-0727): an outcome-changing violation here means the
		// preview would not be what is stored. Refuse before any write.
		return DACLWrite{}, plan, fail(ErrPlanNonCanonical)
	}
	// The connector must still be able to write the DACL afterwards. Owners keep an implicit right
	// (Grants answers Unknown for them), so only a definite No refuses.
	right := Right{Mask: MaskWriteDACL}
	before := Grants(o.Connector, right, base)
	after := Grants(o.Connector, right, withDACL(base, rev, aces))
	if after.Decision == No && before.Decision != No {
		return DACLWrite{}, plan, fail(ErrSelfLockout)
	}
	// A connector that is (or reaches) the owner may hold WRITE_DAC through the owner's implicit rights.
	// Those vanish as soon as the DACL names OWNER RIGHTS (MS-DTYP 2.5.3.2), and we stay conservative
	// for an ACE naming the owner SID. Do not key on the Grants reason text: it differs by base shape
	// (implicit_owner_rights, owner_ace_present). Require an explicit WRITE_DAC route instead.
	if base.HasOwner && o.Connector.holds(base.Owner, nil) {
		named := false
		for _, a := range aces {
			if a.Kind != Opaque && (a.Trustee == sidOwnerRights || a.Trustee == base.Owner) {
				named = true
			}
		}
		if named {
			// Evaluate as if the connector were not the owner: only an explicit route counts.
			ns := withDACL(base, rev, aces)
			ns.HasOwner = false
			if Grants(o.Connector, right, ns).Decision != Yes {
				return DACLWrite{}, plan, fail(ErrSelfLockout)
			}
		}
	}
	return DACLWrite{ok: true, object: o.ObjectGUID, baseDigest: baseDigest, value: encodeDACLSD(ctl, rev, aces, size)}, plan, nil
}

// withDACL returns base with its DACL replaced, for evaluation only.
func withDACL(base SD, rev uint8, aces []ACE) SD {
	s := base
	s.DACL = ACL{Kind: List, Revision: rev, ACEs: aces}
	s.Anomalies = nil
	return s
}

func filterACEs(aces []ACE, drop map[int]bool) []ACE {
	out := make([]ACE, 0, len(aces))
	for i, a := range aces {
		if !drop[i] {
			out = append(out, a)
		}
	}
	return out
}

// encodeDACLSD builds the self-relative SD of a DACL-only write: owner, group and SACL offsets 0,
// SP clear, DP set, the DACL right after the 20-byte header.
func encodeDACLSD(ctl Control, rev uint8, aces []ACE, aclSize int) []byte {
	out := make([]byte, sdHeaderLen+aclSize)
	out[0] = 1
	binary.LittleEndian.PutUint16(out[2:], uint16(ControlSelfRelative|ControlDACLPresent|ctl&(ControlDACLProtected|ControlDACLAutoInh)))
	binary.LittleEndian.PutUint32(out[16:], sdHeaderLen)
	acl := out[sdHeaderLen:]
	acl[0] = rev
	binary.LittleEndian.PutUint16(acl[2:], uint16(aclSize))
	binary.LittleEndian.PutUint16(acl[4:], uint16(len(aces)))
	pos := aclHeaderLen
	for _, a := range aces {
		pos += copy(acl[pos:], a.Raw)
	}
	return out
}

// encodeNew validates a NewACE and builds its stored form.
func encodeNew(n NewACE, cat RightsCatalog) (ACE, error) {
	if n.Trustee == (sid.SID{}) {
		return ACE{}, fail(ErrTrusteeNotSID)
	}
	if n.Flags&FlagInherited != 0 {
		return ACE{}, fail(ErrInheritedFlagOnNew)
	}
	if n.Flags&^newACEFlags != 0 {
		return ACE{}, fail(ErrUnsupportedFlags)
	}
	if n.Mask&maskGeneric != 0 {
		return ACE{}, fail(ErrGenericMask)
	}
	if n.Mask&^storedMaskBits != 0 {
		return ACE{}, fail(ErrMaskUnsupportedBits)
	}
	if n.Mask == 0 {
		return ACE{}, fail(ErrMaskEmpty)
	}
	if n.Flags&(FlagInheritOnly|FlagNoPropagateInherit) != 0 && n.Flags&(FlagObjectInherit|FlagContainerInherit) == 0 {
		return ACE{}, fail(ErrInertACE)
	}
	if n.ObjectType != nil || n.InheritedObjectType != nil {
		if cat == nil {
			return ACE{}, fail(ErrNoCatalog)
		}
	}
	if n.ObjectType != nil {
		k, ok := cat.Kind(*n.ObjectType)
		if !ok {
			return ACE{}, fail(ErrUnknownObjectType)
		}
		if !maskFitsKind(n.Mask, k) {
			return ACE{}, fail(ErrObjectTypeMismatch)
		}
	}
	if n.InheritedObjectType != nil {
		k, ok := cat.Kind(*n.InheritedObjectType)
		if !ok {
			return ACE{}, fail(ErrUnknownObjectType)
		}
		if k != Class {
			return ACE{}, fail(ErrObjectTypeMismatch)
		}
	}
	a := ACE{Kind: Basic, Type: TypeAccessAllowed, Flags: n.Flags, Mask: n.Mask, Trustee: n.Trustee}
	if n.Deny {
		a.Type = TypeAccessDenied
	}
	body := make([]byte, 4, 64)
	binary.LittleEndian.PutUint32(body, n.Mask)
	if n.ObjectType != nil || n.InheritedObjectType != nil {
		a.Kind = Object
		a.Type += TypeAccessAllowedObject
		var of uint32
		var gs []byte
		if n.ObjectType != nil {
			of |= 1
			g := *n.ObjectType
			a.ObjectType = &g
			gs = append(gs, g.Bytes()...)
		}
		if n.InheritedObjectType != nil {
			of |= 2
			g := *n.InheritedObjectType
			a.InheritedObjectType = &g
			gs = append(gs, g.Bytes()...)
		}
		body = binary.LittleEndian.AppendUint32(body, of)
		body = append(body, gs...)
	}
	body = append(body, n.Trustee.Bytes()...)
	raw := []byte{a.Type, a.Flags, 0, 0}
	binary.LittleEndian.PutUint16(raw[2:], uint16(4+len(body)))
	a.Raw = append(raw, body...)
	return a, nil
}

// maskFitsKind says the mask carries only the rights an ACE scoped to that kind of GUID can grant;
// anything else is an ACE the DC stores but never applies as intended.
func maskFitsKind(mask uint32, k RightKind) bool {
	switch k {
	case Class:
		return mask&^(MaskCreateChild|MaskDeleteChild) == 0
	case Attribute, PropertySet:
		return mask&^(MaskReadProp|MaskWriteProp) == 0
	case ControlAccess:
		return mask == MaskControlAccess
	case ValidatedWrite:
		return mask == MaskSelf
	}
	return false
}

// canonicalPosition is where a new ACE goes in a list whose explicit run is canonical: explicit
// before inherited; denies before allows; a whole-object ACE before the first object-scoped ACE of
// the same decision type if there is one, else at the end of its run. Existing ACEs never move.
func canonicalPosition(list []ACE, n ACE) int {
	runEnd := len(list) // end of the explicit run
	for i, a := range list {
		if a.Inherited() {
			runEnd = i
			break
		}
	}
	deny := n.deny()
	end := runEnd // end of this decision type's block
	if deny {
		end = 0
		for i := 0; i < runEnd; i++ {
			if list[i].deny() {
				end = i + 1
			}
		}
	}
	if n.ObjectType == nil {
		for i := 0; i < end; i++ {
			a := list[i]
			if a.deny() == deny && a.ObjectType != nil {
				return i
			}
		}
	}
	return end
}

// normalizeOrder stable-sorts a list by rules 1 and 2 only (explicit before inherited; denies before
// allows among explicit) and returns the moves. Rules 3 and 4 are left alone.
func normalizeOrder(in []ACE) ([]ACE, []Move) {
	idx := make([]int, len(in))
	for i := range idx {
		idx[i] = i
	}
	rank := func(a ACE) int {
		switch {
		case a.Inherited():
			return 2
		case a.deny():
			return 0
		}
		return 1
	}
	sort.SliceStable(idx, func(i, j int) bool { return rank(in[idx[i]]) < rank(in[idx[j]]) })
	out := make([]ACE, len(in))
	var moves []Move
	for to, from := range idx {
		out[to] = in[from]
		if to != from {
			moves = append(moves, Move{From: from, To: to})
		}
	}
	return out, moves
}

var (
	sidEveryone  = mustSID("S-1-1-0")
	sidAuthUsers = mustSID("S-1-5-11")
	sidAnonymous = mustSID("S-1-5-7")
	sidGuests    = mustSID("S-1-5-32-546")
)

// changePrincipal is the token a trustee is evaluated as. Every authenticated token holds Everyone
// and Authenticated Users, so a moved deny naming either narrows every trustee (T-0770). Anonymous
// and Guests do not hold Authenticated Users. Other group memberships are unknown: the caller sets
// ChangesIncomplete when a reorder could matter through them.
func changePrincipal(t sid.SID) Principal {
	if t == sidAnonymous || t == sidGuests {
		return PrincipalFromSIDs(t, sidEveryone)
	}
	return PrincipalFromSIDs(t, sidEveryone, sidAuthUsers)
}

// rightsOverlap reports whether two ACEs can speak about the same right. Two different object
// types overlap on read/write-property bits unless the catalogue proves both are exact-match
// kinds: a property set covers its member attributes (grants.go), and without a catalogue, or
// for a GUID it does not know, that cannot be ruled out.
func rightsOverlap(a, b ACE, cat RightsCatalog) bool {
	common := a.Mask & b.Mask & storedMaskBits
	if common == 0 {
		return false
	}
	if a.ObjectType == nil || b.ObjectType == nil || *a.ObjectType == *b.ObjectType {
		return true
	}
	if common&(MaskReadProp|MaskWriteProp) == 0 {
		return false
	}
	exact := func(g guid.GUID) bool {
		if cat == nil {
			return false
		}
		k, _ := cat.Kind(g)
		return k == Attribute || k == ControlAccess || k == ValidatedWrite || k == Class
	}
	return !(exact(*a.ObjectType) && exact(*b.ObjectType))
}

// groupOrderMatters reports whether a moved ACE changed its relative order against an ACE of the
// opposite decision type, for a different trustee, on an overlapping right. If the moved trustee
// is a group holding that other trustee, the reorder changes its rights, and group membership is
// not known here.
func groupOrderMatters(after SD, moves []Move, cat RightsCatalog) bool {
	n := len(after.DACL.ACEs)
	from := make([]int, n) // after index -> before index
	for i := range from {
		from[i] = i
	}
	for _, mv := range moves {
		from[mv.To] = mv.From
	}
	for _, mv := range moves {
		m := after.DACL.ACEs[mv.To]
		if m.Kind == Opaque || m.Kind == Callback {
			continue
		}
		for j := 0; j < n; j++ {
			o := after.DACL.ACEs[j]
			if j == mv.To || o.Kind == Opaque || o.Kind == Callback || o.Trustee == m.Trustee || o.deny() == m.deny() || !rightsOverlap(m, o, cat) {
				continue
			}
			if (mv.To < j) != (from[mv.To] < from[j]) {
				return true
			}
		}
	}
	return false
}

// rightsChanges evaluates, for each right named by an ACE that moved and each trustee named in the
// DACL, the decision before and after the reorder. Each trustee is evaluated holding Everyone and
// Authenticated Users; group-mediated effects through other groups cannot be resolved here and set
// the incomplete flag.
func rightsChanges(before, after SD, moves []Move, cat RightsCatalog) ([]RightsChange, bool) {
	type key struct {
		t sid.SID
		m uint32
		o guid.GUID
		h bool
	}
	seen := map[key]bool{}
	var keys []key
	var trustees []sid.SID
	tseen := map[sid.SID]bool{}
	for _, a := range after.DACL.ACEs {
		if a.Kind != Opaque && a.Kind != Callback && !tseen[a.Trustee] {
			tseen[a.Trustee] = true
			trustees = append(trustees, a.Trustee)
		}
	}
	capped := false
build:
	for _, mv := range moves {
		a := after.DACL.ACEs[mv.To]
		if a.Kind == Opaque || a.Kind == Callback {
			continue
		}
		for bit := uint32(1); bit != 0 && bit <= MaskWriteOwner; bit <<= 1 {
			if a.Mask&bit == 0 || bit&storedMaskBits == 0 {
				continue
			}
			for _, t := range trustees {
				k := key{t: t, m: bit}
				if a.ObjectType != nil {
					k.o, k.h = *a.ObjectType, true
				}
				if !seen[k] {
					// The DACL is untrusted input: bound the keys before allocating them.
					if len(keys) >= maxChangeEvals {
						capped = true
						break build
					}
					seen[k] = true
					keys = append(keys, k)
				}
			}
		}
	}
	var out []RightsChange
	incomplete := capped || groupOrderMatters(after, moves, cat)
	for _, k := range keys {
		r := Right{Mask: k.m}
		var objp *guid.GUID
		if k.h {
			g := k.o
			objp = &g
			r.Object = objp
			kind := RightKind(0)
			if cat != nil {
				kind, _ = cat.Kind(g)
			}
			if kind == Unset {
				incomplete = true
				continue
			}
			r.Kind = kind
		}
		p := changePrincipal(k.t)
		b, a := Grants(p, r, before).Decision, Grants(p, r, after).Decision
		if b != a {
			out = append(out, RightsChange{Trustee: k.t, Mask: k.m, Object: objp, Before: b, After: a})
		} else if b == Unknown {
			incomplete = true // cannot tell whether the reorder changed this right
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if c := compareSID(out[i].Trustee, out[j].Trustee); c != 0 {
			return c < 0
		}
		return out[i].Mask < out[j].Mask
	})
	return out, incomplete
}

func compareSID(a, b sid.SID) int {
	x, y := a.String(), b.String()
	switch {
	case x < y:
		return -1
	case x > y:
		return 1
	}
	return 0
}

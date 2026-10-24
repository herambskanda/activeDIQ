package sd

import (
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/attr/sid"
)

// Decision is the three-valued answer of Grants. A consumer that guards (the Tier-0 guard) treats
// Unknown as Yes.
type Decision uint8

const (
	No Decision = iota
	Yes
	Unknown
)

func (d Decision) String() string {
	switch d {
	case Yes:
		return "yes"
	case Unknown:
		return "unknown"
	}
	return "no"
}

var (
	sidSelf         = mustSID("S-1-5-10")
	sidOwnerRights  = mustSID("S-1-3-4")
	implicitOwnerRW = uint32(MaskReadControl | MaskWriteDACL)
)

// Bits the DC decides by privilege or by a different algorithm, not by the DACL walk.
const (
	maskAccessSystemSecurity = 0x01000000
	maskMaximumAllowed       = 0x02000000
)

func mustSID(s string) sid.SID {
	v, err := sid.Parse(s)
	if err != nil {
		panic(err)
	}
	return v
}

// Principal is the token of the identity being asked about: its own SID and every group SID
// (tokenGroups, which includes the primary group), taken from the DC, never from names.
type Principal struct {
	sids       map[sid.SID]struct{}
	objectSID  *sid.SID
	incomplete bool
}

// PrincipalFromToken builds a principal from a user SID and its tokenGroups. Every real token
// holds at least Everyone, so an empty group list marks the principal Incomplete.
func PrincipalFromToken(user sid.SID, tokenGroups []sid.SID) Principal {
	p := Principal{sids: map[sid.SID]struct{}{user: {}}, incomplete: len(tokenGroups) == 0}
	for _, g := range tokenGroups {
		p.sids[g] = struct{}{}
	}
	return p
}

// PrincipalFromSIDs builds a principal from a bare SID list with no claim to completeness: the
// result is always Incomplete.
func PrincipalFromSIDs(sids ...sid.SID) Principal {
	p := Principal{sids: map[sid.SID]struct{}{}, incomplete: true}
	for _, s := range sids {
		p.sids[s] = struct{}{}
	}
	return p
}

// WithObjectSID states the SID of the object the SD belongs to. SELF (S-1-5-10) in an ACE means
// "the object itself", so it applies to the principal only when the token holds that SID. Without
// it a SELF ACE that could matter makes the answer Unknown.
func (p Principal) WithObjectSID(object sid.SID) Principal {
	p.objectSID = &object
	return p
}

// Incomplete reports that group membership may be missing.
func (p Principal) Incomplete() bool { return p.incomplete }

// RightKind is what a Right's Object GUID names.
type RightKind uint8

const (
	// Unset is the zero value and fails closed: with an Object GUID it makes Grants answer
	// Unknown, because the primitive cannot tell an attribute from a property set.
	Unset RightKind = iota
	Whole
	Class
	Attribute
	PropertySet
	ControlAccess
	ValidatedWrite
)

// Right is the access asked about: a mask and, for object-scoped rights, the GUID.
type Right struct {
	Mask   uint32
	Object *guid.GUID
	Kind   RightKind
}

// Source is an ACE that contributed to the answer.
type Source struct {
	ACEIndex   int
	Inherited  bool
	ObjectType *guid.GUID
	Reason     string
}

// Result is the answer, the ACEs behind it and what the caller must know about its quality.
type Result struct {
	Decision   Decision
	Sources    []Source
	Why        string // set for Unknown, and for No without a deny ACE
	Incomplete bool   // the principal may lack groups
	Anomalous  bool   // the SD has anomalies; the answer is derived from a non-editable SD
}

// Grants evaluates the DACL in stored order, as the DC does: INHERIT_ONLY ACEs are skipped, ACEs
// whose trustee is not in the token are skipped, an object ACE applies only when its ObjectType is
// the asked GUID, allow ACEs remove bits from the remaining mask and a deny ACE that meets a
// remaining bit refuses the request. Conditions it cannot evaluate make the answer Unknown.
func Grants(p Principal, right Right, s SD) Result {
	res := Result{Incomplete: p.incomplete, Anomalous: len(s.Anomalies) > 0}
	if right.Mask == 0 || right.Mask&(maskGeneric|maskAccessSystemSecurity|maskMaximumAllowed) != 0 {
		res.Decision, res.Why = Unknown, "mask_not_specific"
		return res
	}
	if right.Object != nil && right.Kind != Class && right.Kind != Attribute &&
		right.Kind != PropertySet && right.Kind != ControlAccess && right.Kind != ValidatedWrite {
		res.Decision, res.Why = Unknown, "right_kind_unset"
		return res
	}
	switch s.DACL.Kind {
	case Null:
		res.Decision, res.Why = Yes, "null_dacl"
		return res
	case Absent:
		res.Decision, res.Why = Unknown, "dacl_absent"
		return res
	}
	remaining := right.Mask
	opaqueSeen := false
	var pendingSelf uint32 // bits a SELF allow ACE might grant, object SID unknown
	ownerHasACE := false
	for _, a := range s.DACL.ACEs {
		if s.HasOwner && a.Kind != Opaque && a.Trustee == s.Owner {
			ownerHasACE = true
		}
		if a.Kind != Opaque && a.Trustee == sidOwnerRights {
			ownerHasACE = true
		}
	}
	// The DC removes the owner's implicit READ_CONTROL|WRITE_DAC and, for a holder of
	// SeTakeOwnershipPrivilege, WRITE_OWNER from the request before it walks the DACL, so no ACE,
	// deny included, can take them back. Those bits are not decided by the walk: they make the
	// answer Unknown (at best) and are removed from what the walk evaluates.
	var undecided uint32
	undecidedWhy := ""
	if s.HasOwner && p.holds(s.Owner, nil) {
		if b := remaining & implicitOwnerRW; b != 0 {
			undecided |= b
			undecidedWhy = "implicit_owner_rights"
			if ownerHasACE {
				undecidedWhy = "owner_ace_present"
			}
		}
	}
	if b := remaining & MaskWriteOwner; b != 0 {
		undecided |= b
		if undecidedWhy == "" {
			undecidedWhy = "privilege_unmodelled" // SeTakeOwnershipPrivilege is not in the model
		}
	}
	remaining &^= undecided
	for i, a := range s.DACL.ACEs {
		if a.InheritOnly() {
			continue
		}
		switch a.Kind {
		case Opaque:
			opaqueSeen = true
			continue
		case Callback:
			if a.Mask&remaining != 0 && p.holds(a.Trustee, nil) {
				res.Decision, res.Why = Unknown, "callback_ace"
				return res
			}
			continue
		}
		if a.Type != TypeAccessAllowed && a.Type != TypeAccessDenied &&
			a.Type != TypeAccessAllowedObject && a.Type != TypeAccessDeniedObject {
			continue // audit, label and policy ACEs grant nothing
		}
		if a.ObjectType != nil && (right.Object == nil || *right.Object != *a.ObjectType) {
			// A grant or refusal on an object-tree node (a property set) covers the attributes
			// in it. Without a catalogue we cannot tell whether this GUID is the asked
			// attribute's set, so a held ACE that meets the asked read/write bits makes the
			// answer Unknown. Control-access, validated-write and class asks are exact matches.
			// A property-set ask is covered too: a denied child means the set is not fully granted.
			// An OWNER RIGHTS ACE counts as held when the principal is the owner.
			if (right.Kind == Attribute || right.Kind == PropertySet) &&
				a.Mask&remaining&(MaskReadProp|MaskWriteProp) != 0 &&
				(p.holds(a.Trustee, p.objectSID) || a.Trustee == sidSelf && p.objectSID == nil ||
					a.Trustee == sidOwnerRights && s.HasOwner && p.holds(s.Owner, nil)) {
				res.Decision, res.Sources, res.Why = Unknown, nil, "property_set_unresolved"
				return res
			}
			continue
		}
		hit := a.Mask & remaining
		if hit == 0 {
			continue
		}
		if a.Trustee == sidSelf && p.objectSID == nil {
			// Unresolvable. An allow can only add bits, so it matters only if nothing else grants
			// them; a deny might refuse, so it decides nothing here.
			if a.allow() {
				pendingSelf |= hit
				continue
			}
			res.Decision, res.Why = Unknown, "self_unresolved"
			return res
		}
		if a.Trustee == sidOwnerRights && s.HasOwner && p.holds(s.Owner, nil) {
			// An OWNER RIGHTS ACE replaces the owner's implicit rights and the DC combines it
			// with the other ACEs in ways Samba itself documents as unclear: not modelled.
			res.Decision, res.Sources, res.Why = Unknown, nil, "owner_rights_ace"
			return res
		}
		if !p.holds(a.Trustee, p.objectSID) {
			continue
		}
		src := Source{ACEIndex: i, Inherited: a.Inherited(), ObjectType: a.ObjectType}
		if a.allow() {
			remaining &^= hit
			src.Reason = "allow"
			res.Sources = append(res.Sources, src)
			if remaining == 0 {
				break
			}
			continue
		}
		src.Reason = "deny"
		res.Sources = []Source{src}
		res.Decision = No
		if hit&pendingSelf != 0 {
			res.Decision, res.Sources, res.Why = Unknown, nil, "self_unresolved"
		} else if opaqueSeen {
			res.Decision, res.Why = Unknown, "opaque_ace_before_decision"
		}
		return res
	}
	if remaining != 0 {
		res.Sources = nil
		if remaining&pendingSelf != 0 {
			res.Decision, res.Why = Unknown, "self_unresolved"
			return res
		}
		res.Decision, res.Why = No, "no_matching_ace"
		if opaqueSeen {
			res.Decision, res.Why = Unknown, "opaque_ace_present"
		}
		return res
	}
	res.Decision = Yes
	if opaqueSeen {
		res.Decision, res.Why = Unknown, "opaque_ace_before_decision"
	} else if undecided != 0 {
		res.Decision, res.Sources, res.Why = Unknown, nil, undecidedWhy
	}
	return res
}

func (p Principal) holds(t sid.SID, self *sid.SID) bool {
	if _, ok := p.sids[t]; ok {
		return true
	}
	if self != nil && t == sidSelf {
		_, ok := p.sids[*self]
		return ok
	}
	return false
}

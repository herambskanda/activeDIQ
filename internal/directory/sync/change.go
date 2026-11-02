package sync

import (
	"slices"
	"strings"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// ChangeMapper maps one DirSync ObjectChange (contract §6.4) to the inventory.Patch that applies it. A change is
// a patch, not a snapshot: only the attributes it names enter the Patch, so a change to displayName leaves
// every other stored column and attribute alone (DM-18.I2). It reads attributes by the same closed list and with
// the same decoders as the full-read Mapper, so a value means the same on either path. It is immutable and safe
// for concurrent use.
type ChangeMapper struct {
	nc   inventory.GUID
	full *Mapper
}

// NewChangeMapper builds the mapper of one naming context's feed. The configuration is the full-read Mapper's
// (Requested and Groups are ignored: a patch asks for the whole closed list, and primary groups are derived from
// the stored rows by the inventory writer, whichever of the user and its group arrives first).
func NewChangeMapper(c Config) (*ChangeMapper, error) {
	c.Requested, c.Groups = nil, nil
	m, err := NewMapper(c)
	if err != nil {
		return nil, err
	}
	return &ChangeMapper{nc: c.NC, full: m}, nil
}

// Planned is the outcome of mapping one change.
type Planned struct {
	Patch inventory.Patch
	// MembersUnresolved counts member values the change named without a GUID. An add that could not be named is
	// not applied (it under-grants). A removal, or a whole set, that could not be named sets Patch.Reread: the
	// group's edges are ended until the object is read, never left active.
	MembersUnresolved int
}

// Plan maps one change. A malformed change is an *Error (errors.Is(err, ErrMalformed)); the caller goes on with the
// batch and, when the returned Planned names an object (Patch.Object, set as soon as the GUID parsed), has that
// object read, because the change is consumed with its cookie and what it carried would otherwise be lost. Patch.Create is set only when the change carries everything a stored row needs:
// otherwise the inventory reports the object as needing a read and stores nothing.
func (cm *ChangeMapper) Plan(ch *connectorv1.ObjectChange) (Planned, error) {
	var out Planned
	if ch == nil {
		return out, refuse("objectGUID", CodeMissing)
	}
	object, err := guidText(ch.GetObjectGuid(), "objectGUID")
	if err != nil {
		return out, err
	}
	// The identity is set before anything can be refused, so a refused change still says which object it was about:
	// the caller reads that object instead of losing what the change carried.
	out.Patch.Object, out.Patch.NC = object, cm.nc
	var state inventory.ObjectState
	switch ch.GetState() {
	case connectorv1.ObjectState_OBJECT_STATE_LIVE:
		state = inventory.ObjLive
	case connectorv1.ObjectState_OBJECT_STATE_DELETED:
		state = inventory.ObjDeleted
	case connectorv1.ObjectState_OBJECT_STATE_RECYCLED:
		state = inventory.ObjRecycled
	default:
		return out, refuse("state", CodeMissing)
	}
	entry, members, err := cm.entryOf(ch, object, state)
	if err != nil {
		return out, err
	}
	set, err := cm.full.index(entry)
	if err != nil {
		return out, err
	}

	pt := &out.Patch
	pt.State = inventory.Some(state)
	if err := cm.position(pt, ch, state); err != nil {
		return out, err
	}
	if err := cm.fields(pt, set, state); err != nil {
		return out, err
	}
	if err := members.into(pt, object, &out.MembersUnresolved); err != nil {
		return out, err
	}
	pt.Create = cm.create(entry, ch, set, state)
	return out, nil
}

// position sets the DN, the RDN and the parent. A deleted or recycled object's parent is not the Deleted Objects
// container it now sits in, and the feed does not say where it was: the stored place is kept (as the reconcile
// keeps it), and the tombstone's own DN is stored as the display snapshot.
func (cm *ChangeMapper) position(pt *inventory.Patch, ch *connectorv1.ObjectChange, state inventory.ObjectState) error {
	if d := ch.GetDn().GetDisplayDn(); d != "" {
		full, rdn, err := parseDisplayDN(d)
		if err != nil {
			return err
		}
		pt.DN, pt.RDN = inventory.Some(full), inventory.Some(rdn)
	}
	if state != inventory.ObjLive {
		return nil
	}
	switch {
	case ch.GetParentGuid() != nil:
		p, err := guidText(ch.ParentGuid, "parentGuid")
		if err != nil {
			return err
		}
		if p == pt.Object {
			return refuse("parentGuid", CodeBadGUID)
		}
		pt.Parent = inventory.Some(p)
	case pt.Object == cm.nc:
		pt.Parent = inventory.Some(inventory.GUID("")) // the head has no parent
	}
	return nil
}

// fields reads each attribute the change names. An attribute the change does not name is not read, and stays as
// stored; one it names with no values (CLEARED) is read and empty.
func (cm *ChangeMapper) fields(pt *inventory.Patch, set attrSet, state inventory.ObjectState) error {
	if a, ok := set.get("objectClass"); ok && len(a.GetValues()) > 0 {
		classes, _, err := texts(set, "objectClass", maxClass)
		if err != nil {
			return err
		}
		pt.Class = inventory.Some(inventory.ClassKind{Class: classes[len(classes)-1], Kind: kindOf(classes)})
	}
	for _, f := range []struct {
		name string
		max  int
		dst  *inventory.Opt[string]
	}{{"sAMAccountName", maxSAM, &pt.SAMAccountName}, {"userPrincipalName", maxUPN, &pt.UPN}, {"displayName", maxDisplay, &pt.DisplayName}} {
		if s, present, err := text(set, f.name, f.max); err != nil {
			return err
		} else if present {
			*f.dst = inventory.Some(s)
		}
	}
	if a, ok := set.get("objectSid"); ok {
		v, err := one(a, "objectSid")
		if err != nil {
			return err
		}
		var b []byte
		if v != nil {
			s, isSID := v.GetValue().(*connectorv1.AttributeValue_Sid)
			if !isSID {
				return refuse("objectSid", CodeType)
			}
			if b, err = sidBytes(s.Sid, "objectSid"); err != nil {
				return err
			}
		}
		pt.SID = inventory.Some(b)
	}
	if a, ok := set.get("mS-DS-ConsistencyGuid"); ok {
		v, err := one(a, "mS-DS-ConsistencyGuid")
		if err != nil {
			return err
		}
		var b []byte
		if v != nil {
			o, isOctets := v.GetValue().(*connectorv1.AttributeValue_Octets)
			if !isOctets {
				return refuse("mS-DS-ConsistencyGuid", CodeType)
			}
			if len(o.Octets) != 16 {
				return refuse("mS-DS-ConsistencyGuid", CodeBadGUID)
			}
			b = slices.Clone(o.Octets)
		}
		pt.ConsistencyGUID = inventory.Some(b)
	}
	if _, ok := set.get("whenCreated"); ok {
		t, err := generalized(set, "whenCreated")
		if err != nil {
			return err
		}
		pt.WhenCreated = inventory.Some(t)
	}
	if _, ok := set.get("whenChanged"); ok {
		t, err := generalized(set, "whenChanged")
		if err != nil {
			return err
		}
		pt.WhenChanged = inventory.Some(t)
	}
	for _, in := range []struct {
		attr  string
		never bool
		dst   *inventory.Opt[time.Time]
	}{
		{"lockoutTime", false, &pt.LockoutTime}, {"pwdLastSet", false, &pt.PwdLastSet},
		{"accountExpires", true, &pt.AccountExpires}, {"lastLogonTimestamp", false, &pt.LastLogonTimestamp},
	} {
		t, err := timeOf(set, in.attr, in.never)
		if err != nil {
			return err
		}
		if t.read {
			*in.dst = inventory.Some(t.t)
		}
	}
	if err := cm.numbers(pt, set); err != nil {
		return err
	}
	return cm.bag(pt, set, state)
}

func (cm *ChangeMapper) numbers(pt *inventory.Patch, set attrSet) error {
	if uac, _, has, err := int32Of(set, "userAccountControl"); err != nil {
		return err
	} else if _, named := set.get("userAccountControl"); named {
		var v *int64
		if has {
			b := int64(uint32(uac))
			v = &b
		}
		pt.UserAccountControl = inventory.Some(v)
	}
	if n, _, has, err := int32Of(set, "primaryGroupID"); err != nil {
		return err
	} else if _, named := set.get("primaryGroupID"); named {
		var v *int64
		if has {
			if n < 0 {
				return refuse("primaryGroupID", CodeRange)
			}
			b := int64(n)
			v = &b
		}
		pt.PrimaryGroupID = inventory.Some(v)
	}
	if gt, _, has, err := int32Of(set, "groupType"); err != nil {
		return err
	} else if _, named := set.get("groupType"); named {
		var v *int32
		if has {
			v = &gt
		}
		pt.GroupType = inventory.Some(v)
	}
	if a, ok := set.get("servicePrincipalName"); ok {
		vs, err := values(a, "servicePrincipalName")
		if err != nil {
			return err
		}
		has := len(vs) > 0
		pt.HasSPN = inventory.Some(&has)
	}
	return nil
}

// bag reads the generic attributes. A named attribute with no value is removed from the stored bag.
func (cm *ChangeMapper) bag(pt *inventory.Patch, set attrSet, state inventory.ObjectState) error {
	put := func(name string, v any, present bool) {
		if !present {
			return
		}
		if v == nil {
			pt.ClearAttributes = append(pt.ClearAttributes, name)
			return
		}
		if pt.Attributes == nil {
			pt.Attributes = map[string]any{}
		}
		pt.Attributes[name] = v
	}
	for _, name := range []string{"mail", "company", "dNSHostName", "operatingSystem", "operatingSystemVersion"} {
		s, present, err := text(set, name, 1024)
		if err != nil {
			return err
		}
		put(name, nonEmpty(s), present)
	}
	s, present, err := firstText(set, "description", 4096)
	if err != nil {
		return err
	}
	put("description", nonEmpty(s), present)
	for _, d := range []string{"managedBy"} {
		dv, present, err := dnValue(set, d)
		if err != nil {
			return err
		}
		var s string
		if dv != nil {
			if s, err = cleanText(d, dv.DisplayDn, maxDN); err != nil {
				return err
			}
		}
		put(d, nonEmpty(s), present)
	}
	if list, present, err := texts(set, "msDS-AllowedToDelegateTo", 1024); err != nil {
		return err
	} else if present && len(list) == 0 {
		put("msDS-AllowedToDelegateTo", nil, true)
	} else {
		put("msDS-AllowedToDelegateTo", anyOrNil(list), present)
	}
	if state != inventory.ObjLive {
		dv, present, err := dnValue(set, "lastKnownParent")
		if err != nil {
			return err
		}
		var s string
		if dv != nil {
			if s, err = cleanText("lastKnownParent", dv.DisplayDn, maxDN); err != nil {
				return err
			}
		}
		put("lastKnownParent", nonEmpty(s), present)
	}
	return nil
}

func nonEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func anyOrNil(l []string) any {
	if l == nil {
		return nil
	}
	return l
}

// memberOps collects the member changes of one object.
type memberOps struct {
	added, removed []inventory.GUID
	whole          bool // a SET or CLEARED: added is the whole set
	touched        bool
	unresolved     int
	// reread: a removal or a whole set had a value naming no GUID, so which edges must go is unknown.
	reread bool
}

// into puts the member edges into the patch. A SET or CLEARED is the whole set and mixing it with incremental
// ops, or naming one member both added and removed, is refused: which would win is a guess.
func (ops *memberOps) into(pt *inventory.Patch, object inventory.GUID, unresolved *int) error {
	if !ops.touched {
		return nil
	}
	*unresolved += ops.unresolved
	if len(ops.added)+len(ops.removed) > maxMembers {
		return refuse("member", CodeTooMany)
	}
	if ops.whole && len(ops.removed) > 0 {
		return refuse("member", CodeDuplicate)
	}
	both := map[inventory.GUID]bool{}
	for _, g := range ops.added {
		both[g] = true
	}
	for _, g := range ops.removed {
		if both[g] {
			return refuse("member", CodeDuplicate)
		}
	}
	for _, g := range append(slices.Clone(ops.added), ops.removed...) {
		if g == object {
			return refuse("member", CodeBadGUID)
		}
	}
	pt.Members, pt.RemovedMembers = ops.added, ops.removed
	// A set is complete only when every value of it was named: an edge the change could not name must not let the
	// others' absence remove anything.
	pt.MembersComplete = ops.whole && ops.unresolved == 0
	pt.Reread = ops.reread
	return nil
}

// entryOf turns the change into the DirectoryEntry the full-read Mapper reads, and collects the member ops. Every
// named attribute becomes an attribute of the entry (CLEARED: present with no values), so the same decoders apply.
func (cm *ChangeMapper) entryOf(ch *connectorv1.ObjectChange, object inventory.GUID, state inventory.ObjectState) (*connectorv1.DirectoryEntry, *memberOps, error) {
	e := &connectorv1.DirectoryEntry{ObjectGuid: ch.GetObjectGuid(), Dn: ch.GetDn(), ParentGuid: ch.GetParentGuid()}
	ops := &memberOps{}
	var memberAttr *connectorv1.Attribute
	for _, c := range ch.GetAttributes() {
		if c == nil {
			continue
		}
		name := c.GetName()
		switch c.GetOp() {
		case connectorv1.ChangeOp_CHANGE_OP_SET, connectorv1.ChangeOp_CHANGE_OP_CLEARED,
			connectorv1.ChangeOp_CHANGE_OP_VALUES_ADDED, connectorv1.ChangeOp_CHANGE_OP_VALUES_REMOVED:
		default:
			return nil, nil, refuse(closedSpellingOrBlank(name), CodeType)
		}
		if strings.EqualFold(name, "member") {
			ops.touched = true
			vals := c.GetValues()
			if len(vals) > maxMembers {
				return nil, nil, refuse("member", CodeTooMany)
			}
			switch c.GetOp() {
			case connectorv1.ChangeOp_CHANGE_OP_SET, connectorv1.ChangeOp_CHANGE_OP_CLEARED:
				if ops.whole {
					return nil, nil, refuse("member", CodeDuplicate)
				}
				ops.whole = true
				g, n, err := memberGUIDs(vals)
				if err != nil {
					return nil, nil, err
				}
				ops.added, ops.unresolved = append(ops.added, g...), ops.unresolved+n
				ops.reread = ops.reread || n > 0
			case connectorv1.ChangeOp_CHANGE_OP_VALUES_ADDED:
				g, n, err := memberGUIDs(vals)
				if err != nil {
					return nil, nil, err
				}
				ops.added, ops.unresolved = append(ops.added, g...), ops.unresolved+n
			default:
				g, n, err := memberGUIDs(vals)
				if err != nil {
					return nil, nil, err
				}
				ops.removed, ops.unresolved = append(ops.removed, g...), ops.unresolved+n
				ops.reread = ops.reread || n > 0
			}
			if ops.whole && len(ops.removed) > 0 {
				return nil, nil, refuse("member", CodeDuplicate)
			}
			// The creation path reads a group's added or set members from the entry.
			if c.GetOp() != connectorv1.ChangeOp_CHANGE_OP_VALUES_REMOVED {
				if memberAttr == nil {
					memberAttr = &connectorv1.Attribute{Name: "member"}
				}
				memberAttr.Values = append(memberAttr.Values, vals...)
				memberAttr.Complete = memberAttr.Complete || c.GetOp() == connectorv1.ChangeOp_CHANGE_OP_SET || c.GetOp() == connectorv1.ChangeOp_CHANGE_OP_CLEARED
			}
			continue
		}
		switch c.GetOp() {
		case connectorv1.ChangeOp_CHANGE_OP_SET, connectorv1.ChangeOp_CHANGE_OP_CLEARED:
			e.Attributes = append(e.Attributes, &connectorv1.Attribute{Name: name, Values: c.GetValues(), Complete: true})
		default:
			// Incremental values are a link-attribute encoding; no other attribute on the closed list has one.
			return nil, nil, refuse(closedSpellingOrBlank(name), CodeType)
		}
	}
	if memberAttr != nil {
		e.Attributes = append(e.Attributes, memberAttr)
	}
	// The state the change reports is the feed's own word; isDeleted and isRecycled are derived from it.
	e.Attributes = append(e.Attributes,
		boolAttr("isDeleted", state != inventory.ObjLive), boolAttr("isRecycled", state == inventory.ObjRecycled))
	return e, ops, nil
}

func boolAttr(name string, v bool) *connectorv1.Attribute {
	return &connectorv1.Attribute{Name: name, Complete: true,
		Values: []*connectorv1.AttributeValue{{Value: &connectorv1.AttributeValue_Boolean{Boolean: v}}}}
}

// closedSpellingOrBlank names an attribute in a refusal only when it is one of ours; anything else is
// "attributes", so nothing from the directory enters an error.
func closedSpellingOrBlank(name string) string {
	if inClosed(name) {
		return closedSpelling(name)
	}
	return "attributes"
}

// memberGUIDs reads member values as GUIDs. A value that names no GUID is counted, not stored.
func memberGUIDs(vs []*connectorv1.AttributeValue) (out []inventory.GUID, unresolved int, err error) {
	seen := make(map[inventory.GUID]bool, len(vs))
	for _, v := range vs {
		d, isDN := v.GetValue().(*connectorv1.AttributeValue_Dn)
		if !isDN || d.Dn == nil {
			return nil, 0, refuse("member", CodeType)
		}
		if d.Dn.GetGuid() == nil {
			unresolved++
			continue
		}
		g, err := guidText(d.Dn.Guid, "member")
		if err != nil {
			return nil, 0, err
		}
		if !seen[g] {
			seen[g] = true
			out = append(out, g)
		}
	}
	return out, unresolved, nil
}

// create builds the whole observation of an object the inventory may not hold, when the change carries what a row
// needs, and returns nil when it does not (the inventory then reports the object as needing a read). A change
// that is a creation carries every attribute of the object, because all their USNs are newer than the cookie; a
// change of an existing object carries only what changed, and that is never enough: what is missing is not guessed.
func (cm *ChangeMapper) create(entry *connectorv1.DirectoryEntry, ch *connectorv1.ObjectChange, set attrSet, state inventory.ObjectState) *inventory.Observation {
	if ch.GetDn().GetDisplayDn() == "" {
		return nil
	}
	if state == inventory.ObjLive && !cm.carriesCreation(ch, set) {
		return nil
	}
	m, err := cm.full.Map(entry)
	if err != nil || m.Observation.NC != cm.nc || m.MembersUnresolved > 0 && m.Observation.MembersComplete {
		return nil
	}
	return &m.Observation
}

// carriesCreation reports whether a live change names what a new object has: its class, creation time and
// position, and for a principal or a group its SID, account name and the attribute that types it.
func (cm *ChangeMapper) carriesCreation(ch *connectorv1.ObjectChange, set attrSet) bool {
	has := func(name string) bool { a, ok := set.get(name); return ok && len(a.GetValues()) > 0 }
	if !has("objectClass") || !has("whenCreated") {
		return false
	}
	if ch.GetParentGuid() == nil && ch.GetObjectGuid() != nil {
		// Only the head of the naming context has no parent.
		g, err := guidText(ch.ObjectGuid, "objectGUID")
		if err != nil || g != cm.nc {
			return false
		}
	}
	classes, _, err := texts(set, "objectClass", maxClass)
	if err != nil || len(classes) == 0 {
		return false
	}
	switch kindOf(classes) {
	case inventory.KindUser, inventory.KindInetOrgPerson, inventory.KindComputer, inventory.KindGMSA:
		return has("objectSid") && has("sAMAccountName") && has("userAccountControl")
	case inventory.KindGroup:
		return has("objectSid") && has("sAMAccountName") && has("groupType")
	}
	return true
}

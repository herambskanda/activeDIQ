package sync

import (
	"encoding/json/v2"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/attr/secretattr"
	"github.com/skenzeriq/activediq/internal/directory/attr/sid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/directory/inventory"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// GroupResolver finds the group of a SID in the domain being synced. The cycle driver backs it with
// the groups it has seen (a GroupIndex) or with the stored inventory; the Mapper does no lookups of its own.
type GroupResolver interface {
	GroupBySID(sid []byte) (inventory.GUID, bool)
}

// GroupIndex is an in-memory GroupResolver.
type GroupIndex struct{ by map[string]inventory.GUID }

// NewGroupIndex returns an empty index.
func NewGroupIndex() *GroupIndex { return &GroupIndex{by: map[string]inventory.GUID{}} }

// Add records that the group with the given binary SID has the given GUID.
func (x *GroupIndex) Add(sid []byte, g inventory.GUID) { x.by[string(sid)] = g }

// GroupBySID implements GroupResolver.
func (x *GroupIndex) GroupBySID(sid []byte) (inventory.GUID, bool) {
	g, ok := x.by[string(sid)]
	return g, ok
}

// Config is a Mapper's configuration.
type Config struct {
	// NC is the GUID of the naming context (domain) the entries come from: the nc_guid of every
	// Observation, and the identity of its head.
	NC inventory.GUID
	// Requested narrows the attributes a sync asks for (the reconcile pass wants fewer). Empty means
	// the whole closed list. A name that is not on the list is ErrNotAllowed.
	Requested []string
	// SchemaSecrets are the attributes this directory's schema flags as secret (searchFlags 0x80,
	// 0x200 or 0x1000, computed by the connector at connect). They are dropped from the request, so a
	// customer who marks description confidential never has it read.
	SchemaSecrets []string
	// Groups resolves primaryGroupID. Nil leaves every primary group unresolved (PrimaryGroupNoResolver).
	Groups GroupResolver
}

// PrimaryGroupStatus says what became of a principal's primary group.
type PrimaryGroupStatus string

// The statuses.
const (
	PrimaryGroupResolved      PrimaryGroupStatus = "resolved"
	PrimaryGroupNotApplicable PrimaryGroupStatus = "not_applicable"            // not a live principal
	PrimaryGroupNotRead       PrimaryGroupStatus = "primary_group_id_not_read" // primaryGroupID not on the entry
	PrimaryGroupNoSID         PrimaryGroupStatus = "object_sid_not_read"       // no SID to take the domain from
	PrimaryGroupNoResolver    PrimaryGroupStatus = "no_resolver"               // the Mapper has no GroupResolver
	PrimaryGroupUnresolved    PrimaryGroupStatus = "group_not_found"           // no group of that SID in the domain
)

// Mapped is the outcome of mapping one entry.
type Mapped struct {
	Observation inventory.Observation
	// PrimaryGroup says why Observation.PrimaryGroup is set or left zero.
	PrimaryGroup PrimaryGroupStatus
	// MembersUnresolved counts member values that carried no GUID. Such a group is never complete: an
	// edge the cycle could not name must not let the others' absence remove anything.
	MembersUnresolved int
}

// Mapper maps connector entries to observations. It is immutable and safe for concurrent use.
type Mapper struct {
	nc       inventory.GUID
	requests []string        // effective request, closed-list spelling
	wanted   map[string]bool // lower-case
	groups   GroupResolver
}

// NewMapper validates the configuration. The effective request is the requested (or whole) closed
// list minus the schema secrets; an attribute outside the closed list, or a secret, is ErrNotAllowed.
func NewMapper(c Config) (*Mapper, error) {
	if c.NC == "" || !guidOK(c.NC) {
		return nil, fmt.Errorf("%w: naming context", ErrConfig)
	}
	req := c.Requested
	if len(req) == 0 {
		req = attributes
	}
	deny := map[string]bool{"ntsecuritydescriptor": true}
	for _, s := range secretattr.Static() {
		deny[strings.ToLower(s)] = true
	}
	for _, s := range c.SchemaSecrets {
		deny[strings.ToLower(s)] = true
	}
	m := &Mapper{nc: c.NC, wanted: map[string]bool{}, groups: c.Groups}
	for _, r := range req {
		switch low := strings.ToLower(r); {
		case !inClosed(r):
			return nil, fmt.Errorf("%w: not on the closed list", ErrNotAllowed)
		case deny[low]:
			if slices.ContainsFunc(c.SchemaSecrets, func(s string) bool { return strings.EqualFold(s, r) }) {
				continue // flagged by this schema: dropped, not an error
			}
			return nil, fmt.Errorf("%w: secret attribute", ErrNotAllowed)
		case m.wanted[low]:
		default:
			m.wanted[low] = true
			m.requests = append(m.requests, closedSpelling(r))
		}
	}
	if !m.wanted["objectclass"] {
		return nil, fmt.Errorf("%w: objectClass is required", ErrConfig)
	}
	return m, nil
}

func closedSpelling(name string) string {
	for _, a := range attributes {
		if strings.EqualFold(a, name) {
			return a
		}
	}
	return name
}

func guidOK(g inventory.GUID) bool {
	_, err := guid.Parse(string(g))
	return err == nil && string(g) == strings.ToLower(string(g))
}

// Attributes is the attribute list to put in the ScopedSearch request: the closed list as narrowed by
// the configuration, in the closed list's spelling.
func (m *Mapper) Attributes() []string { return slices.Clone(m.requests) }

// class names the structural classes the mapping recognises, lower-case, in the order that decides
// the kind: gMSA inherits computer, and computer inherits user, so the most derived is tested first.
var kindOfClass = []struct {
	class string
	kind  inventory.Kind
}{
	{"msds-groupmanagedserviceaccount", inventory.KindGMSA},
	{"computer", inventory.KindComputer},
	{"inetorgperson", inventory.KindInetOrgPerson},
	{"user", inventory.KindUser},
	{"group", inventory.KindGroup},
	{"organizationalunit", inventory.KindOU},
	{"contact", inventory.KindContact},
	{"foreignsecurityprincipal", inventory.KindFSP},
	{"container", inventory.KindContainer},
}

// Map maps one entry. A malformed entry is an *Error (errors.Is(err, ErrMalformed)); the caller counts
// it and goes on with the batch. The Observation's ObservedDSA and Ancestry beyond the first hop are
// the caller's (a batch and a chain are not the entry's).
func (m *Mapper) Map(e *connectorv1.DirectoryEntry) (Mapped, error) {
	var out Mapped
	if e == nil {
		return out, refuse("objectGUID", CodeMissing)
	}
	object, err := entryGUID(e.GetObjectGuid(), "objectGUID")
	if err != nil {
		return out, err
	}
	set, err := m.index(e)
	if err != nil {
		return out, err
	}
	o := &out.Observation
	o.Object, o.NC = object, m.nc

	// State first: a deleted or recycled object is not parented to a live container.
	deleted, _, err := boolean(set, "isDeleted")
	if err != nil {
		return out, err
	}
	recycled, _, err := boolean(set, "isRecycled")
	if err != nil {
		return out, err
	}
	switch {
	case recycled:
		o.State = inventory.ObjRecycled
	case deleted:
		o.State = inventory.ObjDeleted
	default:
		o.State = inventory.ObjLive
	}

	if err := m.identity(o, e, set); err != nil {
		return out, err
	}
	if err := m.place(o, e, set); err != nil {
		return out, err
	}
	if err := m.principal(&out, set); err != nil {
		return out, err
	}
	if err := m.group(&out, set); err != nil {
		return out, err
	}
	if err := m.bag(o, set); err != nil {
		return out, err
	}
	return out, nil
}

// index picks the wanted attributes of the entry by name. A duplicate is malformed, because which of
// two values wins would be a guess.
func (m *Mapper) index(e *connectorv1.DirectoryEntry) (attrSet, error) {
	set := attrSet{}
	for _, a := range e.GetAttributes() {
		if a == nil {
			continue
		}
		low := strings.ToLower(a.GetName())
		if !m.wanted[low] {
			continue
		}
		if _, dup := set[low]; dup {
			return nil, refuse(closedSpelling(low), CodeDuplicate)
		}
		set[low] = a
	}
	return set, nil
}

// identity sets kind and class from objectClass, and the naming attributes.
func (m *Mapper) identity(o *inventory.Observation, e *connectorv1.DirectoryEntry, set attrSet) error {
	classes, _, err := texts(set, "objectClass", maxClass)
	if err != nil {
		return err
	}
	switch {
	case len(classes) > 0:
		// The directory lists classes most general first, so the last is the most specific structural class.
		o.Class = classes[len(classes)-1]
		o.Kind = kindOf(classes)
	case o.State != inventory.ObjLive:
		// A recycled object keeps almost nothing; its class is unknown, not guessed. "top" is every object's class.
		o.Class, o.Kind = "top", inventory.KindOther
	default:
		return refuse("objectClass", CodeMissing)
	}

	if s, _, err := text(set, "sAMAccountName", maxSAM); err != nil {
		return err
	} else {
		o.SAMAccountName = s
	}
	if s, _, err := text(set, "userPrincipalName", maxUPN); err != nil {
		return err
	} else {
		o.UPN = s
	}
	if s, _, err := text(set, "displayName", maxDisplay); err != nil {
		return err
	} else {
		o.DisplayName = s
	}

	if a, ok := set.get("objectSid"); ok {
		v, err := one(a, "objectSid")
		if err != nil {
			return err
		}
		if v != nil {
			s, isSID := v.GetValue().(*connectorv1.AttributeValue_Sid)
			if !isSID {
				return refuse("objectSid", CodeType)
			}
			if o.SID, err = sidBytes(s.Sid, "objectSid"); err != nil {
				return err
			}
		}
	}
	if a, ok := set.get("mS-DS-ConsistencyGuid"); ok {
		v, err := one(a, "mS-DS-ConsistencyGuid")
		if err != nil {
			return err
		}
		if v != nil {
			b, isOctets := v.GetValue().(*connectorv1.AttributeValue_Octets)
			if !isOctets {
				return refuse("mS-DS-ConsistencyGuid", CodeType)
			}
			if _, err := guid.FromBytes(b.Octets); err != nil {
				return refuse("mS-DS-ConsistencyGuid", CodeBadGUID)
			}
			o.ConsistencyGUID = slices.Clone(b.Octets)
		}
	}
	if o.WhenCreated, err = generalized(set, "whenCreated"); err != nil {
		return err
	}
	if o.WhenChanged, err = generalized(set, "whenChanged"); err != nil {
		return err
	}
	return nil
}

func kindOf(classes []string) inventory.Kind {
	have := map[string]bool{}
	for _, c := range classes {
		have[strings.ToLower(c)] = true
	}
	for _, k := range kindOfClass {
		if have[k.class] {
			return k.kind
		}
	}
	return inventory.KindOther
}

// place sets the DN, the RDN, the parent and the first hop of the ancestry.
//
// A live object's parent is the entry's parent_guid, and an entry with none must be the head of this
// naming context (the writer derives "complete ancestry" from exactly that). A deleted or recycled
// object sits in the Deleted Objects container, which is not where it belongs: its parent is its
// lastKnownParent, or none.
func (m *Mapper) place(o *inventory.Observation, e *connectorv1.DirectoryEntry, set attrSet) error {
	d := e.GetDn().GetDisplayDn()
	if d == "" {
		return refuse("dn", CodeMissing)
	}
	if len(d) > maxDN {
		return refuse("dn", CodeTooLong)
	}
	parsed, err := dn.Parse(d, dn.Strict)
	if err != nil {
		return refuse("dn", CodeBadDN)
	}
	o.DN = parsed.String()
	o.RDN = rdnOf(parsed)
	if utf8.RuneCountInString(o.RDN) > maxRDN {
		return refuse("dn", CodeTooLong)
	}

	if o.State != inventory.ObjLive {
		lkp, present, err := dnValue(set, "lastKnownParent")
		if err != nil {
			return err
		}
		if present && lkp != nil && lkp.GetGuid() != nil {
			if o.Parent, err = entryGUID(lkp.Guid, "lastKnownParent"); err != nil {
				return err
			}
		}
	} else if e.GetParentGuid() != nil {
		if o.Parent, err = entryGUID(e.ParentGuid, "parentGuid"); err != nil {
			return err
		}
	} else if o.Object != m.nc {
		return refuse("parentGuid", CodeNCHead)
	}
	if o.Parent == o.Object {
		return refuse("parentGuid", CodeBadGUID)
	}
	// The one hop that needs no lookup: a child of the head has exactly the head for ancestry.
	if o.Parent != "" && o.Parent == m.nc && o.Object != m.nc {
		o.Ancestry = []inventory.GUID{m.nc}
	}
	return nil
}

// rdnOf is the first RDN of a parsed DN, rendered: the whole DN less its parent.
func rdnOf(d dn.DN) string {
	full, parent := d.String(), d.Parent().String()
	if parent == "" || len(parent) >= len(full) {
		return full
	}
	return full[:len(full)-len(parent)-1]
}

// principal reads the account-state inputs of users, inetOrgPersons, computers and gMSAs: the
// attributes the datasets derive locked, expired, enabled and activity states from.
func (m *Mapper) principal(out *Mapped, set attrSet) error {
	o := &out.Observation
	if !isPrincipal(o.Kind) || o.State != inventory.ObjLive {
		return nil
	}
	uac, _, has, err := int32Of(set, "userAccountControl")
	if err != nil {
		return err
	}
	if has {
		bits := int64(uint32(uac))
		o.UserAccountControl = &bits
		enabled := bits&0x2 == 0 // ACCOUNTDISABLE
		o.Enabled = &enabled
	}
	if n, _, has, err := int32Of(set, "primaryGroupID"); err != nil {
		return err
	} else if has {
		if n < 0 {
			return refuse("primaryGroupID", CodeRange)
		}
		v := int64(n)
		o.PrimaryGroupID = &v
	}
	for _, in := range []struct {
		attr  string
		never bool
		bit   inventory.InputsRead
		dst   *time.Time
	}{
		{"lockoutTime", false, inventory.ReadLockoutTime, &o.LockoutTime},
		{"pwdLastSet", false, inventory.ReadPwdLastSet, &o.PwdLastSet},
		{"accountExpires", true, inventory.ReadAccountExpires, &o.AccountExpires},
		{"lastLogonTimestamp", false, inventory.ReadLastLogonTimestamp, &o.LastLogonTimestamp},
	} {
		t, err := timeOf(set, in.attr, in.never)
		if err != nil {
			return err
		}
		if t.read {
			o.InputsRead |= in.bit
			*in.dst = t.t
		}
	}
	if a, ok := set.get("servicePrincipalName"); ok {
		vs, err := values(a, "servicePrincipalName")
		if err != nil {
			return err
		}
		has := len(vs) > 0
		o.HasSPN = &has
	}
	out.PrimaryGroup = m.primaryGroup(o)
	return nil
}

func isPrincipal(k inventory.Kind) bool {
	switch k {
	case inventory.KindUser, inventory.KindInetOrgPerson, inventory.KindComputer, inventory.KindGMSA:
		return true
	}
	return false
}

// primaryGroup resolves primaryGroupID to the group of that RID in the principal's own domain.
func (m *Mapper) primaryGroup(o *inventory.Observation) PrimaryGroupStatus {
	switch {
	case o.PrimaryGroupID == nil:
		return PrimaryGroupNotRead
	case len(o.SID) == 0:
		return PrimaryGroupNoSID
	case m.groups == nil:
		return PrimaryGroupNoResolver
	}
	gsid := slices.Clone(o.SID)
	if len(gsid) < 12 {
		return PrimaryGroupNoSID
	}
	// The group's SID is the principal's with its last sub-authority (the RID) replaced, little-endian.
	rid := uint32(*o.PrimaryGroupID)
	n := len(gsid)
	gsid[n-4], gsid[n-3], gsid[n-2], gsid[n-1] = byte(rid), byte(rid>>8), byte(rid>>16), byte(rid>>24)
	if _, err := sid.FromBytes(gsid); err != nil {
		return PrimaryGroupNoSID
	}
	g, ok := m.groups.GroupBySID(gsid)
	if !ok || g == "" || g == o.Object {
		return PrimaryGroupUnresolved
	}
	o.PrimaryGroup = g
	return PrimaryGroupResolved
}

// group reads groupType and the member values of a live group.
func (m *Mapper) group(out *Mapped, set attrSet) error {
	o := &out.Observation
	if o.Kind != inventory.KindGroup || o.State != inventory.ObjLive {
		return nil
	}
	if gt, _, has, err := int32Of(set, "groupType"); err != nil {
		return err
	} else if has {
		o.Facts.GroupType = &gt
	}
	a, ok := set.get("member")
	if !ok {
		return nil // not read: nothing is added and nothing is removed
	}
	if len(a.GetValues()) > maxMembers {
		return refuse("member", CodeTooMany)
	}
	seen := make(map[inventory.GUID]bool, len(a.GetValues()))
	for _, v := range a.GetValues() {
		d, isDN := v.GetValue().(*connectorv1.AttributeValue_Dn)
		if !isDN || d.Dn == nil {
			return refuse("member", CodeType)
		}
		if d.Dn.GetGuid() == nil {
			out.MembersUnresolved++
			continue
		}
		g, err := entryGUID(d.Dn.Guid, "member")
		if err != nil {
			return err
		}
		if g == o.Object {
			return refuse("member", CodeBadGUID)
		}
		if !seen[g] {
			seen[g] = true
			o.Members = append(o.Members, g)
		}
	}
	// Complete only when this entry holds the whole set: not a ranged slice, and every value named.
	r := a.GetRange()
	whole := r == nil || (r.GetStart() == 0 && r.GetTerminal())
	o.MembersComplete = a.GetComplete() && whole && out.MembersUnresolved == 0
	return nil
}

// bag fills Observation.Attributes with the generic attributes the datasets read from the JSON column,
// and lastKnownParent for a deleted object. Nothing else enters it.
func (m *Mapper) bag(o *inventory.Observation, set attrSet) error {
	bag := map[string]any{}
	for _, name := range []string{"mail", "company", "dNSHostName", "operatingSystem", "operatingSystemVersion"} {
		// dNSHostName's rangeUpper is 2048 (a computer's creator writes it); the others are at most 256.
		if s, present, err := text(set, name, maxDNSHostName); err != nil {
			return err
		} else if present && s != "" {
			bag[name] = s
		}
	}
	if err := searchIdentifiers(bag, set); err != nil {
		return err
	}
	if s, present, err := firstText(set, "description", 4096); err != nil {
		return err
	} else if present && s != "" {
		bag["description"] = s
	}
	if d, present, err := dnValue(set, "managedBy"); err != nil {
		return err
	} else if present && d != nil {
		s, err := cleanText("managedBy", d.DisplayDn, maxDN)
		if err != nil {
			return err
		}
		if s != "" {
			bag["managedBy"] = s
		}
	}
	if list, present, err := texts(set, "msDS-AllowedToDelegateTo", 1024); err != nil {
		return err
	} else if present {
		bag["msDS-AllowedToDelegateTo"] = list
	}
	if o.State != inventory.ObjLive {
		if d, present, err := dnValue(set, "lastKnownParent"); err != nil {
			return err
		} else if present && d != nil {
			s, err := cleanText("lastKnownParent", d.DisplayDn, maxDN)
			if err != nil {
				return err
			}
			if s != "" {
				bag["lastKnownParent"] = s
			}
		}
	}
	if len(bag) == 0 {
		return nil
	}
	if b, err := json.Marshal(bag, json.Deterministic(true)); err != nil || len(b) > maxBag {
		return refuse("attributes", CodeAttributesSize)
	}
	o.Attributes = bag
	return nil
}

// The search identifiers (T-1129, ADR-0011 rule 9). Single-valued text attributes and their schema
// rangeUpper (title 128, department 64, physicalDeliveryOfficeName 128, givenName 64, sn 64,
// employeeID 16, employeeNumber 512, mailNickname 64; the mapper allows a little more than the schema,
// and bounds the stored size, not the schema).
var searchTextAttrs = []struct {
	name string
	max  int
}{
	{"givenName", 256}, {"sn", 256}, {"title", 256}, {"department", 256}, {"physicalDeliveryOfficeName", 256},
	{"employeeID", 256}, {"employeeNumber", 512}, {"mailNickname", 256},
}

// maxSearchValues bounds how many values of a multi-valued search attribute are kept (proxyAddresses,
// servicePrincipalName, sIDHistory). The first values are kept; the rest are not searchable, so one
// object with thousands of SPNs cannot push its attribute bag over the store's size limit.
const maxSearchValues = 64

// searchIdentifiers adds the attributes universal search keys are built from to the bag. An attribute the
// entry does not carry adds nothing (not read), and a present-but-empty one adds nothing either.
// No secret or confidential attribute is read here (Test_closed_list_* pin the list).
func searchIdentifiers(bag map[string]any, set attrSet) error {
	for _, a := range searchTextAttrs {
		if s, present, err := firstText(set, a.name, a.max); err != nil {
			return err
		} else if present && s != "" {
			bag[a.name] = s
		}
	}
	for _, name := range []string{"proxyAddresses", "servicePrincipalName"} {
		list, present, err := texts(set, name, 1024)
		if err != nil {
			return err
		}
		list = slices.DeleteFunc(list, func(v string) bool { return v == "" })
		if present && len(list) > 0 {
			bag[name] = list[:min(len(list), maxSearchValues)]
		}
	}
	if a, ok := set.get("sIDHistory"); ok {
		vs, err := values(a, "sIDHistory")
		if err != nil {
			return err
		}
		var list []string
		for _, v := range vs {
			t, isSID := v.GetValue().(*connectorv1.AttributeValue_Sid)
			if !isSID {
				return refuse("sIDHistory", CodeType)
			}
			b, err := sidBytes(t.Sid, "sIDHistory")
			if err != nil {
				return err
			}
			parsed, err := sid.FromBytes(b)
			if err != nil {
				return refuse("sIDHistory", CodeBadSID)
			}
			list = append(list, parsed.String())
		}
		if len(list) > 0 {
			bag["sIDHistory"] = list[:min(len(list), maxSearchValues)]
		}
	}
	return nil
}

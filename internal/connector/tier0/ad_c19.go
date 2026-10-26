package tier0

import (
	"errors"
	"fmt"
	"sort"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/attr/sid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/directory/sd"
)

// C19: control of a Tier-0 object (TM-D27). Depth 1: the trustees of a takeover right on, and the
// owner of, a C1 or C13 group, a C1 account (krbtgt, krbtgt_<n>, RID 500), a DC computer object, the
// Domain Controllers OU and every container that directly holds a DC, and each GPO that C9 marks.
// The rights are read from each object's own live DACL, never inferred from SDProp (rule 3). C19 does
// not iterate (rule 6): a principal that is tier0 only through C19 makes none of its own controllers
// tier0, because the object list is fixed before anything is marked.

// c19Objects is what the earlier steps hand to c19.
type c19Objects struct {
	c1Groups []*ad.Entry // C1 groups
	accounts []*ad.Entry // C1 accounts and every krbtgt (C4)
	dcOU     dn.DN       // the Domain Controllers OU, by well-known GUID
	gpos     []dn.DN     // GPOs C9 marked
}

type c19Kind int

const (
	kGroup c19Kind = iota
	kAccount
	kDC
	kHolder // the DC OU and the containers that hold DC objects
	kGPO
)

type c19Target struct {
	ref  dn.ObjectRef
	kind c19Kind
}

// c19Attr is a schema attribute: its schemaIDGUID and the property set it belongs to, if any. An ACE
// that names either covers the attribute.
type c19Attr struct {
	id  guid.GUID
	set *guid.GUID
}

func (a c19Attr) named(g *guid.GUID) bool {
	return g != nil && (*g == a.id || (a.set != nil && *g == *a.set))
}

// c19Schema holds the GUIDs rule 2 needs, read from the schema and Extended-Rights container at
// snapshot time, never constants. Attributes that exist only on newer schemas (msDS-KeyCredentialLink,
// msDS-AllowedToActOnBehalfOfOtherIdentity) may be absent: no ACE can then name them. Every other
// lookup that fails fails the snapshot.
type c19Schema struct {
	attrs                 map[string]c19Attr
	classes               map[string]guid.GUID
	resetPassword, selfMb guid.GUID
}

var (
	c19Required = []string{"member", "unicodePwd", "servicePrincipalName", "userAccountControl", "gPLink", "gPOptions"}
	c19Optional = []string{"msDS-KeyCredentialLink", "msDS-AllowedToActOnBehalfOfOtherIdentity"}
	c19Classes  = []string{"computer", "organizationalUnit", "groupPolicyContainer"}
)

func (b *builder) c19Schema() (*c19Schema, error) {
	sc := &c19Schema{attrs: map[string]c19Attr{}, classes: map[string]guid.GUID{}}
	read := func(class, name string, optional bool) error {
		q := Query{Classes: []string{class}, Eq: []AttrEq{{Attr: "lDAPDisplayName", Value: name}}}
		var id *guid.GUID
		var set *guid.GUID
		err := b.d.Find(b.ctx, b.nm.Schema, ad.ScopeOneLevel, q, []string{"schemaIDGUID", "attributeSecurityGUID"}, func(e *ad.Entry) error {
			v := e.Raw("schemaIDGUID")
			if len(v) != 1 {
				return fmt.Errorf("tier0: %s schemaIDGUID unreadable", name)
			}
			g, err := guid.FromBytes(v[0])
			if err != nil {
				return fmt.Errorf("tier0: %s schemaIDGUID malformed", name)
			}
			id = &g
			if sv := e.Raw("attributeSecurityGUID"); len(sv) == 1 {
				sg, err := guid.FromBytes(sv[0])
				if err != nil {
					return fmt.Errorf("tier0: %s attributeSecurityGUID malformed", name)
				}
				set = &sg
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("tier0: schema object %s: %w", name, err)
		}
		if id == nil {
			if optional {
				return nil
			}
			return fmt.Errorf("tier0: schema object %s not found", name)
		}
		if class == "classSchema" {
			sc.classes[name] = *id
		} else {
			sc.attrs[name] = c19Attr{id: *id, set: set}
		}
		return nil
	}
	for _, n := range c19Required {
		if err := read("attributeSchema", n, false); err != nil {
			return nil, err
		}
	}
	for _, n := range c19Optional {
		if err := read("attributeSchema", n, true); err != nil {
			return nil, err
		}
	}
	for _, n := range c19Classes {
		if err := read("classSchema", n, false); err != nil {
			return nil, err
		}
	}
	rights, err := b.child(b.nm.Config, "CN=Extended-Rights")
	if err != nil {
		return nil, err
	}
	right := func(cn string) (guid.GUID, error) {
		var out *guid.GUID
		q := Query{Classes: []string{"controlAccessRight"}, Eq: []AttrEq{{Attr: "cn", Value: cn}}}
		err := b.d.Find(b.ctx, rights, ad.ScopeOneLevel, q, []string{"rightsGuid"}, func(e *ad.Entry) error {
			v := e.Strings("rightsGuid")
			if len(v) != 1 {
				return fmt.Errorf("tier0: extended right %s has no rightsGuid", cn)
			}
			g, err := guid.Parse(v[0])
			if err != nil {
				return fmt.Errorf("tier0: extended right %s rightsGuid malformed", cn)
			}
			out = &g
			return nil
		})
		if err != nil {
			return guid.GUID{}, fmt.Errorf("tier0: extended right %s: %w", cn, err)
		}
		if out == nil {
			return guid.GUID{}, fmt.Errorf("tier0: extended right %s not found", cn)
		}
		return *out, nil
	}
	if sc.resetPassword, err = right("User-Force-Change-Password"); err != nil {
		return nil, err
	}
	if sc.selfMb, err = right("Self-Membership"); err != nil {
		return nil, err
	}
	return sc, nil
}

// writes reports a WriteProperty ACE that covers one of the named attributes (rule 2: the attribute's
// own GUID or its property set).
func (sc *c19Schema) writes(a aceGrant, attrs ...string) bool {
	if a.mask&maskWriteProp == 0 {
		return false
	}
	for _, n := range attrs {
		if at, ok := sc.attrs[n]; ok && at.named(a.objectType) {
			return true
		}
	}
	return false
}

// common is rule 2's every-class list: WRITE_DAC, WRITE_OWNER, GENERIC_ALL, GENERIC_WRITE (generic
// and mapped bits) and an all-properties WriteProperty.
func (a aceGrant) c19Common() bool {
	if a.mask&(maskWriteDACL|maskWriteOwner|maskGenericAll|maskGenericWrite) != 0 {
		return true
	}
	return a.mask&maskWriteProp != 0 && a.objectType == nil
}

// takeover reports whether the ACE gives a takeover right on an object of this kind (rule 2 table).
func (sc *c19Schema) takeover(a aceGrant, k c19Kind) bool {
	if a.c19Common() {
		return true
	}
	allExt := a.mask&maskControlAcc != 0 && a.objectType == nil
	resetPwd := a.mask&maskControlAcc != 0 && a.objectType != nil && *a.objectType == sc.resetPassword
	switch k {
	case kGroup:
		return sc.writes(a, "member")
	case kAccount:
		return allExt || resetPwd ||
			sc.writes(a, "unicodePwd", "msDS-KeyCredentialLink", "servicePrincipalName", "userAccountControl")
	case kDC:
		return allExt || resetPwd ||
			sc.writes(a, "unicodePwd", "msDS-KeyCredentialLink", "msDS-AllowedToActOnBehalfOfOtherIdentity",
				"servicePrincipalName", "userAccountControl")
	case kHolder:
		if allExt || a.mask&sd.MaskDeleteChild != 0 || sc.writes(a, "gPLink", "gPOptions") {
			return true
		}
		if a.mask&sd.MaskCreateChild != 0 {
			if a.objectType == nil {
				return true
			}
			for _, c := range c19Classes {
				if sc.classes[c] == *a.objectType {
					return true
				}
			}
		}
	}
	return false
}

// selfMembership reports the Self-Membership validated write (rule 2, group row).
func (sc *c19Schema) selfMembership(a aceGrant) bool {
	return a.mask&sd.MaskSelf != 0 && (a.objectType == nil || *a.objectType == sc.selfMb)
}

// c19Targets resolves the objects handed over by the earlier steps, de-duplicated by reference.
func (b *builder) c19Targets() ([]c19Target, error) {
	var out []c19Target
	seen := map[string]bool{}
	add := func(ref dn.ObjectRef, k c19Kind, key string) {
		if !seen[key] {
			seen[key] = true
			out = append(out, c19Target{ref: ref, kind: k})
		}
	}
	addEntry := func(e *ad.Entry, k c19Kind) error {
		d, err := entryDN(e)
		if err != nil {
			return err
		}
		key, err := dnKey(d)
		if err != nil {
			return err
		}
		add(dn.DNRef(d), k, key)
		return nil
	}
	for _, e := range b.c19o.c1Groups {
		if err := addEntry(e, kGroup); err != nil {
			return nil, err
		}
	}
	for _, e := range b.c19o.accounts {
		if err := addEntry(e, kAccount); err != nil {
			return nil, err
		}
	}
	for _, g := range b.s.c13 { // C13 groups, found by RID, pinned GUID or name
		add(dn.GUIDRef(g), kGroup, "guid:"+g.String())
	}
	for _, d := range b.dcDNs {
		key, err := dnKey(d)
		if err != nil {
			return nil, err
		}
		add(dn.DNRef(d), kDC, key)
		if p := d.Parent(); p.Len() > 0 && !p.Equal(b.nm.Domain) {
			pk, err := dnKey(p)
			if err != nil {
				return nil, err
			}
			add(dn.DNRef(p), kHolder, pk)
		}
	}
	if b.c19o.dcOU.Len() > 0 {
		k, err := dnKey(b.c19o.dcOU)
		if err != nil {
			return nil, err
		}
		add(dn.DNRef(b.c19o.dcOU), kHolder, k)
	}
	for _, g := range b.c19o.gpos {
		k, err := dnKey(g)
		if err != nil {
			return nil, err
		}
		add(dn.DNRef(g), kGPO, k)
	}
	return out, nil
}

// sidSet collects SIDs once, in a stable order.
type sidSet struct {
	seen map[string]bool
	list []sid.SID
}

func (s *sidSet) add(x sid.SID) {
	if s.seen == nil {
		s.seen = map[string]bool{}
	}
	if !s.seen[x.String()] {
		s.seen[x.String()] = true
		s.list = append(s.list, x)
	}
}

func (s *sidSet) sorted() []sid.SID {
	sort.Slice(s.list, func(i, j int) bool { return s.list[i].String() < s.list[j].String() })
	return s.list
}

// c19IgnoredSID: Enterprise Read-only Domain Controllers holds a default ACE on DC objects (rule 4).
// SYSTEM, ENTERPRISE DOMAIN CONTROLLERS, SELF and Creator Owner are ignorableSID; C1 principals
// (including the Domain Controllers group) are skipped as already tier0. No other default is assumed.
var c19IgnoredSID = map[string]bool{"S-1-5-498": true}

func (b *builder) c19() error {
	targets, err := b.c19Targets()
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return nil
	}
	sc, err := b.c19Schema()
	if err != nil {
		return err
	}
	var main, self, owners sidSet
	for _, t := range targets {
		e, found, err := b.get(t.ref, []string{"objectGUID", "nTSecurityDescriptor"})
		if err != nil {
			return err
		}
		if !found || len(e.Raw("nTSecurityDescriptor")) != 1 {
			return errors.New("tier0: a Tier-0 object has no readable security descriptor")
		}
		d, aces, err := grantsOf(e.Raw("nTSecurityDescriptor")[0])
		if err != nil {
			return err
		}
		if !d.HasOwner {
			return errors.New("tier0: a Tier-0 object has no readable owner")
		}
		// OWNER RIGHTS and dSHeuristics character 29 are ignored on purpose (TM-D26 rule 3): the owner
		// is tier0.
		owners.add(d.Owner)
		for _, a := range aces {
			switch {
			case c19IgnoredSID[a.trustee.String()]:
			case sc.takeover(a, t.kind):
				main.add(a.trustee)
			case t.kind == kGroup && sc.selfMembership(a):
				self.add(a.trustee)
			}
		}
	}
	isC1 := func(o *ad.Entry) bool {
		g, err := o.GUID()
		return err == nil && b.s.bases[g.String()][C1]
	}
	if err := b.markPrincipalsSkip(main.sorted(), C19, isC1); err != nil {
		return err
	}
	if err := b.markPrincipalsSkip(owners.sorted(), C19, isC1); err != nil {
		return err
	}
	// Self-Membership lets a trustee add only itself, which changes nothing for one already tier0.
	// Evaluated last so the answer does not depend on the order of the objects.
	alreadyTier0 := func(o *ad.Entry) bool {
		g, err := o.GUID()
		return err == nil && len(b.s.bases[g.String()]) > 0
	}
	return b.markPrincipalsSkip(self.sorted(), C19, alreadyTier0)
}

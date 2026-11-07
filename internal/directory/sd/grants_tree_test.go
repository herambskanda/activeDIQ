package sd

import (
	"encoding/binary"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/attr/sid"
)

// The object-type tree of an attribute ask (connector-contract §5.9.4, MS-ADTS 5.1.3.3.3): the
// class is the root, the property set below it, the attribute a leaf. GUIDs are made up; the real
// ones arrive from the schema snapshot.
var (
	gClass    = mustGUID("c1a55000-0000-0000-0000-000000000001") // the object's class
	gSet      = mustGUID("5e700000-0000-0000-0000-000000000002") // attributeSecurityGuid of the attribute
	gAttr     = mustGUID("a77a0000-0000-0000-0000-000000000003") // the asked attribute
	gOtherSet = mustGUID("5e700000-0000-0000-0000-000000000004")
	gSibling  = mustGUID("a77a0000-0000-0000-0000-000000000005") // another attribute
	gOtherCls = mustGUID("c1a55000-0000-0000-0000-000000000006")
	gCtrl     = mustGUID("c0410000-0000-0000-0000-000000000007") // a control-access right
	gValid    = mustGUID("fa11d000-0000-0000-0000-000000000008") // a validated write
	gUnknown  = mustGUID("dead0000-0000-0000-0000-000000000009") // not in the snapshot
)

func treeCatalog() mapCatalog {
	return mapCatalog{*gClass: Class, *gSet: PropertySet, *gAttr: Attribute, *gOtherSet: PropertySet,
		*gSibling: Attribute, *gOtherCls: Class, *gCtrl: ControlAccess, *gValid: ValidatedWrite}
}

// anyKind encodes any GUID as an object ACE: the writer's catalog check is not under test here.
type anyKind struct{}

func (anyKind) Kind(guid.GUID) (RightKind, bool) { return Attribute, true }

type treeACE struct {
	deny      bool
	trustee   sid.SID
	obj       *guid.GUID
	flags     uint8
	inherited bool
}

func treeSD(t *testing.T, aces ...treeACE) SD {
	t.Helper()
	var list []ACE
	for _, x := range aces {
		a, err := encodeNew(NewACE{Deny: x.deny, Trustee: x.trustee, Mask: MaskReadProp, ObjectType: x.obj, Flags: x.flags}, anyKind{})
		if err != nil {
			t.Fatal(err)
		}
		if x.inherited {
			a.Raw[1] |= FlagInherited
			a.Flags |= FlagInherited
		}
		list = append(list, a)
	}
	size := aclHeaderLen
	for _, a := range list {
		size += len(a.Raw)
	}
	body := encodeDACLSD(0, 4, list, size)
	binary.LittleEndian.PutUint32(body[4:], uint32(len(body)))
	s, err := Decode(Raw(append(body, mustSID("S-1-5-18").Bytes()...)))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func treeAsk(mask uint32) Right {
	return Right{Mask: mask, Object: gAttr, Kind: Attribute, Tree: &ObjectTree{Class: gClass, Set: gSet, Catalog: treeCatalog()}}
}

func TestGrantsAttributeTree(t *testing.T) {
	au, other := mustSID("S-1-5-11"), mustSID("S-1-5-21-1-2-3-9999")
	user := mustSID("S-1-5-21-1-2-3-1105")
	p := PrincipalFromToken(user, []sid.SID{mustSID("S-1-1-0"), au})

	allow := func(trustee sid.SID, o *guid.GUID) treeACE { return treeACE{trustee: trustee, obj: o} }
	deny := func(trustee sid.SID, o *guid.GUID) treeACE { return treeACE{deny: true, trustee: trustee, obj: o} }

	cases := []struct {
		name string
		aces []treeACE
		want Decision
		why  string
	}{
		{"allow on the property set", []treeACE{allow(au, gSet)}, Yes, ""},
		{"allow on the attribute", []treeACE{allow(au, gAttr)}, Yes, ""},
		{"allow with no object type", []treeACE{allow(au, nil)}, Yes, ""},
		{"allow on the class GUID applies to the attribute", []treeACE{allow(au, gClass)}, Yes, ""},
		{"deny on the attribute before the set allow", []treeACE{deny(au, gAttr), allow(au, gSet)}, No, ""},
		{"deny on the set before a whole-object allow", []treeACE{deny(au, gSet), allow(au, nil)}, No, ""},
		{"deny on the class GUID before a set allow", []treeACE{deny(au, gClass), allow(au, gSet)}, No, ""},
		{"deny with no object type", []treeACE{deny(au, nil), allow(au, gSet)}, No, ""},
		{"allow on an unrelated set is ignored", []treeACE{allow(au, gOtherSet)}, No, "no_matching_ace"},
		{"deny on an unrelated set is ignored", []treeACE{deny(au, gOtherSet), allow(au, gSet)}, Yes, ""},
		{"ACE on a sibling attribute is ignored", []treeACE{deny(au, gSibling), allow(au, gSet)}, Yes, ""},
		{"ACE on another class is ignored", []treeACE{deny(au, gOtherCls), allow(au, gSet)}, Yes, ""},
		{"ACE on a control-access right is ignored", []treeACE{deny(au, gCtrl), allow(au, gSet)}, Yes, ""},
		{"ACE on a validated write is ignored", []treeACE{deny(au, gValid), allow(au, gSet)}, Yes, ""},
		{"deny the snapshot cannot place", []treeACE{deny(au, gUnknown), allow(au, gSet)}, Unknown, "object_type_unresolved"},
		{"allow the snapshot cannot place", []treeACE{allow(au, gUnknown)}, Unknown, "object_type_unresolved"},
		{"unplaceable ACE for a trustee outside the token", []treeACE{deny(other, gUnknown), allow(au, gSet)}, Yes, ""},
		{"unplaceable ACE after the answer is settled", []treeACE{allow(au, gSet), deny(au, gUnknown)}, Yes, ""},
		{"inherit-only ACE on the set is skipped", []treeACE{{trustee: au, obj: gSet, flags: FlagInheritOnly | FlagContainerInherit}}, No, "no_matching_ace"},
		{"inherited ACE on the set applies", []treeACE{{trustee: au, obj: gSet, inherited: true}}, Yes, ""},
		{"no ACE for the token", []treeACE{allow(other, gSet)}, No, "no_matching_ace"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := Grants(p, treeAsk(MaskReadProp), treeSD(t, c.aces...))
			if r.Decision != c.want || (c.why != "" && r.Why != c.why) {
				t.Fatalf("got %s (%s), want %s (%s)", r.Decision, r.Why, c.want, c.why)
			}
		})
	}
}

// Rules 5 and 6 of §5.9.4: a tree the snapshot cannot vouch for is Unknown whatever the DACL says,
// including a DACL that would otherwise answer Yes.
func TestGrantsAttributeTreeFailsClosed(t *testing.T) {
	au := mustSID("S-1-5-11")
	p := PrincipalFromToken(mustSID("S-1-5-21-1-2-3-1105"), []sid.SID{au})
	s := treeSD(t, treeACE{trustee: au, obj: nil})
	cat := treeCatalog()
	cases := []struct {
		name string
		tree *ObjectTree
		why  string
	}{
		{"missing attributeSecurityGuid (DefaultSchema)", &ObjectTree{Class: gClass, Catalog: cat}, "property_set_unknown"},
		{"attributeSecurityGuid not in the snapshot", &ObjectTree{Class: gClass, Set: gUnknown, Catalog: cat}, "property_set_unknown"},
		{"attributeSecurityGuid is not a property set", &ObjectTree{Class: gClass, Set: gSibling, Catalog: cat}, "property_set_unknown"},
		{"class missing (objectClass not returned)", &ObjectTree{Set: gSet, Catalog: cat}, "class_unknown"},
		{"class not in the snapshot", &ObjectTree{Class: gUnknown, Set: gSet, Catalog: cat}, "class_unknown"},
		{"class GUID names an attribute", &ObjectTree{Class: gSibling, Set: gSet, Catalog: cat}, "class_unknown"},
		{"no catalog", &ObjectTree{Class: gClass, Set: gSet}, "catalog_missing"},
		{"set equals class", &ObjectTree{Class: gSet, Set: gSet, Catalog: mapCatalog{*gSet: Class, *gAttr: Attribute}}, "property_set_unknown"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := Right{Mask: MaskReadProp, Object: gAttr, Kind: Attribute, Tree: c.tree}
			if got := Grants(p, r, s); got.Decision != Unknown || got.Why != c.why {
				t.Fatalf("got %s (%s), want unknown (%s)", got.Decision, got.Why, c.why)
			}
		})
	}
	t.Run("attribute not in the snapshot", func(t *testing.T) {
		r := treeAsk(MaskReadProp)
		r.Object = gUnknown
		if got := Grants(p, r, s); got.Decision != Unknown || got.Why != "attribute_unknown" {
			t.Fatalf("got %s (%s)", got.Decision, got.Why)
		}
	})
	t.Run("tree on a non-attribute ask", func(t *testing.T) {
		r := treeAsk(MaskReadProp)
		r.Kind = PropertySet
		if got := Grants(p, r, s); got.Decision != Unknown {
			t.Fatalf("got %s", got.Decision)
		}
	})
	t.Run("tree with a non-property mask", func(t *testing.T) {
		if got := Grants(p, treeAsk(MaskReadControl), s); got.Decision != Unknown || got.Why != "mask_not_property" {
			t.Fatalf("got %s (%s)", got.Decision, got.Why)
		}
	})
	t.Run("no tree keeps the old answer", func(t *testing.T) {
		s2 := treeSD(t, treeACE{trustee: au, obj: gSet})
		r := Right{Mask: MaskReadProp, Object: gAttr, Kind: Attribute}
		if got := Grants(p, r, s2); got.Decision != Unknown || got.Why != "property_set_unresolved" {
			t.Fatalf("got %s (%s)", got.Decision, got.Why)
		}
	})
}

// SELF and OWNER RIGHTS on a property set keep their rules inside the tree.
func TestGrantsAttributeTreeSelf(t *testing.T) {
	user := mustSID("S-1-5-21-1-2-3-1105")
	self := treeSD(t, treeACE{trustee: sidSelf, obj: gSet})
	p := PrincipalFromToken(user, []sid.SID{mustSID("S-1-1-0")})
	if got := Grants(p, treeAsk(MaskReadProp), self); got.Decision != Unknown {
		t.Fatalf("SELF without object SID: %s (%s)", got.Decision, got.Why)
	}
	if got := Grants(p.WithObjectSID(user), treeAsk(MaskReadProp), self); got.Decision != Yes {
		t.Fatalf("SELF on own object: %s (%s)", got.Decision, got.Why)
	}
	if got := Grants(p.WithObjectSID(mustSID("S-1-5-21-1-2-3-2000")), treeAsk(MaskReadProp), self); got.Decision != No {
		t.Fatalf("SELF on another object: %s (%s)", got.Decision, got.Why)
	}
}

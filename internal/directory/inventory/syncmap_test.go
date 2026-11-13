package inventory_test

import (
	"fmt"
	"testing"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	dirsync "github.com/skenzeriq/activediq/internal/directory/sync"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// T-1189: what directory/sync maps from connector entries is accepted whole by the real writer, and
// the stored rows say what the entries said. Real PostgreSQL; the entries are connector messages.

func rfc(n byte) *connectorv1.Guid {
	b := []byte{0xbb, 0xbb, 0xbb, 0xbb, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, n}
	return &connectorv1.Guid{Value: b}
}

func guidOf(n byte) string { return fmt.Sprintf("bbbbbbbb-0000-4000-8000-0000000000%02x", n) }

func ent(n byte, dn string, parent *connectorv1.Guid, as ...*connectorv1.Attribute) *connectorv1.DirectoryEntry {
	return &connectorv1.DirectoryEntry{ObjectGuid: rfc(n), Dn: &connectorv1.DnValue{DisplayDn: dn}, ParentGuid: parent, Attributes: as}
}

func at1(name string, vs ...*connectorv1.AttributeValue) *connectorv1.Attribute {
	return &connectorv1.Attribute{Name: name, Values: vs, Complete: true}
}

func tv(s string) *connectorv1.AttributeValue {
	return &connectorv1.AttributeValue{Value: &connectorv1.AttributeValue_Text{Text: s}}
}

func iv(n int32) *connectorv1.AttributeValue {
	return &connectorv1.AttributeValue{Value: &connectorv1.AttributeValue_Int32Value{Int32Value: n}}
}

func dv(g *connectorv1.Guid) *connectorv1.AttributeValue {
	return &connectorv1.AttributeValue{Value: &connectorv1.AttributeValue_Dn{Dn: &connectorv1.DnValue{DisplayDn: "CN=m,DC=lab,DC=test", Guid: g}}}
}

func classes1(cs ...string) *connectorv1.Attribute {
	a := &connectorv1.Attribute{Name: "objectClass", Complete: true}
	for _, c := range cs {
		a.Values = append(a.Values, tv(c))
	}
	return a
}

func Test_mapped_entries_are_accepted_by_populate(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		userSID := &connectorv1.AttributeValue{Value: &connectorv1.AttributeValue_Sid{Sid: &connectorv1.Sid{Value: []byte{
			1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 0x51, 0x04, 0, 0}}}}
		pwd := &connectorv1.AttributeValue{Value: &connectorv1.AttributeValue_Time{Time: &connectorv1.TimeValue{
			Kind: &connectorv1.TimeValue_At{At: timestamppb.New(t2)}}}}
		never := &connectorv1.AttributeValue{Value: &connectorv1.AttributeValue_Time{Time: &connectorv1.TimeValue{
			Kind: &connectorv1.TimeValue_Sentinel{Sentinel: connectorv1.TimeSentinel_TIME_SENTINEL_MAX}}}}

		const head, ouN, userN, compN, grpN, delN = 1, 2, 3, 4, 5, 6
		m, err := dirsync.NewMapper(dirsync.Config{NC: inventory.GUID(guidOf(head))})
		if err != nil {
			t.Fatal(err)
		}
		entries := []*connectorv1.DirectoryEntry{
			ent(head, "DC=lab,DC=test", nil, classes1("top", "domain", "domainDNS")),
			ent(ouN, "OU=Staff,DC=lab,DC=test", rfc(head), classes1("top", "organizationalUnit")),
			ent(userN, `CN=Raman\, Priya,OU=Staff,DC=lab,DC=test`, rfc(ouN), classes1("top", "person", "organizationalPerson", "user"),
				at1("sAMAccountName", tv("praman")), at1("objectSid", userSID), at1("userAccountControl", iv(0x200)),
				at1("pwdLastSet", pwd), at1("accountExpires", never), at1("lockoutTime")),
			ent(compN, "CN=WS1,OU=Staff,DC=lab,DC=test", rfc(ouN), classes1("top", "person", "organizationalPerson", "user", "computer"),
				at1("dNSHostName", tv("ws1.lab.test"))),
			ent(grpN, "CN=Team,OU=Staff,DC=lab,DC=test", rfc(ouN), classes1("top", "group"), at1("groupType", iv(-2147483646)),
				at1("member", dv(rfc(userN)), dv(rfc(compN)), dv(rfc(ouN)))),
			ent(delN, `CN=Gone\0ADEL:`+guidOf(delN)+",CN=Deleted Objects,DC=lab,DC=test", rfc(99), classes1("top", "contact"),
				at1("isDeleted", &connectorv1.AttributeValue{Value: &connectorv1.AttributeValue_Boolean{Boolean: true}}),
				at1("lastKnownParent", &connectorv1.AttributeValue{Value: &connectorv1.AttributeValue_Dn{Dn: &connectorv1.DnValue{DisplayDn: "OU=Staff,DC=lab,DC=test", Guid: rfc(ouN)}}})),
		}
		var obs []inventory.Observation
		for _, en := range entries {
			got, err := m.Map(en)
			if err != nil {
				t.Fatalf("Map: %v", err)
			}
			o := got.Observation
			// The chain below a child of the head is the cycle driver's: it knows the parents it stored first.
			if o.Parent == inventory.GUID(guidOf(ouN)) && o.State == inventory.ObjLive {
				o.Ancestry = []inventory.GUID{inventory.GUID(guidOf(ouN)), inventory.GUID(guidOf(head))}
			}
			obs = append(obs, o)
		}
		res, err := e.populate(t, e.adA, t2, obs...)
		if err != nil {
			t.Fatalf("Populate refused the mapped batch: %v", err)
		}
		if res.Inserted != 6 || res.Members != 3 {
			t.Errorf("populated %+v", res)
		}
		if n := e.count(t, `SELECT count(*) FROM public.directory_objects WHERE ancestry_complete`); n != 5 {
			t.Errorf("%d rows with complete ancestry, want 5 (head, OU, user, computer, group; the tombstone has no chain)", n)
		}
		if n := e.count(t, `SELECT count(*) FROM public.directory_objects WHERE object_guid = $1::uuid AND kind = 'user' AND user_account_control = 512
			AND enabled AND inputs_read = 7 AND account_expires IS NULL AND pwd_last_set IS NOT NULL AND lockout_time IS NULL`, guidOf(userN)); n != 1 {
			t.Errorf("user row does not say what the entry said")
		}
		if n := e.count(t, `SELECT count(*) FROM public.directory_objects WHERE object_guid = $1::uuid AND state = 'deleted' AND parent_guid = $2::uuid AND NOT ancestry_complete`, guidOf(delN), guidOf(ouN)); n != 1 {
			t.Errorf("deleted row keeps its lastKnownParent and is out of scope")
		}
		if n := e.count(t, `SELECT count(*) FROM public.links WHERE source_guid = $1::uuid AND link_attr = 'member' AND state = 'active'`, guidOf(grpN)); n != 3 {
			t.Errorf("%d member edges, want 3", n)
		}
	})
}

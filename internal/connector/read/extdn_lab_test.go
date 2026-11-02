//go:build lab

package read_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/skenzeriq/activediq/internal/directory/attr/sid"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// T-1202: member DnValues carry the target's objectGUID (RFC 4122 order) and objectSid, taken from
// the extended-DN control, on ScopedSearch and on Read, against the Samba lab. Whether a Windows DC
// returns the same together with member;range= is a Windows-lab check (see the ticket note).
func TestLabMemberEdgesCarryGuidAndSid(t *testing.T) {
	l := newSearchLab(t)
	ou := "OU=t1202" + l.stamp + "," + labDom
	t.Cleanup(func() { l.delTree(ou) })
	l.add(t, ou, map[string][]string{"objectClass": {"top", "organizationalUnit"}})
	userObj := []string{"top", "person", "organizationalPerson", "user"}
	names := []string{`Müller\, A` + l.stamp, "plain" + l.stamp, "third" + l.stamp}
	var members []string
	for i, cn := range names {
		dn := "CN=" + cn + "," + ou
		l.add(t, dn, map[string][]string{"objectClass": userObj, "sAMAccountName": {"t1202u" + string(rune('a'+i)) + l.stamp}})
		members = append(members, dn)
	}
	nested := "CN=nested," + ou
	l.add(t, nested, map[string][]string{"objectClass": {"top", "group"}, "sAMAccountName": {"t1202n" + l.stamp}})
	members = append(members, nested)
	grp := "CN=grp," + ou
	l.add(t, grp, map[string][]string{"objectClass": {"top", "group"}, "sAMAccountName": {"t1202g" + l.stamp}, "member": members})

	// Reference identities straight from the admin connection.
	type ident struct {
		guid []byte
		sid  []byte
	}
	want := map[string]ident{}
	for _, dn := range members {
		r, err := l.adm.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"objectSid"}, nil))
		if err != nil || len(r.Entries) != 1 {
			t.Fatalf("admin read %s: %v", dn, err)
		}
		id := ident{guid: l.guid(t, dn).GetValue()}
		if b := r.Entries[0].GetRawAttributeValue("objectSid"); len(b) > 0 {
			s, err := sid.FromBytes(b)
			if err != nil {
				t.Fatal(err)
			}
			id.sid = s.Bytes()
		}
		want[strings.ToLower(dn)] = id
	}

	check := func(what string, attrs []*connectorv1.Attribute) {
		t.Helper()
		var vals []*connectorv1.AttributeValue
		for _, a := range attrs {
			if a.GetName() == "member" {
				vals = a.GetValues()
			}
		}
		if len(vals) != len(members) {
			t.Fatalf("%s: %d members, want %d", what, len(vals), len(members))
		}
		for _, v := range vals {
			d := v.GetDn()
			w, ok := want[strings.ToLower(d.GetDisplayDn())]
			if !ok {
				t.Errorf("%s: unexpected member %q (display_dn must be the plain DN)", what, d.GetDisplayDn())
				continue
			}
			if !bytes.Equal(d.GetGuid().GetValue(), w.guid) {
				t.Errorf("%s: %s guid %x, want %x", what, d.GetDisplayDn(), d.GetGuid().GetValue(), w.guid)
			}
			if !bytes.Equal(d.GetSid().GetValue(), w.sid) {
				t.Errorf("%s: %s sid %x, want %x", what, d.GetDisplayDn(), d.GetSid().GetValue(), w.sid)
			}
		}
	}

	gOU := l.guid(t, ou)
	got, done, err := rpc(t, l.client, l.request(gOU, connectorv1.SearchDepth_SEARCH_DEPTH_ONE_LEVEL, "group", "member", "cn", "distinguishedName"))
	if err != nil || !done {
		t.Fatalf("search: done=%v err=%v", done, err)
	}
	ge := got[string(l.guid(t, grp).GetValue())]
	if ge == nil {
		t.Fatal("group not returned")
	}
	if strings.HasPrefix(ge.GetDn().GetDisplayDn(), "<") {
		t.Errorf("entry dn must stay plain: %q", ge.GetDn().GetDisplayDn())
	}
	check("search", ge.GetAttributes())
	for _, a := range ge.GetAttributes() { // distinguishedName is DN-syntax too: it must still be the plain DN
		if a.GetName() == "distinguishedname" && !strings.EqualFold(a.GetValues()[0].GetDn().GetDisplayDn(), grp) {
			t.Errorf("distinguishedName %q", a.GetValues()[0].GetDn().GetDisplayDn())
		}
	}

	ms, err := collect(t, l.client, &connectorv1.ReadRequest{
		Connection: &connectorv1.ConnectionRef{ConnectionId: "c1", DirectoryIdentity: l.ident},
		Guid:       l.guid(t, grp), Attributes: []string{"member"}})
	if err != nil {
		t.Fatal(err)
	}
	check("read", ms[0].GetHeader().GetEntry().GetAttributes())
}

// A member that is a foreign-domain principal: Samba creates a ForeignSecurityPrincipal. Whatever the
// DC supplies is passed on and nothing more: the SID is the foreign one, never a guess.
func TestLabForeignMemberKeepsOnlyWhatTheDCSupplies(t *testing.T) {
	l := newSearchLab(t)
	ou := "OU=t1202f" + l.stamp + "," + labDom
	t.Cleanup(func() { l.delTree(ou) })
	l.add(t, ou, map[string][]string{"objectClass": {"top", "organizationalUnit"}})
	grp := "CN=fgrp," + ou
	const foreignSID = "S-1-5-21-111111111-222222222-333333333-1999"
	l.add(t, grp, map[string][]string{"objectClass": {"top", "group"}, "sAMAccountName": {"t1202f" + l.stamp}})
	m := ldap.NewModifyRequest(grp, nil)
	m.Add("member", []string{"<SID=" + foreignSID + ">"})
	if err := l.adm.Modify(m); err != nil {
		t.Skipf("this Samba does not create a foreign security principal from a SID member: %v", err)
	}
	ms, err := collect(t, l.client, &connectorv1.ReadRequest{
		Connection: &connectorv1.ConnectionRef{ConnectionId: "c1", DirectoryIdentity: l.ident},
		Guid:       l.guid(t, grp), Attributes: []string{"member"}})
	if err != nil {
		t.Fatal(err)
	}
	vals := ms[0].GetHeader().GetEntry().GetAttributes()[0].GetValues()
	if len(vals) != 1 {
		t.Fatalf("%d members", len(vals))
	}
	d := vals[0].GetDn()
	want, err := sid.Parse(foreignSID)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("foreign member: dn=%q guid=%x sid=%x", d.GetDisplayDn(), d.GetGuid().GetValue(), d.GetSid().GetValue())
	if d.GetSid() != nil && !bytes.Equal(d.GetSid().GetValue(), want.Bytes()) {
		t.Errorf("sid %x, want %x or unset", d.GetSid().GetValue(), want.Bytes())
	}
	if d.GetDisplayDn() == "" || strings.HasPrefix(d.GetDisplayDn(), "<") {
		t.Errorf("display_dn %q", d.GetDisplayDn())
	}
}

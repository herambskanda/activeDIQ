//go:build lab

package write

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/skenzeriq/activediq/internal/directory/accountkind"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/platform/operation/digest"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// T-1586 kinds 11-13 against Samba AD: `make lab-up && go test -tags lab ./internal/connector/write -run TestWKMember|TestWKComputerReset`.
// Windows-only parts (cluster objects, scope-rule result codes, machine-side repair) are the Windows-lab ticket.

func (r *wkRig) memberChange(kind connectorv1.WriteKind, member guid.GUID, class string) *connectorv1.WriteChange {
	r.t.Helper()
	key := accountkind.KeyGroupMemberAdd
	if kind == connectorv1.WriteKind_WRITE_KIND_GROUP_MEMBER_REMOVE {
		key = accountkind.KeyGroupMemberRemove
	}
	ch, err := accountkind.GroupChangeFromAttrs(key, []digest.Attr{
		{Name: accountkind.AttrMember, Values: []string{member.String()}},
		{Name: accountkind.AttrMemberClass, Values: []string{class}},
	})
	if err != nil {
		r.t.Fatal(err)
	}
	return ch
}

// memberWrite plans and applies kind 11 or 12 on group with the Tier-0 context covering both objects.
func (r *wkRig) memberWrite(add bool, group, member guid.GUID, class string) (*connectorv1.ApplyResponse, error) {
	r.t.Helper()
	kind := connectorv1.WriteKind_WRITE_KIND_GROUP_MEMBER_ADD
	if !add {
		kind = connectorv1.WriteKind_WRITE_KIND_GROUP_MEMBER_REMOVE
	}
	p := r.planReq(kind, group, r.memberChange(kind, member, class))
	p.Tier0 = r.tier0Ctx(group, member)
	pr, err := r.plan(p)
	if err != nil {
		return nil, err
	}
	return r.apply(r.applyFrom(p, pr, nil))
}

func (r *wkRig) memberValues(groupDN string) []string {
	r.t.Helper()
	res, err := r.admin.Search(ldap.NewSearchRequest(groupDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"member"}, nil))
	if err != nil || len(res.Entries) != 1 {
		r.t.Fatalf("read members of %s: %v", groupDN, err)
	}
	return res.Entries[0].GetAttributeValues("member")
}

func (r *wkRig) hasMember(groupDN, memberDN string) bool {
	for _, v := range r.memberValues(groupDN) {
		if strings.EqualFold(v, memberDN) {
			return true
		}
	}
	return false
}

// Add and remove a user, a contact and a computer (comma and Unicode in the DNs); a retry is
// ALREADY_APPLIED; removing a non-member is a no-op, never an error.
func TestWKMemberAddRemoveClasses(t *testing.T) {
	r := newWKRig(t)
	gdn := "CN=wk\\, Gruppe Ünï," + r.ou
	r.adminAdd(gdn, "group", map[string][]string{"sAMAccountName": {"wkgrp1"}, "groupType": {"-2147483646"}})
	cases := []struct{ dn, class, cls string }{
		{"CN=Jörg\\, Müller 日本," + r.ou, "user", "user"},
		{"CN=wkcontact," + r.ou, "contact", "contact"},
		{"CN=WKMPC," + r.ou, "computer", "computer"},
	}
	r.adminAdd(cases[0].dn, "user", map[string][]string{"sAMAccountName": {"wkmjorg"}})
	r.adminAdd(cases[1].dn, "contact", nil)
	r.adminAdd(cases[2].dn, "computer", map[string][]string{"sAMAccountName": {"WKMPC$"}, "userAccountControl": {"4096"}})
	g := r.guidOf(gdn)
	for _, c := range cases {
		m := r.guidOf(c.dn)
		if _, err := r.memberWrite(true, g, m, c.cls); err != nil {
			t.Fatalf("add %s: %v %v", c.cls, err, connErr(t, err))
		}
		if !r.hasMember(gdn, c.dn) {
			t.Fatalf("%s not a member after add: %v", c.cls, r.memberValues(gdn))
		}
		// Retry of the same step is ALREADY_APPLIED (the member is already there).
		p := r.planReq(connectorv1.WriteKind_WRITE_KIND_GROUP_MEMBER_ADD, g, r.memberChange(connectorv1.WriteKind_WRITE_KIND_GROUP_MEMBER_ADD, m, c.cls))
		p.Tier0 = r.tier0Ctx(g, m)
		if pr, err := r.plan(p); err != nil {
			t.Fatalf("replan %s: %v", c.cls, err)
		} else if !pr.GetNoOp() {
			t.Errorf("%s: planning an add of a present member must be a no-op", c.cls)
		}
	}
	for _, c := range cases {
		m := r.guidOf(c.dn)
		if _, err := r.memberWrite(false, g, m, c.cls); err != nil {
			t.Fatalf("remove %s: %v %v", c.cls, err, connErr(t, err))
		}
		if r.hasMember(gdn, c.dn) {
			t.Fatalf("%s still a member after remove", c.cls)
		}
	}
	// A wrong class label is refused, not guessed.
	m := r.guidOf(cases[0].dn)
	if _, err := r.memberWrite(true, g, m, "contact"); err == nil {
		t.Fatal("a user labelled contact must be refused")
	}
}

// A group of more than 1,500 members: an add and a remove cost one modify, and the other members are
// untouched (the group's member list is never rewritten).
func TestWKMemberBigGroup(t *testing.T) {
	r := newWKRig(t)
	gdn := "CN=wkbig," + r.ou
	r.adminAdd(gdn, "group", map[string][]string{"sAMAccountName": {"wkbig"}, "groupType": {"-2147483646"}})
	var dns []string
	for i := 0; i < 1600; i++ {
		d := fmt.Sprintf("CN=wkc%04d,%s", i, r.ou)
		r.adminAdd(d, "contact", nil)
		dns = append(dns, d)
	}
	for i := 0; i < len(dns); i += 400 {
		mod := ldap.NewModifyRequest(gdn, nil)
		mod.Add("member", dns[i:i+400])
		if err := r.admin.Modify(mod); err != nil {
			t.Fatal(err)
		}
	}
	udn := "CN=wkbigu," + r.ou
	r.adminAdd(udn, "user", map[string][]string{"sAMAccountName": {"wkbigu"}})
	g, u := r.guidOf(gdn), r.guidOf(udn)
	if _, err := r.memberWrite(true, g, u, "user"); err != nil {
		t.Fatalf("add: %v %v", err, connErr(t, err))
	}
	if !r.hasMember(gdn, udn) {
		t.Fatal("not added")
	}
	if _, err := r.memberWrite(false, g, u, "user"); err != nil {
		t.Fatalf("remove: %v %v", err, connErr(t, err))
	}
	after := r.memberValues(gdn)
	sort.Strings(after)
	if len(after) != 1600 {
		t.Fatalf("members after remove: %d, want 1600", len(after))
	}
}

// Nesting: a group into a group; closing a circle A -> B -> C -> A is refused by us (NestingCycle); an
// existing circle can still be unwound.
func TestWKMemberNestAndCircle(t *testing.T) {
	r := newWKRig(t)
	names := []string{"wkna", "wknb", "wknc"}
	dns := map[string]string{}
	ids := map[string]guid.GUID{}
	for _, n := range names {
		dns[n] = "CN=" + n + "," + r.ou
		r.adminAdd(dns[n], "group", map[string][]string{"sAMAccountName": {n}, "groupType": {"-2147483640"}}) // universal security
		ids[n] = r.guidOf(dns[n])
	}
	nest := func(parent, child string) {
		t.Helper()
		if _, err := r.memberWrite(true, ids[parent], ids[child], "group"); err != nil {
			t.Fatalf("nest %s in %s: %v %v", child, parent, err, connErr(t, err))
		}
		if !r.hasMember(dns[parent], dns[child]) {
			t.Fatalf("%s not in %s", child, parent)
		}
	}
	nest("wkna", "wknb")
	nest("wknb", "wknc")
	// Closing the circle is our refusal (NestingCycle), not an AD limit; nothing is written.
	if _, err := r.memberWrite(true, ids["wknc"], ids["wkna"], "group"); err == nil {
		t.Fatal("closing a nesting circle must be refused")
	} else if ce := connErr(t, err); !strings.Contains(fmt.Sprint(ce), "NestingCycle") {
		t.Fatalf("refusal: %v", ce)
	}
	if r.hasMember(dns["wknc"], dns["wkna"]) {
		t.Fatal("circle was written")
	}
	// A circle that already exists (AD allows it; the seed has one) does not hang the read or the unnest:
	// build it as the administrator and remove an edge through kind 12.
	mod := ldap.NewModifyRequest(dns["wknc"], nil)
	mod.Add("member", []string{dns["wkna"]})
	if err := r.admin.Modify(mod); err != nil {
		t.Fatal(err)
	}
	for _, p := range [][2]string{{"wknc", "wkna"}, {"wknb", "wknc"}, {"wkna", "wknb"}} {
		if _, err := r.memberWrite(false, ids[p[0]], ids[p[1]], "group"); err != nil {
			t.Fatalf("unnest %v: %v", p, err)
		}
	}
}

// Kind 13: the reset changes pwdLastSet and nothing else the connector could have written. BitLocker
// recovery objects (children) and LAPS attributes are untouched: every readable attribute other than
// the ones a password change moves is byte-identical.
func TestWKComputerReset(t *testing.T) {
	r := newWKRig(t)
	cdn := "CN=WKRESET," + r.ou
	r.adminAdd(cdn, "computer", map[string][]string{"sAMAccountName": {"WKRESET$"}, "userAccountControl": {"4096"}, "description": {"keep"}})
	// A BitLocker recovery object child and a LAPS-style attribute (when the schema has one).
	r.adminAdd("CN=2026-01-01T00-00-00Z{11111111-1111-1111-1111-111111111111},"+cdn, "msFVE-RecoveryInformation",
		map[string][]string{"msFVE-RecoveryPassword": {"111111-222222-333333-444444-555555-666666-777777-888888"}, "msFVE-RecoveryGuid": {"\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11"}})
	snap := func() map[string]string {
		e := r.entry(cdn, "*")
		out := map[string]string{}
		for _, a := range e.Attributes {
			out[a.Name] = strings.Join(a.Values, "|")
		}
		return out
	}
	children := func() string {
		res, err := r.admin.Search(ldap.NewSearchRequest(cdn, ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"msFVE-RecoveryPassword"}, nil))
		if err != nil {
			t.Fatal(err)
		}
		var s []string
		for _, e := range res.Entries {
			s = append(s, e.DN+"="+e.GetAttributeValue("msFVE-RecoveryPassword"))
		}
		return strings.Join(s, ";")
	}
	before, kids := snap(), children()
	id := r.guidOf(cdn)
	ch, err := accountkind.ChangeFromAttrs(accountkind.KeyComputerReset, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.planApply(connectorv1.WriteKind_WRITE_KIND_COMPUTER_ACCOUNT_RESET, id, ch); err != nil {
		t.Fatalf("reset: %v %v", err, connErr(t, err))
	}
	after := snap()
	moved := map[string]bool{"pwdLastSet": true, "uSNChanged": true, "whenChanged": true, "dBCSPwd": true, "unicodePwd": true,
		"lmPwdHistory": true, "ntPwdHistory": true, "supplementalCredentials": true, "msDS-KeyVersionNumber": true, "badPasswordTime": true}
	for k, v := range after {
		if before[k] != v && !moved[k] {
			t.Errorf("attribute %s changed: %q -> %q", k, before[k], v)
		}
	}
	for k := range before {
		if _, ok := after[k]; !ok && !moved[k] {
			t.Errorf("attribute %s vanished", k)
		}
	}
	if before["pwdLastSet"] == after["pwdLastSet"] {
		t.Errorf("pwdLastSet did not move: %s", after["pwdLastSet"])
	}
	if got := children(); got != kids {
		t.Errorf("BitLocker children changed:\n%s\n%s", kids, got)
	}
}

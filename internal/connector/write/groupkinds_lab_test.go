//go:build lab

package write

import (
	"fmt"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// CC-WK-45..62 (kinds 11-13) against Samba AD: `make lab-up && go test -tags lab ./internal/connector/write -run TestWKG`.
// The Windows halves, CC-WK-59 (cluster objects) and the proxy-log assertions are not covered here.

const (
	kAdd  = connectorv1.WriteKind_WRITE_KIND_GROUP_MEMBER_ADD
	kRem  = connectorv1.WriteKind_WRITE_KIND_GROUP_MEMBER_REMOVE
	kComp = connectorv1.WriteKind_WRITE_KIND_COMPUTER_ACCOUNT_RESET

	clsContact = connectorv1.DirectoryObjectClass_DIRECTORY_OBJECT_CLASS_CONTACT
)

func addChange(m guid.GUID, c connectorv1.DirectoryObjectClass) *connectorv1.WriteChange {
	return &connectorv1.WriteChange{Change: &connectorv1.WriteChange_GroupMemberAdd{GroupMemberAdd: &connectorv1.GroupMemberAdd{Member: toWire(m), MemberClass: c}}}
}

func remChange(m guid.GUID, c connectorv1.DirectoryObjectClass) *connectorv1.WriteChange {
	return &connectorv1.WriteChange{Change: &connectorv1.WriteChange_GroupMemberRemove{GroupMemberRemove: &connectorv1.GroupMemberRemove{Member: toWire(m), MemberClass: c}}}
}

func (r *wkRig) mkUser(name string) string {
	d := "CN=" + name + "," + r.ou
	r.adminAdd(d, "user", map[string][]string{"sAMAccountName": {name}})
	return d
}

func (r *wkRig) mkGroup(name string, extra map[string][]string) string {
	d := "CN=" + name + "," + r.ou
	a := map[string][]string{"sAMAccountName": {name}}
	for k, v := range extra {
		a[k] = v
	}
	r.adminAdd(d, "group", a)
	return d
}

func (r *wkRig) mkComputer(name string) string {
	d := "CN=" + name + "," + r.ou
	r.adminAdd(d, "computer", map[string][]string{"sAMAccountName": {name + "$"}, "userAccountControl": {"4096"}})
	return d
}

func (r *wkRig) memberOf(member string) []string {
	return r.entry(member, "memberOf").GetAttributeValues("memberOf")
}

func (r *wkRig) isMember(member, group string) bool {
	for _, v := range r.memberOf(member) {
		if strings.EqualFold(v, group) {
			return true
		}
	}
	return false
}

func (r *wkRig) adminMod(group string, add bool, member string) {
	r.t.Helper()
	m := ldap.NewModifyRequest(group, nil)
	if add {
		m.Add("member", []string{member})
	} else {
		m.Delete("member", []string{member})
	}
	if err := r.admin.Modify(m); err != nil {
		r.t.Fatalf("admin modify %s: %v", group, err)
	}
}

// memberReq plans and applies a member add/remove with Tier-0 statements for the group and member.
func (r *wkRig) memberReq(kind connectorv1.WriteKind, group, member string, cls connectorv1.DirectoryObjectClass) (*connectorv1.PlanRequest, guid.GUID) {
	g, m := r.guidOf(group), r.guidOf(member)
	ch := addChange(m, cls)
	if kind == kRem {
		ch = remChange(m, cls)
	}
	p := r.planReq(kind, g, ch)
	p.Tier0 = r.tier0Ctx(g, m)
	return p, m
}

func (r *wkRig) memberDo(kind connectorv1.WriteKind, group, member string, cls connectorv1.DirectoryObjectClass) (*connectorv1.ApplyResponse, error) {
	r.t.Helper()
	p, _ := r.memberReq(kind, group, member, cls)
	pr, err := r.plan(p)
	if err != nil {
		return nil, err
	}
	return r.apply(r.applyFrom(p, pr, nil))
}

func wantApplied(t *testing.T, what string, resp *connectorv1.ApplyResponse, err error) {
	t.Helper()
	if err != nil || resp.GetOutcome() != connectorv1.ApplyOutcome_APPLY_OUTCOME_APPLIED {
		t.Fatalf("%s: %v %v", what, resp.GetOutcome(), err)
	}
}

// CC-WK-45, 46, 53: add a user, a computer, a contact and a group; the inverse removes them again.
func TestWKGMemberAddRemove(t *testing.T) {
	r := newWKRig(t)
	grp := r.mkGroup("wkg1", nil)
	user := r.mkUser("wkgu1")
	comp := r.mkComputer("wkgc1")
	contact := "CN=wkgct," + r.ou
	r.adminAdd(contact, "contact", nil)
	nested := r.mkGroup("wkgnest", nil)
	for _, m := range []struct {
		dn  string
		cls connectorv1.DirectoryObjectClass
	}{{user, clsUser}, {comp, clsComp}, {contact, clsContact}, {nested, clsGroup}} {
		resp, err := r.memberDo(kAdd, grp, m.dn, m.cls)
		wantApplied(t, "add "+m.dn, resp, err)
		if !r.isMember(m.dn, grp) {
			t.Fatalf("%s: group not in memberOf", m.dn)
		}
		// CC-WK-49: the same add again is ALREADY_APPLIED, never TARGET_CHANGED.
		p, _ := r.memberReq(kAdd, grp, m.dn, m.cls)
		pr, err := r.plan(p)
		if err != nil {
			t.Fatalf("replan: %v", err)
		}
		again, err := r.apply(r.applyFrom(p, pr, nil))
		if err != nil || again.GetOutcome() != connectorv1.ApplyOutcome_APPLY_OUTCOME_ALREADY_APPLIED {
			t.Fatalf("second add %s: %v %v", m.dn, again.GetOutcome(), err)
		}
		// CC-WK-53: remove, then the inverse (add) restores it.
		resp, err = r.memberDo(kRem, grp, m.dn, m.cls)
		wantApplied(t, "remove "+m.dn, resp, err)
		if r.isMember(m.dn, grp) {
			t.Fatalf("%s: still in memberOf after remove", m.dn)
		}
		resp, err = r.memberDo(kAdd, grp, m.dn, m.cls)
		wantApplied(t, "inverse add "+m.dn, resp, err)
		resp, err = r.memberDo(kRem, grp, m.dn, m.cls)
		wantApplied(t, "final remove "+m.dn, resp, err)
		// CC-WK-54: removing an absent member is ALREADY_APPLIED.
		p, _ = r.memberReq(kRem, grp, m.dn, m.cls)
		pr, err = r.plan(p)
		if err != nil {
			t.Fatalf("replan remove: %v", err)
		}
		gone, err := r.apply(r.applyFrom(p, pr, nil))
		if err != nil || gone.GetOutcome() != connectorv1.ApplyOutcome_APPLY_OUTCOME_ALREADY_APPLIED {
			t.Fatalf("remove absent %s: %v %v", m.dn, gone.GetOutcome(), err)
		}
	}
}

// CC-WK-46, 50: class mismatch, self, loop, user as target, OU as member.
func TestWKGMemberRefusals(t *testing.T) {
	r := newWKRig(t)
	grp := r.mkGroup("wkg2", nil)
	user := r.mkUser("wkgu2")
	other := r.mkGroup("wkgother", nil)

	_, err := r.memberDo(kAdd, grp, other, clsUser) // a group declared USER
	wantRule(t, "group declared user", err, "MemberClassMismatch")
	_, err = r.memberDo(kAdd, grp, user, clsGroup) // a user declared GROUP
	wantRule(t, "user declared group", err, "MemberClassMismatch")
	_, err = r.memberDo(kAdd, grp, grp, clsGroup)
	wantRule(t, "self", err, "SelfMembership")
	_, err = r.memberDo(kAdd, user, grp, clsGroup) // a user as the target
	wantRule(t, "user as target", err, "ClassNotAllowed")
	_, err = r.memberDo(kAdd, grp, r.ou, clsGroup) // an OU as member
	wantRule(t, "ou as member", err, "ClassNotAllowed")

	// loop: other is a member of grp; adding grp to other would close the loop.
	resp, err := r.memberDo(kAdd, grp, other, clsGroup)
	wantApplied(t, "nest other in grp", resp, err)
	if len(r.entry(other, "tokenGroups").GetRawAttributeValues("tokenGroups")) == 0 {
		// Samba does not construct tokenGroups on group objects (Windows does), so the loop check has
		// nothing to read here: NestingCycle is proven by the unit cases and by the Windows lab (T-1926).
		t.Log("Samba returns no tokenGroups for a group: NestingCycle not provable on Samba")
		return
	}
	_, err = r.memberDo(kAdd, other, grp, clsGroup)
	wantRule(t, "nesting loop", err, "NestingCycle")
	if r.isMember(grp, other) {
		t.Fatal("a loop was written")
	}
}

// CC-WK-49 (primary group), CC-WK-54: the primary group counts as already a member; it cannot be removed.
func TestWKGPrimaryGroup(t *testing.T) {
	r := newWKRig(t)
	user := r.mkUser("wkgu3")
	du := "CN=Domain Users,CN=Users," + labDom
	p, _ := r.memberReq(kAdd, du, user, clsUser)
	pr, err := r.plan(p)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := r.apply(r.applyFrom(p, pr, nil))
	if err != nil || resp.GetOutcome() != connectorv1.ApplyOutcome_APPLY_OUTCOME_ALREADY_APPLIED {
		t.Fatalf("add to primary group: %v %v", resp.GetOutcome(), err)
	}
	_, err = r.memberDo(kRem, du, user, clsUser)
	wantRule(t, "remove primary", err, "PrimaryGroupMember")
}

// CC-WK-47, 48, 55: Tier-0 groups, Tier-0 members; no write.
func TestWKGTier0(t *testing.T) {
	r := newWKRig(t)
	grp := r.mkGroup("wkg4", nil)
	user := r.mkUser("wkgu4")
	admin := "CN=Administrator,CN=Users," + labDom
	for _, g := range []string{"CN=Domain Admins,CN=Users," + labDom, "CN=Account Operators,CN=Builtin," + labDom} {
		_, err := r.memberDo(kAdd, g, user, clsUser)
		wantCode(t, "add to "+g, err, connectorv1.ErrorCode_ERROR_CODE_TIER0_REFUSED)
		if r.isMember(user, g) {
			t.Fatalf("added to %s", g)
		}
	}
	// a group nested in Domain Admins (C2)
	nest := r.mkGroup("wkgnest4", nil)
	r.adminMod("CN=Domain Admins,CN=Users,"+labDom, true, nest)
	t.Cleanup(func() { r.adminMod("CN=Domain Admins,CN=Users,"+labDom, false, nest) })
	_, err := r.memberDo(kAdd, nest, user, clsUser)
	wantCode(t, "add to group nested in DA", err, connectorv1.ErrorCode_ERROR_CODE_TIER0_REFUSED)
	r.adminMod(nest, true, user)
	_, err = r.memberDo(kRem, nest, user, clsUser)
	wantCode(t, "remove from group nested in DA", err, connectorv1.ErrorCode_ERROR_CODE_TIER0_REFUSED)
	if !r.isMember(user, nest) {
		t.Fatal("removal went through")
	}
	// a C1 member into an ordinary group, both verbs
	_, err = r.memberDo(kAdd, grp, admin, clsUser)
	wantCode(t, "C1 member add", err, connectorv1.ErrorCode_ERROR_CODE_TIER0_REFUSED)
	r.adminMod(grp, true, admin)
	_, err = r.memberDo(kRem, grp, admin, clsUser)
	wantCode(t, "C1 member remove", err, connectorv1.ErrorCode_ERROR_CODE_TIER0_REFUSED)
	// a DC computer as member (C4)
	dc := "CN=DC1,OU=Domain Controllers," + labDom
	if r.exists(dc) {
		_, err = r.memberDo(kAdd, grp, dc, clsComp)
		wantCode(t, "DC member add", err, connectorv1.ErrorCode_ERROR_CODE_TIER0_REFUSED)
	} else {
		t.Log("no CN=DC1 in the lab; DC-member case skipped")
	}
}

// CC-WK-51: a domain-local group in a global group; the DC's scope rule, fixed text.
func TestWKGScopeRule(t *testing.T) {
	r := newWKRig(t)
	global := r.mkGroup("wkgglobal", map[string][]string{"groupType": {"-2147483646"}})
	local := r.mkGroup("wkglocal", map[string][]string{"groupType": {"-2147483644"}})
	_, err := r.memberDo(kAdd, global, local, clsGroup)
	if err == nil {
		// Samba's LDAP path accepts a domain-local group in a global group; Windows refuses it. The
		// refusal mapping (CodeConstraint -> GroupScopeRule) is a unit case; the Windows run is T-1926.
		t.Log("Samba does not enforce the group scope rule: GroupScopeRule not provable on Samba")
		return
	}
	wantRule(t, "domain-local in global", err, "GroupScopeRule")
	if strings.Contains(fmt.Sprint(err), "DC=") || strings.Contains(fmt.Sprint(err), local) {
		t.Fatalf("error leaks DN: %v", err)
	}
	if r.isMember(local, global) {
		t.Fatal("scope rule violated")
	}
}

// CC-WK-52 (Samba half): a group of 1,600 members (more than one default range) takes an add, and an
// unrelated membership change between Plan and Apply does not fail the digest.
func TestWKGLargeGroup(t *testing.T) {
	r := newWKRig(t)
	big := r.mkGroup("wkgbig", nil)
	const n = 1600
	m := ldap.NewModifyRequest(big, nil)
	vals := make([]string, 0, n)
	for i := 0; i < n; i++ {
		d := fmt.Sprintf("CN=wkgc%04d,%s", i, r.ou)
		r.adminAdd(d, "contact", nil)
		vals = append(vals, d)
	}
	m.Add("member", vals)
	if err := r.admin.Modify(m); err != nil {
		t.Fatal(err)
	}
	user := r.mkUser("wkgu5")
	other := r.mkUser("wkgu6")
	p, _ := r.memberReq(kAdd, big, user, clsUser)
	pr, err := r.plan(p)
	if err != nil {
		t.Fatal(err)
	}
	r.adminMod(big, true, other) // unrelated membership change between Plan and Apply
	resp, err := r.apply(r.applyFrom(p, pr, nil))
	wantApplied(t, "add to big group", resp, err)
	if !r.isMember(user, big) {
		t.Fatal("not a member")
	}
	empty := r.mkGroup("wkgempty", nil)
	resp, err = r.memberDo(kAdd, empty, user, clsUser)
	wantApplied(t, "add to empty group", resp, err)
}

// CC-WK-56 (Samba half): the member removed by another technician between Plan and Apply.
func TestWKGRemoveRace(t *testing.T) {
	r := newWKRig(t)
	grp := r.mkGroup("wkg7", nil)
	user := r.mkUser("wkgu7")
	r.adminMod(grp, true, user)
	p, _ := r.memberReq(kRem, grp, user, clsUser)
	pr, err := r.plan(p)
	if err != nil {
		t.Fatal(err)
	}
	r.adminMod(grp, false, user)
	resp, err := r.apply(r.applyFrom(p, pr, nil))
	if err != nil || resp.GetOutcome() != connectorv1.ApplyOutcome_APPLY_OUTCOME_ALREADY_APPLIED {
		t.Fatalf("race: %v %v", resp.GetOutcome(), err)
	}
	// the group becomes nested under Domain Admins between Plan and Apply
	r.adminMod(grp, true, user)
	p, _ = r.memberReq(kRem, grp, user, clsUser)
	pr, err = r.plan(p)
	if err != nil {
		t.Fatal(err)
	}
	da := "CN=Domain Admins,CN=Users," + labDom
	r.adminMod(da, true, grp)
	t.Cleanup(func() { r.adminMod(da, false, grp) })
	_, err = r.apply(r.applyFrom(p, pr, nil))
	wantCode(t, "nested between plan and apply", err, connectorv1.ErrorCode_ERROR_CODE_TIER0_REFUSED)
	if !r.isMember(user, grp) {
		t.Fatal("removed under Tier-0")
	}
}

func resetChange() *connectorv1.WriteChange {
	return &connectorv1.WriteChange{Change: &connectorv1.WriteChange_ComputerAccountReset{ComputerAccountReset: &connectorv1.ComputerAccountReset{}}}
}

// CC-WK-57, 58, 60 on Samba: the machine password is replaced over LDAPS and pwdLastSet advances; two
// resets differ; a user, a contact and a DC as target are refused; a supplied secret is refused.
func TestWKGComputerReset(t *testing.T) {
	r := newWKRig(t)
	comp := r.mkComputer("wkgpc")
	id := r.guidOf(comp)
	before := r.entry(comp, "pwdLastSet", "unicodePwd").GetAttributeValue("pwdLastSet")
	p := r.planReq(kComp, id, resetChange())
	pr, err := r.plan(p)
	if err != nil {
		t.Fatalf("plan: %v (%v)", err, connErr(t, err))
	}
	// CC-WK-60: a secret input on a kind that generates its own value is refused.
	_, err = r.apply(r.applyFrom(p, pr, []byte("supplied-secret")))
	wantRule(t, "secret supplied", err, "SecretInputMismatch")
	resp, err := r.apply(r.applyFrom(p, pr, nil))
	wantApplied(t, "computer reset", resp, err)
	after := r.entry(comp, "pwdLastSet").GetAttributeValue("pwdLastSet")
	if after == before {
		t.Fatalf("pwdLastSet did not advance: %s", before)
	}
	for _, field := range []string{resp.String(), fmt.Sprint(resp.GetReadBack())} {
		if strings.Contains(field, "unicodePwd") && strings.Contains(field, "pw:") {
			t.Fatal("response carries a password value")
		}
	}

	// CC-WK-58: class refusals
	user := r.mkUser("wkgu8")
	contact := "CN=wkgct8," + r.ou
	r.adminAdd(contact, "contact", nil)
	for _, d := range []string{user, contact} {
		_, err = r.planApply(kComp, r.guidOf(d), resetChange())
		wantRule(t, "reset on "+d, err, "ClassNotAllowed")
	}
	dc := "CN=DC1,OU=Domain Controllers," + labDom
	if r.exists(dc) {
		_, err = r.planApply(kComp, r.guidOf(dc), resetChange())
		wantCode(t, "reset on a DC", err, connectorv1.ErrorCode_ERROR_CODE_TIER0_REFUSED)
	}
}

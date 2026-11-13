package write

import (
	"context"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/attr/sid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

const (
	clsUser  = connectorv1.DirectoryObjectClass_DIRECTORY_OBJECT_CLASS_USER
	clsGroup = connectorv1.DirectoryObjectClass_DIRECTORY_OBJECT_CLASS_GROUP
	clsComp  = connectorv1.DirectoryObjectClass_DIRECTORY_OBJECT_CLASS_COMPUTER
)

// fakeDir is a groupTx over in-memory entries. It is a fake of the DC's objects, not of the kind: the
// refusals, the digest and the Modify request are the real code's. reads records every attribute read.
type fakeDir struct {
	objs    map[guid.GUID]*ad.Entry
	reads   [][]string
	sent    []*ldap.ModifyRequest
	sendErr error
	onSend  func()
}

type recWrite struct{ d *fakeDir }

func (w recWrite) Add(*ldap.AddRequest) error { return nil }
func (w recWrite) Del(*ldap.DelRequest) error { return nil }
func (w recWrite) Modify(r *ldap.ModifyRequest) error {
	w.d.sent = append(w.d.sent, r)
	if w.d.onSend != nil {
		w.d.onSend()
	}
	return w.d.sendErr
}

func (d *fakeDir) DCTime() (time.Time, error) { return time.Unix(1700000000, 0), nil }
func (d *fakeDir) Read(ref dn.ObjectRef, attrs []string) (*ad.Entry, error) {
	d.reads = append(d.reads, attrs)
	g, _ := ref.GUID()
	if e, ok := d.objs[g]; ok {
		return e, nil
	}
	return nil, ad.NewError(ad.CodeObjectNotFound)
}
func (d *fakeDir) Send(f func(ad.WriteConn) error) error {
	if err := f(recWrite{d}); err != nil {
		if d.onSend != nil {
			return ad.NewError(ad.CodeConflict)
		}
		return err
	}
	return nil
}

func objEntry(id guid.GUID, dnText, sidText string, classes []string, extra map[string][][]byte) *ad.Entry {
	s, _ := sid.Parse(sidText)
	m := map[string][][]byte{"objectGUID": {id.Bytes()}, "objectSid": {s.Bytes()}}
	var oc [][]byte
	for _, c := range classes {
		oc = append(oc, []byte(c))
	}
	m["objectClass"] = oc
	for k, v := range extra {
		m[k] = v
	}
	return ad.NewEntry(dnText, m)
}

func gSIDBytes(t *testing.T, text string) []byte {
	s, err := sid.Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	return s.Bytes()
}

const dom = "S-1-5-21-1-2-3"

type gfix struct {
	d             *fakeDir
	group, member guid.GUID
}

// newGroupFix builds group Helpdesk (RID 1200) and a user (RID 1300) in the same domain.
func newGroupFix(t *testing.T, memberOf [][]byte, primary string) *gfix {
	f := &gfix{d: &fakeDir{objs: map[guid.GUID]*ad.Entry{}}, group: mk(60), member: mk(61)}
	f.d.objs[f.group] = objEntry(f.group, "CN=Helpdesk\\, EU,OU=Groups,DC=lab,DC=test", dom+"-1200", []string{"top", "group"},
		map[string][][]byte{"groupType": {[]byte("-2147483646")}})
	extra := map[string][][]byte{"primaryGroupID": {[]byte(primary)}}
	if memberOf != nil {
		extra["memberOf"] = memberOf
	}
	f.d.objs[f.member] = objEntry(f.member, "CN=Zoë Ünal\\, Jr,OU=People,DC=lab,DC=test", dom+"-1300",
		[]string{"top", "person", "organizationalPerson", "user"}, extra)
	return f
}

const groupDN = "CN=Helpdesk\\, EU,OU=Groups,DC=lab,DC=test"

func rule(r *Refusal) string {
	if r == nil {
		return ""
	}
	return r.Err.GetRejectedInput().GetRuleId()
}

func TestGroupMemberAddSendsOneAddOfTheEscapedMemberDN(t *testing.T) {
	f := newGroupFix(t, nil, "513")
	rd, r := readMembership(f.d, true, f.group, f.member, clsUser)
	if r != nil || rd.satisfied(true) {
		t.Fatalf("read: %v", r)
	}
	f.d.onSend = func() { // the DC applies the add
		f.d.objs[f.member] = objEntry(f.member, f.d.objs[f.member].DN, dom+"-1300", []string{"top", "person", "organizationalPerson", "user"},
			map[string][][]byte{"primaryGroupID": {[]byte("513")}, "memberOf": {[]byte(groupDN)}})
		f.d.onSend = nil
	}
	resp, r := applyGroupMemberIn(f.d, &connectorv1.TargetPrecondition{StateDigest: rd.dig}, true, f.group, f.member, clsUser)
	if r != nil || resp.GetOutcome() != connectorv1.ApplyOutcome_APPLY_OUTCOME_APPLIED {
		t.Fatalf("apply: %v %v", r, resp)
	}
	if len(f.d.sent) != 1 || len(f.d.sent[0].Changes) != 1 {
		t.Fatalf("sent %v", f.d.sent)
	}
	ch := f.d.sent[0].Changes[0]
	if ch.Operation != ldap.AddAttribute || ch.Modification.Type != "member" || len(ch.Modification.Vals) != 1 ||
		ch.Modification.Vals[0] != "CN=Zoë Ünal\\, Jr,OU=People,DC=lab,DC=test" {
		t.Fatalf("change %+v", ch)
	}
	for _, rd := range f.d.reads { // a 50,000-member group costs the same as an empty one
		for _, a := range rd {
			if a == "member" {
				t.Fatalf("the group's member list was read: %v", rd)
			}
		}
	}
}

func TestGroupMemberRemoveSendsOneDelete(t *testing.T) {
	f := newGroupFix(t, [][]byte{[]byte(groupDN)}, "513")
	rd, r := readMembership(f.d, false, f.group, f.member, clsUser)
	if r != nil || rd.satisfied(false) {
		t.Fatalf("read: %v", r)
	}
	f.d.onSend = func() {
		f.d.objs[f.member] = objEntry(f.member, f.d.objs[f.member].DN, dom+"-1300", []string{"top", "person", "organizationalPerson", "user"},
			map[string][][]byte{"primaryGroupID": {[]byte("513")}})
		f.d.onSend = nil
	}
	resp, r := applyGroupMemberIn(f.d, &connectorv1.TargetPrecondition{StateDigest: rd.dig}, false, f.group, f.member, clsUser)
	if r != nil || resp.GetOutcome() != connectorv1.ApplyOutcome_APPLY_OUTCOME_APPLIED || len(f.d.sent) != 1 ||
		f.d.sent[0].Changes[0].Operation != ldap.DeleteAttribute {
		t.Fatalf("apply: %v %v %v", r, resp, f.d.sent)
	}
}

func TestGroupMemberRefusals(t *testing.T) {
	cases := []struct {
		name    string
		add     bool
		cls     connectorv1.DirectoryObjectClass
		primary string
		mutate  func(f *gfix)
		self    bool
		want    string
	}{
		{name: "self", add: true, cls: clsGroup, self: true, want: "SelfMembership"},
		{name: "declared class differs", add: true, cls: clsGroup, primary: "513", want: "MemberClassMismatch"},
		{name: "user declared as computer", add: true, cls: clsComp, primary: "513", want: "MemberClassMismatch"},
		{name: "remove the primary group", add: false, cls: clsUser, primary: "1200", want: "PrimaryGroupMember"},
		{name: "member in another domain", add: true, cls: clsUser, primary: "513", want: "CrossDomainMemberUnsupported", mutate: func(f *gfix) {
			f.d.objs[f.member] = objEntry(f.member, "CN=u,DC=other,DC=test", dom+"-1300", []string{"top", "person", "organizationalPerson", "user"}, nil)
		}},
		{name: "foreignSecurityPrincipal member", add: true, cls: clsUser, primary: "513", want: "ClassNotAllowed", mutate: func(f *gfix) {
			f.d.objs[f.member] = objEntry(f.member, "CN=S-1-5-9,CN=ForeignSecurityPrincipals,DC=lab,DC=test", dom+"-1300", []string{"top", "foreignSecurityPrincipal"}, nil)
		}},
		{name: "gMSA member", add: true, cls: clsUser, primary: "513", want: "ClassNotAllowed", mutate: func(f *gfix) {
			f.d.objs[f.member] = objEntry(f.member, "CN=g,DC=lab,DC=test", dom+"-1300", []string{"top", "person", "organizationalPerson", "user", "computer", "msDS-GroupManagedServiceAccount"}, nil)
		}},
		{name: "OU member", add: true, cls: clsUser, primary: "513", want: "ClassNotAllowed", mutate: func(f *gfix) {
			f.d.objs[f.member] = objEntry(f.member, "OU=x,DC=lab,DC=test", dom+"-1300", []string{"top", "organizationalUnit"}, nil)
		}},
		{name: "user as the target", add: true, cls: clsUser, primary: "513", want: "ClassNotAllowed", mutate: func(f *gfix) {
			f.d.objs[f.group] = objEntry(f.group, groupDN, dom+"-1200", []string{"top", "person", "organizationalPerson", "user"}, nil)
		}},
		{name: "nesting loop", add: true, cls: clsGroup, want: "NestingCycle", mutate: func(f *gfix) {
			// The member group's SID is in the target group's tokenGroups: the target already sits below it.
			f.d.objs[f.member] = objEntry(f.member, "CN=Parent,OU=Groups,DC=lab,DC=test", dom+"-1300", []string{"top", "group"}, nil)
			f.d.objs[f.group] = objEntry(f.group, groupDN, dom+"-1200", []string{"top", "group"},
				map[string][][]byte{"tokenGroups": {gSIDBytes(t, dom+"-1300")}})
		}},
	}
	for _, c := range cases {
		f := newGroupFix(t, nil, c.primary)
		if c.mutate != nil {
			c.mutate(f)
		}
		m := f.member
		if c.self {
			m = f.group
		}
		_, r := readMembership(f.d, c.add, f.group, m, c.cls)
		if rule(r) != c.want || len(f.d.sent) != 0 {
			t.Errorf("%s: got %q, want %q", c.name, rule(r), c.want)
		}
	}
}

func TestGroupNestingOfAGroupIsAllowedWhenNoLoop(t *testing.T) {
	f := newGroupFix(t, nil, "")
	f.d.objs[f.member] = objEntry(f.member, "CN=Child,OU=Groups,DC=lab,DC=test", dom+"-1300", []string{"top", "group"}, nil)
	if _, r := readMembership(f.d, true, f.group, f.member, clsGroup); r != nil {
		t.Fatalf("refused: %v", rule(r))
	}
}

func TestGroupMemberAlreadyApplied(t *testing.T) {
	cases := []struct {
		name     string
		add      bool
		memberOf [][]byte
		primary  string
		want     bool
	}{
		{"add, already a member", true, [][]byte{[]byte(groupDN)}, "513", true},
		{"add, primary group (not stored in member)", true, nil, "1200", true},
		{"add, not a member", true, nil, "513", false},
		{"remove, not a member", false, nil, "513", true},
		{"remove, a member", false, [][]byte{[]byte(groupDN)}, "513", false},
		// A DN spelled differently (case, spacing) is the same DN.
		{"add, member DN in other case", true, [][]byte{[]byte("cn=helpdesk\\, eu,ou=groups,dc=lab,dc=test")}, "513", true},
	}
	for _, c := range cases {
		f := newGroupFix(t, c.memberOf, c.primary)
		rd, r := readMembership(f.d, c.add, f.group, f.member, clsUser)
		if r != nil || rd.satisfied(c.add) != c.want {
			t.Errorf("%s: satisfied=%v err=%q", c.name, rd != nil && rd.satisfied(c.add), rule(r))
		}
	}
}

func TestGroupMemberApplyAlreadyAppliedWritesNothingAndDigestIgnoresGroupChurn(t *testing.T) {
	f := newGroupFix(t, [][]byte{[]byte(groupDN)}, "513")
	resp, r := applyGroupMemberIn(f.d, &connectorv1.TargetPrecondition{StateDigest: []byte("stale")}, true, f.group, f.member, clsUser)
	if r != nil || resp.GetOutcome() != connectorv1.ApplyOutcome_APPLY_OUTCOME_ALREADY_APPLIED || len(f.d.sent) != 0 {
		t.Fatalf("got %v %v", r, resp)
	}
	// The digest does not move with the group's uSNChanged or its member list (CC-WK-52).
	g := newGroupFix(t, nil, "513")
	a, _ := readMembership(g.d, true, g.group, g.member, clsUser)
	g.d.objs[g.group] = objEntry(g.group, groupDN, dom+"-1200", []string{"top", "group"},
		map[string][][]byte{"groupType": {[]byte("-2147483646")}, "uSNChanged": {[]byte("99999")}, "member": {[]byte("CN=x,DC=lab,DC=test")}})
	b, _ := readMembership(g.d, true, g.group, g.member, clsUser)
	if string(a.dig) != string(b.dig) {
		t.Fatal("digest moved with the group's churn")
	}
	// ... but it does move when the member moves to another OU.
	g.d.objs[g.member] = objEntry(g.member, "CN=Zoë Ünal\\, Jr,OU=Elsewhere,DC=lab,DC=test", dom+"-1300", []string{"top", "person", "organizationalPerson", "user"},
		map[string][][]byte{"primaryGroupID": {[]byte("513")}})
	c, _ := readMembership(g.d, true, g.group, g.member, clsUser)
	if string(a.dig) == string(c.dig) {
		t.Fatal("digest ignored a member move")
	}
}

func TestGroupMemberApplyTargetChangedAndRaces(t *testing.T) {
	f := newGroupFix(t, nil, "513")
	_, r := applyGroupMemberIn(f.d, &connectorv1.TargetPrecondition{StateDigest: []byte("stale")}, true, f.group, f.member, clsUser)
	if r == nil || r.Err.GetCode() != connectorv1.ErrorCode_ERROR_CODE_TARGET_CHANGED || len(f.d.sent) != 0 {
		t.Fatalf("got %v", r)
	}
	// The DC refuses the add (value present) because a second technician added it: ALREADY_APPLIED.
	rd, _ := readMembership(f.d, true, f.group, f.member, clsUser)
	f.d.sendErr = ad.NewError(ad.CodeConflict)
	f.d.onSend = func() {
		f.d.objs[f.member] = objEntry(f.member, f.d.objs[f.member].DN, dom+"-1300", []string{"top", "person", "organizationalPerson", "user"},
			map[string][][]byte{"primaryGroupID": {[]byte("513")}, "memberOf": {[]byte(groupDN)}})
	}
	resp, r := applyGroupMemberIn(f.d, &connectorv1.TargetPrecondition{StateDigest: rd.dig}, true, f.group, f.member, clsUser)
	if r != nil || resp.GetOutcome() != connectorv1.ApplyOutcome_APPLY_OUTCOME_ALREADY_APPLIED {
		t.Fatalf("got %v %v", r, resp)
	}
}

func TestGroupScopeRuleIsFixedText(t *testing.T) {
	f := newGroupFix(t, nil, "513")
	rd, _ := readMembership(f.d, true, f.group, f.member, clsUser)
	f.d.sendErr = ad.NewError(ad.CodeConstraint)
	_, r := applyGroupMemberIn(f.d, &connectorv1.TargetPrecondition{StateDigest: rd.dig}, true, f.group, f.member, clsUser)
	if rule(r) != "GroupScopeRule" || r.Err.GetMessage() != "invalid request" {
		t.Fatalf("got %v", r)
	}
}

func TestGroupMemberGhostIsObjectNotFound(t *testing.T) {
	f := newGroupFix(t, nil, "513")
	delete(f.d.objs, f.member)
	_, r := readMembership(f.d, false, f.group, f.member, clsUser)
	if r == nil || r.Err.GetCode() != connectorv1.ErrorCode_ERROR_CODE_OBJECT_NOT_FOUND || len(f.d.sent) != 0 {
		t.Fatalf("got %v", r)
	}
}

func TestGroupKindsDeclareTheMembershipOpAndBothTouchedObjects(t *testing.T) {
	m := mk(61)
	for _, add := range []bool{true, false} {
		var ch *connectorv1.WriteChange
		if add {
			ch = &connectorv1.WriteChange{Change: &connectorv1.WriteChange_GroupMemberAdd{GroupMemberAdd: &connectorv1.GroupMemberAdd{Member: toWire(m), MemberClass: clsUser}}}
		} else {
			ch = &connectorv1.WriteChange{Change: &connectorv1.WriteChange_GroupMemberRemove{GroupMemberRemove: &connectorv1.GroupMemberRemove{Member: toWire(m), MemberClass: clsUser}}}
		}
		op := groupOp(add)
		pw, err := op.PropertyWrite(ch)
		if err != nil || pw.Op == 0 || len(pw.Keys) != 0 {
			t.Fatalf("declaration %v %v", pw, err)
		}
		g := mk(60)
		got, err := op.Touched(g, ch)
		if err != nil || len(got) != 2 || got[0] != g || got[1] != m {
			t.Fatalf("touched %v %v", got, err)
		}
		if !op.Arm(ch) || groupOp(!add).Arm(ch) {
			t.Fatal("arm check")
		}
	}
}

// Either touched object being Tier-0 refuses a membership change before any directory call, add or
// remove (CC-WK-47, 48, 55): the group is the target and the member is the second touched object.
func TestGroupKindsRefuseWhenGroupOrMemberIsTier0(t *testing.T) {
	g, m := mk(70), mk(71)
	for _, tier0ID := range []guid.GUID{g, m} {
		for _, add := range []bool{true, false} {
			run := passRun(map[string][]Basis{tier0ID.String(): {connectorv1.Tier0Basis_TIER0_BASIS_C2_PROTECTED_GROUP_MEMBER}})
			r := newRig(t, &run)
			r.prov.guard = &stubGuard{}
			var kind connectorv1.WriteKind
			var ch *connectorv1.WriteChange
			if add {
				kind = connectorv1.WriteKind_WRITE_KIND_GROUP_MEMBER_ADD
				ch = &connectorv1.WriteChange{Change: &connectorv1.WriteChange_GroupMemberAdd{GroupMemberAdd: &connectorv1.GroupMemberAdd{Member: toWire(m), MemberClass: clsUser}}}
			} else {
				kind = connectorv1.WriteKind_WRITE_KIND_GROUP_MEMBER_REMOVE
				ch = &connectorv1.WriteChange{Change: &connectorv1.WriteChange_GroupMemberRemove{GroupMemberRemove: &connectorv1.GroupMemberRemove{Member: toWire(m), MemberClass: clsUser}}}
			}
			p := planReq(g, ctxFor(g, m))
			p.Kind, p.Change = kind, ch
			p.Target.NcGuid = ncWire
			var err error
			r.h, err = New(r.prov, r.gate, WithRecorder(r.rec), WithClock(func() time.Time { return r.now }))
			if err != nil {
				t.Fatal(err)
			}
			_, err = r.h.Plan(context.Background(), p)
			wantTier0(t, err, connectorv1.Tier0RefusalStage_TIER0_REFUSAL_STAGE_CONNECTOR_SET)
		}
	}
}

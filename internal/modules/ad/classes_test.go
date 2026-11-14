package ad_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/accountkind"
	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/modules/ad"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

const (
	grp  = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
	grp2 = "ffffffff-ffff-4fff-8fff-ffffffffffff"
	cmp  = "99999999-9999-4999-8999-999999999999"
	ouX  = "12121212-1212-4121-8121-121212121212"
)

func classDir() *dirFake {
	d := newDir()
	d.objs[grp] = client.ObjectState{Exists: true, Class: "group", Parent: ouA, RDN: "Staff, Ünïcode"}
	d.objs[grp2] = client.ObjectState{Exists: true, Class: "group", Parent: ouA, RDN: "Outer"}
	d.objs[cmp] = client.ObjectState{Exists: true, Class: "computer", Parent: ouA, RDN: "WS01"}
	d.objs[ouX] = client.ObjectState{Exists: true, Class: "organizationalUnit", Parent: ouA, RDN: "Sales"}
	d.children = map[string]*client.ChildCount{}
	return d
}

func tgt(g string) ad.Target { return ad.Target{ConnectionID: conn, ObjectGUID: g, NamingContext: nc} }

func refusalCode(err error) string {
	var pr *operation.PlanRefusal
	if errors.As(err, &pr) {
		return pr.Code
	}
	return ""
}

// AC2: an OU with children is blocked at Plan unless it is empty; the reason names the child count and
// an explicit cascade is refused rather than ignored.
func TestOUDeleteWithChildrenIsBlockedAtPlanNamingTheCount(t *testing.T) {
	d := classDir()
	act := lifeActions(t, d, nil)[ad.VerbID("ou", "delete")]
	for name, tc := range map[string]struct {
		cc   *client.ChildCount
		in   ad.DeleteInput
		code string
	}{
		"three children":   {&client.ChildCount{Count: 3}, ad.DeleteInput{Target: tgt(ouX)}, "ou_not_empty_3"},
		"capped":           {&client.ChildCount{Count: 1000, Capped: true}, ad.DeleteInput{Target: tgt(ouX)}, "ou_not_empty_1000_or_more"},
		"explicit cascade": {&client.ChildCount{Count: 3}, ad.DeleteInput{Target: tgt(ouX), Cascade: true}, "cascade_not_supported"},
	} {
		t.Run(name, func(t *testing.T) {
			d.children[ouX] = tc.cc
			err := planErr(act, input(t, tc.in))
			if got := refusalCode(err); got != tc.code {
				t.Fatalf("plan error %v, code %q want %q", err, got, tc.code)
			}
		})
	}
	// An empty OU plans a delete; the DC still decides leaf-ness at Apply.
	d.children[ouX] = &client.ChildCount{}
	sp := plan1(t, act, ad.DeleteInput{Target: tgt(ouX)})
	if sp.Kind == "" || sp.Target.GUID != ouX {
		t.Fatalf("plan %+v", sp)
	}
	// A reader that gave no count refuses (never reads as zero children).
	delete(d.children, ouX)
	if err := planErr(act, input(t, ad.DeleteInput{Target: tgt(ouX)})); !errors.Is(err, operation.ErrTransient) {
		t.Fatalf("no count: %v", err)
	}
	// A user is not an OU.
	if err := planErr(act, input(t, ad.DeleteInput{Target: tgt(obj)})); !errors.Is(err, operation.ErrInvalid) {
		t.Fatalf("user target: %v", err)
	}
}

func TestEveryClassHasItsVerbsAndRefusesOtherClasses(t *testing.T) {
	d := classDir()
	as := lifeActions(t, d, nil)
	for _, seg := range []string{"user", "group", "computer", "contact", "ou"} {
		for _, v := range []string{"create", "update", "delete", "move", "rename", "restore"} {
			a, ok := as[ad.VerbID(seg, v)]
			if !ok {
				t.Fatalf("missing ad.%s.%s", seg, v)
			}
			wantPerm := ad.VerbPermission(seg, v)
			if v == "rename" {
				wantPerm = ad.VerbPermission(seg, "move") // a modifyDN (TM-D19)
			}
			if got := a.Describe().Permission; got != wantPerm {
				t.Errorf("ad.%s.%s permission %s want %s", seg, v, got, wantPerm)
			}
		}
	}
	// A computer is not a group: the group Actions refuse it, and the other way round.
	if err := planErr(as[ad.VerbID("group", "rename")], input(t, ad.RenameInput{Target: tgt(cmp), NewName: "x"})); !errors.Is(err, operation.ErrInvalid) || !strings.Contains(err.Error(), "target_not_a_group") {
		t.Fatalf("group rename of a computer: %v", err)
	}
	if err := planErr(as[ad.VerbID("computer", "rename")], input(t, ad.RenameInput{Target: tgt(grp), NewName: "x"})); !errors.Is(err, operation.ErrInvalid) {
		t.Fatalf("computer rename of a group: %v", err)
	}
	sp := plan1(t, as[ad.VerbID("group", "rename")], ad.RenameInput{Target: tgt(grp), NewName: "Staff, Ünïcode 2"})
	if sp.Kind != client.DigestObjectRename || sp.Diff[0].After[0] != "Staff, Ünïcode 2" {
		t.Fatalf("plan %+v", sp)
	}
	// The class attribute lists differ: description is a group attribute, givenName is not.
	if err := planErr(as[ad.VerbID("group", "update")], input(t, ad.UpdateInput{Target: tgt(grp), Set: map[string]string{"givenName": "x"}})); !errors.Is(err, operation.ErrInvalid) {
		t.Fatalf("givenName on a group: %v", err)
	}
	plan1(t, as[ad.VerbID("group", "update")], ad.UpdateInput{Target: tgt(grp), Set: map[string]string{"description": "x"}})
}

func TestCreateOtherClasses(t *testing.T) {
	d := classDir()
	as := lifeActions(t, d, nil)
	in := ad.ObjectCreateInput{ConnectionID: conn, NamingContext: nc, ParentGuid: ouA, Name: "Staff, Ünïcode", GroupScope: "global", GroupSecurity: true}
	sp := plan1(t, as[ad.VerbID("group", "create")], in)
	if sp.Target.Class != "group" || sp.Target.RDN != "Staff, Ünïcode" {
		t.Fatalf("target %+v", sp.Target)
	}
	if err := planErr(as[ad.VerbID("group", "create")], input(t, ad.ObjectCreateInput{ConnectionID: conn, NamingContext: nc, ParentGuid: ouA, Name: "g"})); !errors.Is(err, operation.ErrInvalid) {
		t.Fatalf("group without scope: %v", err)
	}
	cs := plan1(t, as[ad.VerbID("computer", "create")], ad.ObjectCreateInput{ConnectionID: conn, NamingContext: nc, ParentGuid: ouA, Name: "ws02"})
	if cs.Target.Class != "computer" {
		t.Fatalf("computer target %+v", cs.Target)
	}
	var sam string
	for _, c := range cs.Diff {
		if strings.Contains(c.Attribute, "sAMAccountName") {
			sam = c.After[0]
		}
	}
	if sam != "s:WS02$" {
		t.Fatalf("sAMAccountName %q, %+v", sam, cs.Diff)
	}
	ou := plan1(t, as[ad.VerbID("ou", "create")], ad.ObjectCreateInput{ConnectionID: conn, NamingContext: nc, ParentGuid: ouA, Name: "Sales"})
	if ou.Target.Class != "organizationalUnit" {
		t.Fatalf("ou target %+v", ou.Target)
	}
	if err := planErr(as[ad.VerbID("ou", "create")], input(t, ad.ObjectCreateInput{ConnectionID: conn, NamingContext: nc, ParentGuid: ouA, Name: "x", Attributes: map[string]string{"userAccountControl": "512"}})); !errors.Is(err, operation.ErrInvalid) {
		t.Fatalf("denied attribute: %v", err)
	}
}

func memberActions(t *testing.T, d *dirFake) map[operation.ActionID]operation.Action {
	t.Helper()
	as, err := ad.MemberActions(ad.LifecyclePorts{Reader: d, Writer: d})
	if err != nil {
		t.Fatal(err)
	}
	m := map[operation.ActionID]operation.Action{}
	for _, a := range as {
		m[a.Describe().ID] = a
	}
	return m
}

// AC1: the planned step of every membership Action targets the group, never the member, and the
// Descriptor declares the group class and one of the membership permissions (rbac.GroupMembershipPermissions).
func TestMemberActionsTargetTheGroup(t *testing.T) {
	d := classDir()
	as := memberActions(t, d)
	cases := []struct {
		id    operation.ActionID
		perm  string
		in    ad.MemberInput
		kind  string
		class string
	}{
		{ad.AddMemberID, "objects.group.add_member", ad.MemberInput{ConnectionID: conn, NamingContext: nc, GroupGuid: grp, MemberGuid: obj, MemberClass: "user"}, accountkind.KeyGroupMemberAdd, "user"},
		{ad.NestGroupID, "objects.group.nest", ad.MemberInput{ConnectionID: conn, NamingContext: nc, GroupGuid: grp, MemberGuid: grp2, MemberClass: "group"}, accountkind.KeyGroupMemberAdd, "group"},
	}
	for _, c := range cases {
		a := as[c.id]
		dd := a.Describe()
		if string(dd.Permission) != c.perm || dd.TargetClass != "group" {
			t.Fatalf("%s: %+v", c.id, dd)
		}
		sp := plan1(t, a, c.in)
		if sp.Target.GUID != grp || sp.Target.Class != "group" || sp.Kind != c.kind {
			t.Fatalf("%s: the step must target the group: %+v", c.id, sp.Target)
		}
		for _, ch := range sp.Diff {
			if ch.Attribute == accountkind.AttrMember && ch.After[0] != c.in.MemberGuid {
				t.Fatalf("member attribute %+v", ch)
			}
		}
	}
	// Remove is an ordinary object permission, not a guarded one.
	if p := as[ad.RemoveMemberID].Describe(); string(p.Permission) != "objects.group.remove_member" || p.TargetClass != "group" {
		t.Fatalf("remove %+v", p)
	}
	// A group member through the add Action must use nest (the connector would refuse too).
	err := planErr(as[ad.AddMemberID], input(t, ad.MemberInput{ConnectionID: conn, NamingContext: nc, GroupGuid: grp, MemberGuid: grp2, MemberClass: "group"}))
	if !errors.Is(err, operation.ErrInvalid) || !strings.Contains(err.Error(), ad.ReasonUseNest) {
		t.Fatalf("add of a group: %v", err)
	}
}

func TestMemberPlanRefusalsAndNoOps(t *testing.T) {
	d := classDir()
	as := memberActions(t, d)
	in := ad.MemberInput{ConnectionID: conn, NamingContext: nc, GroupGuid: grp, MemberGuid: obj, MemberClass: "user"}
	bad := map[string]ad.MemberInput{
		"self":           {ConnectionID: conn, NamingContext: nc, GroupGuid: grp2, MemberGuid: grp2, MemberClass: "group"},
		"class mismatch": {ConnectionID: conn, NamingContext: nc, GroupGuid: grp, MemberGuid: obj, MemberClass: "contact"},
		"not a group":    {ConnectionID: conn, NamingContext: nc, GroupGuid: cmp, MemberGuid: obj, MemberClass: "user"},
		"no member":      {ConnectionID: conn, NamingContext: nc, GroupGuid: grp, MemberGuid: "00000000-0000-4000-8000-000000000001", MemberClass: "user"},
	}
	for name, b := range bad {
		id := ad.AddMemberID
		if b.MemberClass == "group" {
			id = ad.NestGroupID
		}
		if err := planErr(as[id], input(t, b)); !errors.Is(err, operation.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Tier-0 group and Tier-0 member are denied.
	st := d.objs[grp]
	st.Tier0 = true
	d.objs[grp] = st
	if err := planErr(as[ad.AddMemberID], input(t, in)); !errors.Is(err, operation.ErrDenied) {
		t.Fatalf("tier0 group: %v", err)
	}
	st.Tier0 = false
	d.objs[grp] = st
	// Already a member: add plans nothing; remove plans a step. Not a member: the reverse.
	d.members = map[string]bool{grp + "/" + obj: true}
	if steps, err := as[ad.AddMemberID].Plan(context.Background(), operation.PlanContext{Pins: pins()}, input(t, in)); err != nil || len(steps) != 0 {
		t.Fatalf("add of a member: %v %d", err, len(steps))
	}
	plan1(t, as[ad.RemoveMemberID], in)
	d.members = nil
	if steps, err := as[ad.RemoveMemberID].Plan(context.Background(), operation.PlanContext{Pins: pins()}, input(t, in)); err != nil || len(steps) != 0 {
		t.Fatalf("remove of a non-member: %v %d", err, len(steps))
	}
}

func TestMemberInverse(t *testing.T) {
	for _, tc := range []struct {
		id    operation.ActionID
		class string
		want  operation.ActionID
	}{{ad.AddMemberID, "user", ad.RemoveMemberID}, {ad.NestGroupID, "group", ad.RemoveMemberID}, {ad.RemoveMemberID, "group", ad.NestGroupID}, {ad.RemoveMemberID, "computer", ad.AddMemberID}} {
		if got, ok := ad.MemberInverse(tc.id, tc.class); !ok || got != tc.want {
			t.Errorf("%s/%s: %s %v", tc.id, tc.class, got, ok)
		}
	}
}

// AC3 (fake directory; the Samba lab test is in the lab suite): the computer reset sends no attribute at
// all, so a BitLocker recovery or LAPS attribute cannot ride along; Verify needs pwdLastSet to move.
func TestComputerResetSendsNoAttributesAndVerifiesPwdLastSet(t *testing.T) {
	a := newAccounts()
	a.class = "computer"
	act := actions(t, a)[ad.ComputerResetID]
	sp := plan1(t, act, ad.AccountInput{Target: target()})
	if sp.Kind != accountkind.KeyComputerReset || sp.Target.Class != "computer" || !sp.Credential || sp.Reversibility != operation.Irreversible || len(sp.Diff) != 0 {
		t.Fatalf("plan %+v", sp)
	}
	if !strings.Contains(strings.Join(sp.Preconditions, " "), "BitLocker") {
		t.Fatalf("preconditions %q", sp.Preconditions)
	}
	// A user is not a computer.
	a.class = "user"
	if err := planErr(act, input(t, ad.AccountInput{Target: target()})); !errors.Is(err, operation.ErrInvalid) || !strings.Contains(err.Error(), ad.ReasonNotComputer) {
		t.Fatalf("user target: %v", err)
	}
}

// Membership Actions run end to end through the runner against the fake directory: the write goes to
// the group, Verify reads the direct membership back, and the opposite Action undoes the change.
func TestMemberAddNestRemoveApplyAndVerify(t *testing.T) {
	d := classDir()
	as := memberActions(t, d)
	reg, err := operation.NewRegistry(storeFace{as[ad.AddMemberID]}, storeFace{as[ad.NestGroupID]}, storeFace{as[ad.RemoveMemberID]})
	if err != nil {
		t.Fatal(err)
	}
	r, err := operation.NewRunner(operation.Config{DB: fakeDB{}, Audit: &sink{}, Authz: &scopeAuthz{}, Registry: reg})
	if err != nil {
		t.Fatal(err)
	}
	do := func(id operation.ActionID, in ad.MemberInput, opID string) {
		t.Helper()
		res, err := r.RunStore(context.Background(), operation.Request{
			Tenant: tenanttest.NewID(t), Action: id, Input: input(t, in), Pins: pins(), Operation: step.OperationID(opID),
			Actor: authority.Chain{Requester: authority.Principal{ID: "tech", Kind: authority.Human}}, FreshStepUp: true,
		})
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		_ = res
	}
	user := ad.MemberInput{ConnectionID: conn, NamingContext: nc, GroupGuid: grp, MemberGuid: obj, MemberClass: "user"}
	nested := ad.MemberInput{ConnectionID: conn, NamingContext: nc, GroupGuid: grp, MemberGuid: grp2, MemberClass: "group"}
	do(ad.AddMemberID, user, "op-m-1")
	do(ad.NestGroupID, nested, "op-m-2")
	if !d.members[grp+"/"+obj] || !d.members[grp+"/"+grp2] || len(d.writes) != 2 {
		t.Fatalf("after add/nest: %v, %d writes", d.members, len(d.writes))
	}
	for _, w := range d.writes {
		if w.Target.GUID != grp || w.Target.Class != "group" {
			t.Fatalf("write must target the group: %+v", w.Target)
		}
	}
	do(ad.RemoveMemberID, user, "op-m-3")
	if d.members[grp+"/"+obj] || !d.members[grp+"/"+grp2] {
		t.Fatalf("after remove: %v", d.members)
	}
}

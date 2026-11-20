package sync_test

import (
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	dsync "github.com/skenzeriq/activediq/internal/directory/sync"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// These tests need no database: they pin what the ChangeMapper turns an ObjectChange into.

func changeMapper(t *testing.T) *dsync.ChangeMapper {
	t.Helper()
	cm, err := dsync.NewChangeMapper(dsync.Config{NC: inventory.GUID(gtext(hGUID))})
	if err != nil {
		t.Fatal(err)
	}
	return cm
}

func wantRefused(t *testing.T, err error, attr string, code dsync.Code) {
	t.Helper()
	var de *dsync.Error
	if !errors.Is(err, dsync.ErrMalformed) || !errors.As(err, &de) {
		t.Fatalf("err = %v, want a malformed refusal", err)
	}
	if de.Attr != attr || de.Code != code {
		t.Errorf("refusal = %s/%s, want %s/%s", de.Attr, de.Code, attr, code)
	}
}

func TestPlanNamesOnlyWhatTheChangeNames(t *testing.T) {
	p, err := changeMapper(t).Plan(live(priya, "", 0, cset("displayName", txt("X")), cclear("lockoutTime")))
	if err != nil {
		t.Fatal(err)
	}
	pt := p.Patch
	if !pt.DisplayName.Set || pt.DisplayName.Value != "X" || !pt.LockoutTime.Set || !pt.LockoutTime.Value.IsZero() {
		t.Errorf("patch: %+v", pt)
	}
	if pt.SAMAccountName.Set || pt.UserAccountControl.Set || pt.PwdLastSet.Set || pt.SID.Set || pt.Parent.Set || pt.DN.Set ||
		pt.Members != nil || pt.RemovedMembers != nil || pt.MembersComplete || pt.Attributes != nil || pt.Create != nil {
		t.Errorf("a field the change did not name is set: %+v", pt)
	}
	if !pt.State.Set || pt.State.Value != inventory.ObjLive {
		t.Errorf("state: %+v", pt.State)
	}
}

func TestPlanRefusesWhatItCannotMeanFaithfully(t *testing.T) {
	cm := changeMapper(t)
	m1, m2 := member(40), member(41)
	tests := []struct {
		name string
		ch   *connectorv1.ObjectChange
		attr string
		code dsync.Code
	}{
		{"unspecified state", change(priya, connectorv1.ObjectState_OBJECT_STATE_UNSPECIFIED, "", nil), "state", dsync.CodeMissing},
		{"no guid", &connectorv1.ObjectChange{State: connectorv1.ObjectState_OBJECT_STATE_LIVE}, "objectGUID", dsync.CodeBadGUID},
		{"set with removed", live(grpAll, "", 0, cset("member", m1), cdel("member", m2)), "member", dsync.CodeDuplicate},
		{"added and removed", live(grpAll, "", 0, cadd("member", m1), cdel("member", m1)), "member", dsync.CodeDuplicate},
		{"member is itself", live(grpAll, "", 0, cadd("member", member(grpAll))), "member", dsync.CodeBadGUID},
		{"parent is itself", live(priya, "CN=x,"+root, priya), "parentGuid", dsync.CodeBadGUID},
		{"unspecified op", live(priya, "", 0, &connectorv1.AttributeChange{Name: "displayName", Values: []*connectorv1.AttributeValue{txt("x")}}), "displayName", dsync.CodeType},
		{"incremental op on a single value", live(priya, "", 0, cadd("displayName", txt("x"))), "displayName", dsync.CodeType},
		{"wrong type", live(priya, "", 0, cset("userAccountControl", txt("512"))), "userAccountControl", dsync.CodeType},
		{"two values", live(priya, "", 0, cset("displayName", txt("a"), txt("b"))), "displayName", dsync.CodeMultiValued},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := cm.Plan(tc.ch)
			if err == nil {
				t.Fatal("accepted")
			}
			var de *dsync.Error
			if !errors.As(err, &de) {
				t.Fatalf("err = %v", err)
			}
			if de.Code != tc.code {
				t.Errorf("code = %s (%v), want %s", de.Code, err, tc.code)
			}
		})
	}
}

func TestPlanMemberOps(t *testing.T) {
	cm := changeMapper(t)
	p, err := cm.Plan(live(grpAll, "", 0, cadd("member", member(40), member(40), member(41)), cdel("member", member(42))))
	if err != nil {
		t.Fatal(err)
	}
	if p.Patch.MembersComplete || !slices.Equal(p.Patch.Members, []inventory.GUID{inventory.GUID(gtext(40)), inventory.GUID(gtext(41))}) ||
		!slices.Equal(p.Patch.RemovedMembers, []inventory.GUID{inventory.GUID(gtext(42))}) {
		t.Errorf("incremental: %+v", p.Patch)
	}
	p, err = cm.Plan(live(grpAll, "", 0, cset("member", member(40))))
	if err != nil || !p.Patch.MembersComplete || len(p.Patch.Members) != 1 {
		t.Errorf("SET: %+v %v", p.Patch, err)
	}
	p, err = cm.Plan(live(grpAll, "", 0, cclear("member")))
	if err != nil || !p.Patch.MembersComplete || len(p.Patch.Members) != 0 {
		t.Errorf("CLEARED: %+v %v", p.Patch, err)
	}
	// A value with no GUID cannot be named: it is counted, the set is then not complete, and nothing is removed by it.
	p, err = cm.Plan(live(grpAll, "", 0, cset("member", member(40), dnv("CN=ext,"+root, nil))))
	if err != nil || p.MembersUnresolved != 1 || p.Patch.MembersComplete {
		t.Errorf("unresolved: %+v %v", p, err)
	}
}

// A secret named in a change is not read: it leaves no trace in the patch or in a refusal.
func TestPlanDropsSecrets(t *testing.T) {
	const sentinel = "SENTINEL-PWD-do-not-log"
	p, err := changeMapper(t).Plan(live(priya, "", 0, cset("displayName", txt("ok")),
		cset("unicodePwd", txt(sentinel)), cset("userPassword", txt(sentinel)), cset("ntPwdHistory", txt(sentinel))))
	if err != nil {
		t.Fatal(err)
	}
	if s := fmt.Sprintf("%+v %#v", p, p); containsStr(s, sentinel) {
		t.Errorf("a secret reached the patch: %s", s)
	}
}

func containsStr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestPlanStatesAndTombstones(t *testing.T) {
	cm := changeMapper(t)
	for st, want := range map[connectorv1.ObjectState]inventory.ObjectState{
		connectorv1.ObjectState_OBJECT_STATE_DELETED:  inventory.ObjDeleted,
		connectorv1.ObjectState_OBJECT_STATE_RECYCLED: inventory.ObjRecycled,
	} {
		p, err := cm.Plan(tombstone(priya, st))
		if err != nil {
			t.Fatal(err)
		}
		pt := p.Patch
		if pt.State.Value != want || pt.Parent.Set {
			t.Errorf("%v: state %v, parent set %v (a tombstone's parent is the Deleted Objects container, not the old place)", st, pt.State.Value, pt.Parent.Set)
		}
		if !pt.DN.Set || pt.Create == nil {
			t.Errorf("%v: dn set %v, create %v (a tombstone carries enough to be stored)", st, pt.DN.Set, pt.Create)
		}
	}
	// A live change that is only a modification has no Create: the inventory reports it as needing a read.
	p, _ := cm.Plan(live(51, "CN=x,"+root, staff, classes("top", "person", "user"), cset("displayName", txt("x"))))
	if p.Patch.Create != nil {
		t.Errorf("a half object was offered for creation")
	}
	// A complete creation set has one.
	p, err := cm.Plan(newUser(50, "n", "OU=Staff,"+root, staff, 3000, 513))
	if err != nil || p.Patch.Create == nil {
		t.Errorf("creation: %v %v", p.Patch.Create, err)
	}
}

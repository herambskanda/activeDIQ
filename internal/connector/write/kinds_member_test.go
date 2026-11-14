package write

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// memSID builds S-1-5-21-1-2-3-<rid> in binary.
func memSID(rid byte) []byte {
	return []byte{1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, rid, 0, 0, 0}
}

type memberFake struct {
	byGUID  map[guid.GUID]*ad.Entry
	sendErr error
	sent    []*ldap.ModifyRequest
	// after is applied to the member's memberOf by a successful send (the directory's own effect).
	onSend func()
}

func (f *memberFake) DCTime() (time.Time, error) { return time.Unix(1700000000, 0), nil }
func (f *memberFake) Read(ref dn.ObjectRef, _ []string) (*ad.Entry, error) {
	g, _ := ref.GUID()
	if e, ok := f.byGUID[g]; ok {
		return e, nil
	}
	return nil, ad.NewError(ad.CodeObjectNotFound)
}
func (f *memberFake) Send(send func(ad.WriteConn) error) error {
	c := &recConn{f: f}
	if err := send(c); err != nil {
		return err
	}
	if f.onSend != nil {
		f.onSend()
	}
	return f.sendErr
}

type recConn struct{ f *memberFake }

func (c *recConn) Add(*ldap.AddRequest) error { return errors.New("add not expected") }
func (c *recConn) Del(*ldap.DelRequest) error { return errors.New("del not expected") }
func (c *recConn) Modify(r *ldap.ModifyRequest) error {
	c.f.sent = append(c.f.sent, r)
	return nil
}

const (
	memGrpDN = "CN=Staff,OU=Groups,DC=lab,DC=example"
	memUsrDN = "CN=Smith\\, Ann,OU=People,DC=lab,DC=example"
)

func mkEntry(dnText string, classes []string, rid byte, extra map[string][][]byte) *ad.Entry {
	a := map[string][][]byte{"objectSid": {memSID(rid)}}
	var oc [][]byte
	for _, c := range classes {
		oc = append(oc, []byte(c))
	}
	a["objectClass"] = oc
	for k, v := range extra {
		a[k] = v
	}
	return ad.NewEntry(dnText, a)
}

func rig11() (*memberFake, guid.GUID, guid.GUID) {
	gid, uid := mk(90), mk(91)
	f := &memberFake{byGUID: map[guid.GUID]*ad.Entry{
		gid: mkEntry(memGrpDN, []string{"top", "group"}, 10, map[string][][]byte{"groupType": {[]byte("-2147483646")}}),
		uid: mkEntry(memUsrDN, []string{"top", "person", "organizationalPerson", "user"}, 20, map[string][][]byte{"primaryGroupID": {[]byte("513")}}),
	}}
	return f, gid, uid
}

const (
	clsUser  = connectorv1.DirectoryObjectClass_DIRECTORY_OBJECT_CLASS_USER
	clsGroup = connectorv1.DirectoryObjectClass_DIRECTORY_OBJECT_CLASS_GROUP
)

func wantRule(t *testing.T, r *Refusal, rule string) {
	t.Helper()
	if r == nil {
		t.Fatalf("want %s, got success", rule)
	}
	if got := r.Err.GetRejectedInput().GetRuleId(); got != rule {
		t.Fatalf("want %s, got %s (%s)", rule, got, r.Err.GetCode())
	}
}

func TestMemberAddPlanAndApply(t *testing.T) {
	f, gid, uid := rig11()
	a := Authorised{}
	plan, r := planMemberIn(a, f, true, gid, uid, clsUser)
	if r != nil || plan.GetNoOp() || plan.GetPrecondition().UsnChanged != nil {
		t.Fatalf("plan %v %v", r, plan)
	}
	f.onSend = func() {
		f.byGUID[uid] = mkEntry(memUsrDN, []string{"top", "person", "organizationalPerson", "user"}, 20,
			map[string][][]byte{"primaryGroupID": {[]byte("513")}, "memberOf": {[]byte(memGrpDN)}})
	}
	resp, r := applyMemberIn(a, f, true, gid, uid, clsUser, plan.GetPrecondition())
	if r != nil || resp.GetOutcome() != connectorv1.ApplyOutcome_APPLY_OUTCOME_APPLIED {
		t.Fatalf("apply %v %v", r, resp)
	}
	if len(f.sent) != 1 || len(f.sent[0].Changes) != 1 {
		t.Fatalf("sent %d", len(f.sent))
	}
	ch := f.sent[0].Changes[0]
	if ch.Operation != ldap.AddAttribute || ch.Modification.Type != "member" || len(ch.Modification.Vals) != 1 {
		t.Fatalf("change %+v", ch)
	}
	// The value is the member's DN with the comma in its RDN escaped.
	if !strings.Contains(ch.Modification.Vals[0], `Smith\, Ann`) {
		t.Fatalf("value %q", ch.Modification.Vals[0])
	}
	if f.sent[0].DN != memGrpDN {
		t.Fatalf("target %q", f.sent[0].DN)
	}
}

func TestMemberAlreadyApplied(t *testing.T) {
	f, gid, uid := rig11()
	f.byGUID[uid] = mkEntry(memUsrDN, []string{"top", "person", "organizationalPerson", "user"}, 20,
		map[string][][]byte{"primaryGroupID": {[]byte("513")}, "memberOf": {[]byte("cn=staff,ou=groups,dc=lab,dc=example")}})
	plan, r := planMemberIn(Authorised{}, f, true, gid, uid, clsUser)
	if r != nil || !plan.GetNoOp() {
		t.Fatalf("add of a member: %v noop=%v", r, plan.GetNoOp())
	}
	resp, r := applyMemberIn(Authorised{}, f, true, gid, uid, clsUser, plan.GetPrecondition())
	if r != nil || resp.GetOutcome() != connectorv1.ApplyOutcome_APPLY_OUTCOME_ALREADY_APPLIED || len(f.sent) != 0 {
		t.Fatalf("%v %v sent=%d", r, resp.GetOutcome(), len(f.sent))
	}
	// A primary group is "already a member" for the add, and is not removable.
	f2, g2, u2 := rig11()
	f2.byGUID[g2] = mkEntry(memGrpDN, []string{"top", "group"}, 0, map[string][][]byte{"groupType": {[]byte("-2147483646")}})
	f2.byGUID[g2].Raw("objectSid")[0][24] = 0xff // RID 255
	f2.byGUID[u2] = mkEntry(memUsrDN, []string{"user"}, 20, map[string][][]byte{"primaryGroupID": {[]byte("255")}})
	if p, r := planMemberIn(Authorised{}, f2, true, g2, u2, clsUser); r != nil || !p.GetNoOp() {
		t.Fatalf("primary group add: %v", r)
	}
	_, r = planMemberIn(Authorised{}, f2, false, g2, u2, clsUser)
	wantRule(t, r, "PrimaryGroupMember")
}

func TestMemberRefusals(t *testing.T) {
	f, gid, uid := rig11()
	_, r := planMemberIn(Authorised{}, f, true, gid, gid, clsGroup)
	wantRule(t, r, "SelfMembership")
	_, r = planMemberIn(Authorised{}, f, true, gid, uid, clsGroup)
	wantRule(t, r, "MemberClassMismatch")
	// A user is not a group target.
	_, r = planMemberIn(Authorised{}, f, true, uid, gid, clsGroup)
	wantRule(t, r, "ClassNotAllowed")
	// An OU and a foreignSecurityPrincipal are not members.
	ou, fsp := mk(92), mk(93)
	f.byGUID[ou] = mkEntry("OU=X,DC=lab,DC=example", []string{"top", "organizationalUnit"}, 30, nil)
	f.byGUID[fsp] = mkEntry("CN=S-1-5-4,CN=ForeignSecurityPrincipals,DC=lab,DC=example", []string{"top", "foreignSecurityPrincipal"}, 31, nil)
	for _, id := range []guid.GUID{ou, fsp} {
		_, r = planMemberIn(Authorised{}, f, true, gid, id, clsUser)
		wantRule(t, r, "ClassNotAllowed")
	}
	// A managed service account's chain contains computer; its most specific class is not allowed.
	msa := mk(94)
	f.byGUID[msa] = mkEntry("CN=svc,DC=lab,DC=example", []string{"top", "person", "organizationalPerson", "user", "computer", "msDS-GroupManagedServiceAccount"}, 32, nil)
	_, r = planMemberIn(Authorised{}, f, true, gid, msa, connectorv1.DirectoryObjectClass_DIRECTORY_OBJECT_CLASS_COMPUTER)
	wantRule(t, r, "ClassNotAllowed")
	// Another domain.
	far := mk(95)
	f.byGUID[far] = mkEntry("CN=Bob,DC=other,DC=example", []string{"top", "person", "organizationalPerson", "user"}, 33, nil)
	_, r = planMemberIn(Authorised{}, f, true, gid, far, clsUser)
	wantRule(t, r, "CrossDomainMemberUnsupported")
	// A member that is not live.
	_, r = planMemberIn(Authorised{}, f, true, gid, mk(99), clsUser)
	if r == nil || r.Err.GetCode() != connectorv1.ErrorCode_ERROR_CODE_OBJECT_NOT_FOUND {
		t.Fatalf("missing member: %v", r)
	}
}

func TestMemberNestingCycle(t *testing.T) {
	f, gid, _ := rig11()
	child := mk(96)
	f.byGUID[child] = mkEntry("CN=Child,OU=Groups,DC=lab,DC=example", []string{"top", "group"}, 40, map[string][][]byte{"groupType": {[]byte("-2147483646")}})
	// The group Staff already sits below Child: Staff's tokenGroups carries Child's SID.
	f.byGUID[gid].Raw("objectSid")
	f.byGUID[gid] = mkEntry(memGrpDN, []string{"top", "group"}, 10, map[string][][]byte{
		"groupType": {[]byte("-2147483646")}, "tokenGroups": {memSID(40)}})
	_, r := planMemberIn(Authorised{}, f, true, gid, child, clsGroup)
	wantRule(t, r, "NestingCycle")
	// Removal of the nested group is allowed.
	if _, r := planMemberIn(Authorised{}, f, false, gid, child, clsGroup); r != nil {
		t.Fatalf("remove refused: %v", r)
	}
}

func TestMemberStateChangedAndConflict(t *testing.T) {
	f, gid, uid := rig11()
	plan, _ := planMemberIn(Authorised{}, f, true, gid, uid, clsUser)
	// The member moved to another OU between Plan and Apply: TARGET_CHANGED, nothing sent.
	f.byGUID[uid] = mkEntry("CN=Smith\\, Ann,OU=Other,DC=lab,DC=example", []string{"user"}, 20, map[string][][]byte{"primaryGroupID": {[]byte("513")}})
	_, r := applyMemberIn(Authorised{}, f, true, gid, uid, clsUser, plan.GetPrecondition())
	if r == nil || r.Err.GetCode() != connectorv1.ErrorCode_ERROR_CODE_TARGET_CHANGED || len(f.sent) != 0 {
		t.Fatalf("moved: %v sent=%d", r, len(f.sent))
	}
	// The DC refuses the add (a second writer got there first and the member's side shows it): ALREADY_APPLIED.
	f, gid, uid = rig11()
	plan, _ = planMemberIn(Authorised{}, f, true, gid, uid, clsUser)
	f.sendErr = ad.NewError(ad.CodeConflict)
	f.onSend = func() {
		f.byGUID[uid] = mkEntry(memUsrDN, []string{"user"}, 20, map[string][][]byte{"primaryGroupID": {[]byte("513")}, "memberOf": {[]byte(memGrpDN)}})
	}
	resp, r := applyMemberIn(Authorised{}, f, true, gid, uid, clsUser, plan.GetPrecondition())
	if r != nil || resp.GetOutcome() != connectorv1.ApplyOutcome_APPLY_OUTCOME_ALREADY_APPLIED {
		t.Fatalf("confirmed conflict: %v", r)
	}
	// ... and when the member's side does not confirm it, the target changed.
	f, gid, uid = rig11()
	plan, _ = planMemberIn(Authorised{}, f, true, gid, uid, clsUser)
	f.sendErr = ad.NewError(ad.CodeConflict)
	_, r = applyMemberIn(Authorised{}, f, true, gid, uid, clsUser, plan.GetPrecondition())
	if r == nil || r.Err.GetCode() != connectorv1.ErrorCode_ERROR_CODE_TARGET_CHANGED {
		t.Fatalf("unconfirmed conflict: %v", r)
	}
	// The DC's scope rule.
	f, gid, uid = rig11()
	plan, _ = planMemberIn(Authorised{}, f, true, gid, uid, clsUser)
	f.sendErr = ad.NewError(ad.CodeConstraint)
	_, r = applyMemberIn(Authorised{}, f, true, gid, uid, clsUser, plan.GetPrecondition())
	wantRule(t, r, "GroupScopeRule")
}

func TestMemberRemove(t *testing.T) {
	f, gid, uid := rig11()
	f.byGUID[uid] = mkEntry(memUsrDN, []string{"user"}, 20, map[string][][]byte{"primaryGroupID": {[]byte("513")}, "memberOf": {[]byte(memGrpDN)}})
	plan, r := planMemberIn(Authorised{}, f, false, gid, uid, clsUser)
	if r != nil || plan.GetNoOp() {
		t.Fatalf("%v", r)
	}
	f.onSend = func() {
		f.byGUID[uid] = mkEntry(memUsrDN, []string{"user"}, 20, map[string][][]byte{"primaryGroupID": {[]byte("513")}})
	}
	resp, r := applyMemberIn(Authorised{}, f, false, gid, uid, clsUser, plan.GetPrecondition())
	if r != nil || resp.GetOutcome() != connectorv1.ApplyOutcome_APPLY_OUTCOME_APPLIED || f.sent[0].Changes[0].Operation != ldap.DeleteAttribute {
		t.Fatalf("%v", r)
	}
}

func TestMemberOpsRegisteredAndValid(t *testing.T) {
	if err := validateOps(operations); err != nil {
		t.Fatal(err)
	}
	for _, k := range []connectorv1.WriteKind{connectorv1.WriteKind_WRITE_KIND_GROUP_MEMBER_ADD, connectorv1.WriteKind_WRITE_KIND_GROUP_MEMBER_REMOVE} {
		w, ok := operations[k]
		if !ok {
			t.Fatalf("%s not registered", k)
		}
		pw, _ := w.PropertyWrite(nil)
		if pw.Op.String() != "GROUP_MEMBERSHIP" {
			t.Fatalf("%s declares %v", k, pw)
		}
	}
}

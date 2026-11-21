package write

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/tier0"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/directory/ldapfilter"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// fakeSchema stands in for ad.Session.EditableAttr: the pure vetting is all that is tested here; the
// directory behaviour of kinds 1-3 is proved against Samba in wk_lab_test.go.
type fakeSchema struct{ attrs, oids map[string]string }

func (f fakeSchema) EditableAttr(name string) (string, ldapfilter.Syntax, error) {
	if c, ok := f.attrs[strings.ToLower(name)]; ok {
		return c, ldapfilter.SynString, nil
	}
	return "", 0, errors.New("not in the snapshot")
}

// AttrOID maps a resolved ldapDisplayName to its attributeID.
func (f fakeSchema) AttrOID(name string) string { return f.oids[strings.ToLower(name)] }

func (fakeSchema) Do(_ context.Context, _ func(*ad.Tx) error) error { return errors.New("unused") }

var schema = fakeSchema{attrs: map[string]string{
	"description": "description", "displayname": "displayName", "samaccountname": "sAMAccountName",
	// the deny-listed names are in the schema snapshot on purpose: the list must win over the schema
	"unicodepwd": "unicodePwd", "useraccountcontrol": "userAccountControl", "member": "member",
	"1.2.840.113556.1.4.90": "unicodePwd",
	"userparameters":        "userParameters", "1.2.840.113556.1.4.138": "userParameters",
}, oids: map[string]string{"userparameters": "1.2.840.113556.1.4.138"}}

func txt(s string) *connectorv1.EditValue {
	return &connectorv1.EditValue{Value: &connectorv1.EditValue_Text{Text: s}}
}

func set(attr string, v ...string) *connectorv1.AttributeEdit {
	e := &connectorv1.AttributeEdit{Attribute: attr, Op: connectorv1.EditOp_EDIT_OP_SET}
	for _, s := range v {
		e.Values = append(e.Values, txt(s))
	}
	return e
}

func code(r *Refusal) connectorv1.ErrorCode {
	if r == nil {
		return connectorv1.ErrorCode_ERROR_CODE_UNSPECIFIED
	}
	return r.Code()
}

// CC-WK-05: the deny-list is checked by name, case-insensitively, by numeric OID and by option, and
// before anything else about the edit.
func TestPrepareEditsDenyList(t *testing.T) {
	for _, name := range []string{"unicodePwd", "UNICODEPWD", "UnicodePwd", "1.2.840.113556.1.4.90", "unicodePwd;binary",
		"description;lang-fr", "userAccountControl", "member", "name", "objectClass", "nTSecurityDescriptor", "gPLink"} {
		_, r := prepareEdits(schema, []*connectorv1.AttributeEdit{set(name, "x")}, false)
		if code(r) != connectorv1.ErrorCode_ERROR_CODE_ATTRIBUTE_NOT_ALLOWED {
			t.Errorf("%q: got %v, want ATTRIBUTE_NOT_ALLOWED", name, code(r))
		}
	}
	// A name the schema does not know is refused the same way (the schema snapshot is the allow-list).
	if _, r := prepareEdits(schema, []*connectorv1.AttributeEdit{set("nosuchattr", "x")}, false); code(r) != connectorv1.ErrorCode_ERROR_CODE_ATTRIBUTE_NOT_ALLOWED {
		t.Errorf("unknown attribute: %v", code(r))
	}
	// An allowed attribute passes and keeps the schema's spelling.
	es, r := prepareEdits(schema, []*connectorv1.AttributeEdit{set("DISPLAYNAME", "x")}, false)
	if r != nil || len(es) != 1 || es[0].name != "displayName" {
		t.Fatalf("allowed edit: %v %v", es, r)
	}
}

func TestPrepareEditsLimitsAndShape(t *testing.T) {
	many := make([]*connectorv1.AttributeEdit, maxEdits+1)
	for i := range many {
		many[i] = set("description", "x")
	}
	if _, r := prepareEdits(schema, many, false); code(r) != connectorv1.ErrorCode_ERROR_CODE_LIMIT_EXCEEDED {
		t.Errorf("65 edits: %v", code(r))
	}
	vals := make([]string, maxEditValues+1)
	if _, r := prepareEdits(schema, []*connectorv1.AttributeEdit{set("description", vals...)}, false); code(r) != connectorv1.ErrorCode_ERROR_CODE_LIMIT_EXCEEDED {
		t.Errorf("1001 values: %v", code(r))
	}
	// A deny-listed attribute inside an over-limit request: the limit is checked first and does not leak.
	cases := map[string][]*connectorv1.AttributeEdit{
		"duplicate":         {set("description", "a"), set("Description", "b")},
		"set without value": {{Attribute: "description", Op: connectorv1.EditOp_EDIT_OP_SET}},
		"clear with value":  {{Attribute: "description", Op: connectorv1.EditOp_EDIT_OP_CLEAR, Values: []*connectorv1.EditValue{txt("x")}}},
		"add without value": {{Attribute: "description", Op: connectorv1.EditOp_EDIT_OP_ADD_VALUE}},
		"unspecified op":    {{Attribute: "description", Values: []*connectorv1.EditValue{txt("x")}}},
	}
	for n, in := range cases {
		if _, r := prepareEdits(schema, in, false); code(r) != connectorv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT {
			t.Errorf("%s: %v", n, code(r))
		}
	}
	// Create's initial attributes are SET only.
	if _, r := prepareEdits(schema, []*connectorv1.AttributeEdit{{Attribute: "description", Op: connectorv1.EditOp_EDIT_OP_CLEAR}}, true); r == nil {
		t.Error("a CLEAR in create.initial passed")
	}
	if _, r := prepareEdits(nil, []*connectorv1.AttributeEdit{set("description", "x")}, false); code(r) != connectorv1.ErrorCode_ERROR_CODE_CAPABILITY_UNSUPPORTED {
		t.Errorf("no directory: %v", code(r))
	}
}

func TestUacAndGroupType(t *testing.T) {
	for _, c := range []struct {
		cls     connectorv1.DirectoryObjectClass
		enabled bool
		want    int32
		ok      bool
	}{{ctUser, true, 512, true}, {ctUser, false, 514, true}, {ctComputer, true, 4096, true}, {ctComputer, false, 4098, true},
		{ctGroup, true, 0, false}, {ctOU, false, 0, false}} {
		if got, ok := uacFor(c.cls, c.enabled); got != c.want || ok != c.ok {
			t.Errorf("uacFor(%v,%v) = %d,%v", c.cls, c.enabled, got, ok)
		}
	}
	for _, c := range []struct {
		s    connectorv1.GroupScope
		sec  bool
		want int32
		ok   bool
	}{{connectorv1.GroupScope_GROUP_SCOPE_GLOBAL, true, -2147483646, true}, {connectorv1.GroupScope_GROUP_SCOPE_DOMAIN_LOCAL, true, -2147483644, true},
		{connectorv1.GroupScope_GROUP_SCOPE_UNIVERSAL, false, 8, true}, {connectorv1.GroupScope_GROUP_SCOPE_GLOBAL, false, 2, true},
		{connectorv1.GroupScope_GROUP_SCOPE_UNSPECIFIED, true, 0, false}} {
		if got, ok := groupTypeFor(c.s, c.sec); got != c.want || ok != c.ok {
			t.Errorf("groupTypeFor(%v,%v) = %d,%v", c.s, c.sec, got, ok)
		}
	}
}

func create(cls connectorv1.DirectoryObjectClass, mod func(*connectorv1.ObjectCreate)) *connectorv1.ObjectCreate {
	oc := &connectorv1.ObjectCreate{ObjectClass: cls, RdnValue: "Jane, Doe",
		Initial: []*connectorv1.AttributeEdit{set("sAMAccountName", "jdoe")}}
	if mod != nil {
		mod(oc)
	}
	return oc
}

func TestVetCreateFields(t *testing.T) {
	good := map[string]*connectorv1.ObjectCreate{
		"user, disabled":      create(ctUser, nil),
		"user enabled+secret": create(ctUser, func(o *connectorv1.ObjectCreate) { o.AccountEnabled, o.HasSecretInput = true, true }),
		"group": create(ctGroup, func(o *connectorv1.ObjectCreate) {
			o.GroupScope = connectorv1.GroupScope_GROUP_SCOPE_GLOBAL
			o.GroupIsSecurity = true
		}),
		"computer": create(ctComputer, func(o *connectorv1.ObjectCreate) {
			o.Initial = []*connectorv1.AttributeEdit{set("sAMAccountName", "PC1$")}
		}),
		"ou": create(ctOU, func(o *connectorv1.ObjectCreate) { o.Initial = nil }),
	}
	for n, oc := range good {
		if _, r := vetCreateFields(schema, oc); r != nil {
			t.Errorf("%s: %v", n, r)
		}
	}
	bad := map[string]*connectorv1.ObjectCreate{
		"no rdn":                   create(ctUser, func(o *connectorv1.ObjectCreate) { o.RdnValue = "" }),
		"unknown class":            create(connectorv1.DirectoryObjectClass_DIRECTORY_OBJECT_CLASS_UNSPECIFIED, nil),
		"enabled without password": create(ctUser, func(o *connectorv1.ObjectCreate) { o.AccountEnabled = true }),
		"secret on a group":        create(ctGroup, func(o *connectorv1.ObjectCreate) { o.HasSecretInput = true }),
		"enabled group":            create(ctGroup, func(o *connectorv1.ObjectCreate) { o.AccountEnabled = true }),
		"group without scope":      create(ctGroup, nil),
		"scope on a user":          create(ctUser, func(o *connectorv1.ObjectCreate) { o.GroupScope = connectorv1.GroupScope_GROUP_SCOPE_GLOBAL }),
		"user without sam":         create(ctUser, func(o *connectorv1.ObjectCreate) { o.Initial = nil }),
		"computer sam lacks $":     create(ctComputer, nil),
		"unicodePwd in initial":    create(ctUser, func(o *connectorv1.ObjectCreate) { o.Initial = append(o.Initial, set("unicodePwd", "x")) }),
		"userAccountControl":       create(ctUser, func(o *connectorv1.ObjectCreate) { o.Initial = append(o.Initial, set("userAccountControl", "512")) }),
	}
	for n, oc := range bad {
		if _, r := vetCreateFields(schema, oc); r == nil {
			t.Errorf("%s: passed", n)
		}
	}
	if _, r := vetCreateFields(schema, nil); r == nil {
		t.Error("a nil arm passed")
	}
}

// CC-WK-29: the change arm must agree with the kind; a secret is carried iff the kind needs one.
func TestShapeCheck(t *testing.T) {
	mk := func(kind connectorv1.WriteKind, ch *connectorv1.WriteChange, apply, secret bool) *Refusal {
		c := &call{kind: kind, change: ch, name: "plan"}
		if apply {
			c.name = "apply"
		}
		if secret {
			c.secret = true
		}
		return shapeCheck(c)
	}
	upd := &connectorv1.WriteChange{Change: &connectorv1.WriteChange_ObjectUpdate{ObjectUpdate: &connectorv1.ObjectUpdate{}}}
	del := &connectorv1.WriteChange{Change: &connectorv1.WriteChange_ObjectDelete{ObjectDelete: &connectorv1.ObjectDelete{}}}
	userSecret := &connectorv1.WriteChange{Change: &connectorv1.WriteChange_ObjectCreate{ObjectCreate: create(ctUser, func(o *connectorv1.ObjectCreate) { o.HasSecretInput = true })}}
	if r := mk(connectorv1.WriteKind_WRITE_KIND_OBJECT_UPDATE, del, false, false); r == nil {
		t.Error("update kind with a delete arm passed")
	}
	if r := mk(connectorv1.WriteKind_WRITE_KIND_OBJECT_UPDATE, nil, false, false); r == nil {
		t.Error("update kind with no arm passed")
	}
	if r := mk(connectorv1.WriteKind_WRITE_KIND_OBJECT_UPDATE, upd, true, false); r != nil {
		t.Errorf("matching update refused: %v", r)
	}
	if r := mk(connectorv1.WriteKind_WRITE_KIND_OBJECT_UPDATE, upd, true, true); r == nil {
		t.Error("a secret on an update passed")
	}
	if r := mk(connectorv1.WriteKind_WRITE_KIND_OBJECT_CREATE, userSecret, true, false); r == nil {
		t.Error("create with has_secret_input and no secret passed")
	}
	if r := mk(connectorv1.WriteKind_WRITE_KIND_OBJECT_CREATE, userSecret, true, true); r != nil {
		t.Errorf("create with its secret refused: %v", r)
	}
}

func TestPropertyWriteDeclarations(t *testing.T) {
	u := func(edits ...*connectorv1.AttributeEdit) *connectorv1.WriteChange {
		return &connectorv1.WriteChange{Change: &connectorv1.WriteChange_ObjectUpdate{ObjectUpdate: &connectorv1.ObjectUpdate{Edits: edits}}}
	}
	pw, err := updatePropertyWrite(u(set("title", "x"), set("description", "y")))
	if err != nil || pw.Op != tier0.OpUpdate || len(pw.Keys) != 2 {
		t.Fatalf("update: %+v %v", pw, err)
	}
	pw, _ = updatePropertyWrite(u(set("Manager", "x")))
	if pw.Op != tier0.OpSetManager {
		t.Errorf("manager set: %v", pw.Op)
	}
	pw, _ = updatePropertyWrite(u(&connectorv1.AttributeEdit{Attribute: "manager", Op: connectorv1.EditOp_EDIT_OP_CLEAR}))
	if pw.Op != tier0.OpClearManager {
		t.Errorf("manager clear: %v", pw.Op)
	}
	if _, err := updatePropertyWrite(u()); err == nil {
		t.Error("an update with no edits declared nothing and passed")
	}
	if _, err := updatePropertyWrite(&connectorv1.WriteChange{}); err == nil {
		t.Error("a missing arm declared a write")
	}
	if pw, err := createPropertyWrite(&connectorv1.WriteChange{Change: &connectorv1.WriteChange_ObjectCreate{ObjectCreate: create(ctComputer, nil)}}); err != nil || pw.Kind != tier0.WriteDevice || pw.Op != tier0.OpCreate {
		t.Errorf("computer create: %+v %v", pw, err)
	}
	if _, err := createPropertyWrite(&connectorv1.WriteChange{Change: &connectorv1.WriteChange_ObjectCreate{ObjectCreate: create(connectorv1.DirectoryObjectClass_DIRECTORY_OBJECT_CLASS_UNSPECIFIED, nil)}}); err == nil {
		t.Error("an unknown class declared a write")
	}
	if _, err := deletePropertyWrite(&connectorv1.WriteChange{}); err == nil {
		t.Error("a delete with no arm declared a write")
	}
	pw, err = deletePropertyWrite(&connectorv1.WriteChange{Change: &connectorv1.WriteChange_ObjectDelete{ObjectDelete: &connectorv1.ObjectDelete{}}})
	if err != nil || pw.Plane != tier0.PlaneAD || pw.Op != tier0.OpDelete || len(pw.Keys) != 0 {
		t.Errorf("delete declared %+v %v; want the AD DELETE op with no keys (never UPDATE: contract 8.10.9 R1)", pw, err)
	}
}

// CC-WRITE-30 (unit half): deleteRecheck hands the §8.9 guard the DELETE op with the kind of the live
// class, and a token with no checker refuses. The decision itself is tier0's (dynprop_test.go).
func TestDeleteRecheckUsesTheLiveClass(t *testing.T) {
	var seen []tier0.PropertyWrite
	// A guard that refuses exactly what the contract table refuses under a memberOf closure rule.
	tok := Authorised{p: &pass{recheck: func(_ context.Context, w tier0.PropertyWrite, target guid.GUID, step string) *Refusal {
		seen = append(seen, w)
		if w.Op == tier0.OpDelete && w.Kind == tier0.WriteGroup {
			return propertyRefusal(w, target, step, tier0.ReasonDesignatedDynamicRule, stConnectorSet)
		}
		return nil
	}}}
	target := mk(7)
	for _, c := range []struct {
		class   connectorv1.DirectoryObjectClass
		kind    tier0.WriteKind
		refused bool
	}{
		{connectorv1.DirectoryObjectClass_DIRECTORY_OBJECT_CLASS_GROUP, tier0.WriteGroup, true},
		{connectorv1.DirectoryObjectClass_DIRECTORY_OBJECT_CLASS_USER, tier0.WriteUser, false},
		{connectorv1.DirectoryObjectClass_DIRECTORY_OBJECT_CLASS_COMPUTER, tier0.WriteDevice, false},
		{connectorv1.DirectoryObjectClass_DIRECTORY_OBJECT_CLASS_CONTACT, tier0.WriteUser, false},
		{connectorv1.DirectoryObjectClass_DIRECTORY_OBJECT_CLASS_ORGANIZATIONAL_UNIT, tier0.WriteUser, false},
	} {
		seen = nil
		r := deleteRecheck(context.Background(), tok, c.class, target, false)
		if (r != nil) != c.refused {
			t.Errorf("%v: refusal %v, want refused=%v", c.class, r, c.refused)
		}
		if len(seen) != 1 || seen[0].Plane != tier0.PlaneAD || seen[0].Op != tier0.OpDelete || seen[0].Kind != c.kind || len(seen[0].Keys) != 0 {
			t.Errorf("%v: guard saw %+v", c.class, seen)
		}
	}
	if deleteRecheck(context.Background(), Authorised{}, connectorv1.DirectoryObjectClass_DIRECTORY_OBJECT_CLASS_USER, target, false) == nil {
		t.Error("a token with no checker passed the delete recheck")
	}
}

// T-1632 security review F1: deleting an object with direct reports clears each report's manager
// (MS-ADTS 3.1.1.1.6), so the guard is also asked for CLEAR_MANAGER, whatever the class, and its
// refusal wins. Without reports it is not asked.
func TestDeleteRecheckWithReportsAsksClearManager(t *testing.T) {
	target := mk(8)
	for _, c := range []struct {
		name         string
		class        connectorv1.DirectoryObjectClass
		reports      bool
		refuseClear  bool
		wantOps      []tier0.Op
		wantRefusal  bool
		wantKindSeen tier0.WriteKind
	}{
		{"user with reports, manager rule", connectorv1.DirectoryObjectClass_DIRECTORY_OBJECT_CLASS_USER, true, true, []tier0.Op{tier0.OpDelete, tier0.OpClearManager}, true, tier0.WriteUser},
		{"contact with reports, manager rule", connectorv1.DirectoryObjectClass_DIRECTORY_OBJECT_CLASS_CONTACT, true, true, []tier0.Op{tier0.OpDelete, tier0.OpClearManager}, true, tier0.WriteUser},
		{"computer with reports, manager rule", connectorv1.DirectoryObjectClass_DIRECTORY_OBJECT_CLASS_COMPUTER, true, true, []tier0.Op{tier0.OpDelete, tier0.OpClearManager}, true, tier0.WriteUser},
		{"user with reports, no manager rule", connectorv1.DirectoryObjectClass_DIRECTORY_OBJECT_CLASS_USER, true, false, []tier0.Op{tier0.OpDelete, tier0.OpClearManager}, false, tier0.WriteUser},
		{"user without reports", connectorv1.DirectoryObjectClass_DIRECTORY_OBJECT_CLASS_USER, false, true, []tier0.Op{tier0.OpDelete}, false, 0},
	} {
		var seen []tier0.PropertyWrite
		tok := Authorised{p: &pass{recheck: func(_ context.Context, w tier0.PropertyWrite, tg guid.GUID, step string) *Refusal {
			seen = append(seen, w)
			if w.Op == tier0.OpClearManager && c.refuseClear {
				return propertyRefusal(w, tg, step, tier0.ReasonDesignatedDynamicRule, stConnectorSet)
			}
			return nil
		}}}
		r := deleteRecheck(context.Background(), tok, c.class, target, c.reports)
		if (r != nil) != c.wantRefusal {
			t.Errorf("%s: refusal %v, want %v", c.name, r, c.wantRefusal)
		}
		var ops []tier0.Op
		for _, w := range seen {
			ops = append(ops, w.Op)
		}
		if fmt.Sprint(ops) != fmt.Sprint(c.wantOps) {
			t.Errorf("%s: guard asked %v, want %v", c.name, ops, c.wantOps)
		}
		if c.reports && len(seen) == 2 && (seen[1].Plane != tier0.PlaneAD || seen[1].Kind != c.wantKindSeen || len(seen[1].Keys) != 0) {
			t.Errorf("%s: CLEAR_MANAGER declared as %+v", c.name, seen[1])
		}
	}
}

// ---- kind 3 bodies without a lab (T-1632 review: the recheck must be pinned in CI) ---------------

type fakeConn struct{ dels []string }

func (f *fakeConn) Add(*ldap.AddRequest) error       { return nil }
func (f *fakeConn) Modify(*ldap.ModifyRequest) error { return nil }
func (f *fakeConn) Del(r *ldap.DelRequest) error     { f.dels = append(f.dels, r.DN); return nil }

type fakeDeleteTx struct {
	class     string // most specific objectClass
	reports   [][]byte
	asked     [][]string
	readErr   error
	conn      fakeConn
	sendCalls int
}

func (f *fakeDeleteTx) DCTime() (time.Time, error) { return t0time, nil }
func (f *fakeDeleteTx) Read(_ dn.ObjectRef, attrs []string) (*ad.Entry, error) {
	f.asked = append(f.asked, attrs)
	if f.readErr != nil {
		return nil, f.readErr
	}
	m := map[string][][]byte{"objectClass": {[]byte("top"), []byte(f.class)}, "uSNChanged": {[]byte("100")}}
	if len(f.reports) > 0 {
		m["directReports"] = f.reports
	}
	return ad.NewEntry("CN=Target\\, Test,OU=People,DC=lab,DC=test", m), nil
}
func (f *fakeDeleteTx) ReadDeleted(dn.ObjectRef, []string) (*ad.Entry, error) {
	return nil, errors.New("not deleted")
}
func (f *fakeDeleteTx) HasChildren(dn.ObjectRef) (bool, error) { return false, nil }
func (f *fakeDeleteTx) Send(fn func(ad.WriteConn) error) error {
	f.sendCalls++
	return fn(&f.conn)
}

// deleteRig is a handler whose property guard refuses the ops in refuse, and a token wired to it
// the way the handler wires it for a body.
func deleteRig(t *testing.T) (*rig, Authorised) {
	t.Helper()
	r := newRig(t, nil)
	return r, Authorised{p: &pass{recheck: r.h.recheckProperty}}
}

// refuseDelete is a guard that refuses a GROUP delete and a CLEAR_MANAGER, as the closure rules of
// CC-WRITE-30 do, and allows every other declaration.
type refuseDelete struct {
	group, clearManager bool
	err                 error
	seen                []tier0.PropertyWrite
}

func (g *refuseDelete) CheckPropertyWrite(_ context.Context, w tier0.PropertyWrite) (tier0.DynamicRuleRefusal, error) {
	g.seen = append(g.seen, w)
	if g.err != nil {
		return tier0.DynamicRuleRefusal{}, g.err
	}
	if w.Op == tier0.OpDelete && w.Kind == tier0.WriteGroup && g.group || w.Op == tier0.OpClearManager && g.clearManager {
		return tier0.DynamicRuleRefusal{Refused: true, Reason: tier0.ReasonDesignatedDynamicRule, Stage: tier0.StageConnectorSet, Op: w.Op}, nil
	}
	return tier0.DynamicRuleRefusal{}, nil
}

func TestKind3BodiesRecheckBeforeAnyDelete(t *testing.T) {
	target := mk(9)
	rep := [][]byte{[]byte("CN=Report,OU=People,DC=lab,DC=test")}
	for _, c := range []struct {
		name    string
		class   string
		reports [][]byte
		g       refuseDelete
		refused bool
		reason  string
		kind    string
		op      string
	}{
		{"group, memberOf rule", "group", nil, refuseDelete{group: true}, true, tier0.ReasonDesignatedDynamicRule, "GROUP", "DELETE"},
		{"user, memberOf rule", "user", nil, refuseDelete{group: true}, false, "", "", ""},
		{"computer, memberOf rule", "computer", nil, refuseDelete{group: true}, false, "", "", ""},
		{"user with reports, manager rule", "user", rep, refuseDelete{clearManager: true}, true, tier0.ReasonDesignatedDynamicRule, "USER", "CLEAR_MANAGER"},
		{"contact with reports, manager rule", "contact", rep, refuseDelete{clearManager: true}, true, tier0.ReasonDesignatedDynamicRule, "USER", "CLEAR_MANAGER"},
		{"user without reports, manager rule", "user", nil, refuseDelete{clearManager: true}, false, "", "", ""},
		{"user with reports, memberOf rule only", "user", rep, refuseDelete{group: true}, false, "", "", ""},
		{"guard unavailable", "user", nil, refuseDelete{err: errors.New("graph down")}, true, reasonGuardUnavailable, "USER", "DELETE"},
	} {
		for _, phase := range []string{"plan", "apply"} {
			g := c.g
			r, tok := deleteRig(t)
			r.prov.guard = &g
			tx := &fakeDeleteTx{class: c.class, reports: c.reports}
			var err *Refusal
			if phase == "plan" {
				_, err = planDeleteIn(context.Background(), tok, tx, target)
			} else {
				pre := &connectorv1.TargetPrecondition{UsnChanged: ptr(uint64(100)),
					StateDigest: hashParts(classByObjectClass[c.class].String(), "CN=Target\\, Test,OU=People,DC=lab,DC=test")}
				_, err = applyDeleteIn(context.Background(), tok, tx, target, pre)
			}
			name := c.name + "/" + phase
			if (err != nil) != c.refused {
				t.Errorf("%s: refusal %v, want refused=%v", name, err, c.refused)
				continue
			}
			sawReports := false
			for _, a := range tx.asked {
				for _, n := range a {
					sawReports = sawReports || strings.EqualFold(n, "directReports")
				}
			}
			if !sawReports {
				t.Errorf("%s: the read did not ask for directReports (%v)", name, tx.asked)
			}
			if !c.refused {
				if phase == "apply" && (tx.sendCalls != 1 || len(tx.conn.dels) != 1) {
					t.Errorf("%s: sends %d dels %v, want one delete", name, tx.sendCalls, tx.conn.dels)
				}
				continue
			}
			if tx.sendCalls != 0 || len(tx.conn.dels) != 0 {
				t.Errorf("%s: a delete was sent after a refusal (%v)", name, tx.conn.dels)
			}
			// The audit record: the reason, the declared kind and op, at the stage the guard gave.
			if e := r.h.finish(&Event{Op: phase}, err); e == nil {
				t.Fatalf("%s: finish dropped the refusal", name)
			}
			ev := r.rec.last()
			if ev.Reason != c.reason || ev.PropertyKind != c.kind || ev.PropertyOp != c.op || ev.Code != connectorv1.ErrorCode_ERROR_CODE_TIER0_REFUSED.String() {
				t.Errorf("%s: event reason %q kind %q op %q code %q", name, ev.Reason, ev.PropertyKind, ev.PropertyOp, ev.Code)
			}
			wantStage := connectorv1.Tier0RefusalStage_TIER0_REFUSAL_STAGE_CONNECTOR_SET
			if c.reason == reasonGuardUnavailable {
				wantStage = connectorv1.Tier0RefusalStage_TIER0_REFUSAL_STAGE_LIVE_REREAD
			}
			if got := connErr(t, err).GetTier0Refused().GetStage(); got != wantStage {
				t.Errorf("%s: stage %s, want %s", name, got, wantStage)
			}
		}
	}
}

// A read that fails cannot say whether the object has reports, so nothing is deleted.
func TestKind3ReadFailureRefusesBeforeDelete(t *testing.T) {
	r, tok := deleteRig(t)
	r.prov.guard = &refuseDelete{}
	tx := &fakeDeleteTx{class: "user", readErr: errors.New("boom")}
	if _, err := planDeleteIn(context.Background(), tok, tx, mk(9)); err == nil || tx.sendCalls != 0 {
		t.Errorf("plan err %v sends %d", err, tx.sendCalls)
	}
}

func TestCapabilitiesSupported(t *testing.T) {
	for _, c := range Capabilities() {
		if c.GetState() != connectorv1.SupportState_SUPPORT_STATE_SUPPORTED {
			t.Errorf("%s: %s", c.GetOperation(), c.GetState())
		}
	}
}

// ALREADY_APPLIED must not accept an object whose userAccountControl differs from the one value
// a create sets (extra bits mean it is not activeDIQ's own create).
func TestCreateMatchesComparesUserAccountControl(t *testing.T) {
	oc := create(ctUser, nil) // disabled: 514
	p := &createPlanned{oc: oc}
	entry := func(uac string) *ad.Entry {
		return ad.NewEntry("CN=x,DC=lab,DC=test", map[string][][]byte{
			"objectClass":        {[]byte("top"), []byte("person"), []byte("organizationalPerson"), []byte("user")},
			"userAccountControl": {[]byte(uac)},
		})
	}
	if !p.matches(entry("514"), nil) {
		t.Fatal("exact UAC must match")
	}
	for _, uac := range []string{"512", "66050", "546", ""} {
		if p.matches(entry(uac), nil) {
			t.Errorf("UAC %q wrongly matched", uac)
		}
	}
}

// A user create that carries a password reaches the directory: the step-4 secret rule belongs to the
// kinds that declare an Arm (account kinds), not to the object kinds, whose rule is shapeCheck at step 1.
// Found in review of the T-1623 merge with main; no non-lab test sent Apply with a create and secret_input.
func TestStepFourShapeLeavesObjectKindsToShapeCheck(t *testing.T) {
	apply := func(ch *connectorv1.WriteChange, secret bool) *call {
		return &call{kind: connectorv1.WriteKind_WRITE_KIND_OBJECT_CREATE, change: ch, name: "apply", secret: secret}
	}
	userSecret := &connectorv1.WriteChange{Change: &connectorv1.WriteChange_ObjectCreate{ObjectCreate: create(ctUser, func(o *connectorv1.ObjectCreate) { o.HasSecretInput = true })}}
	userNoSecret := &connectorv1.WriteChange{Change: &connectorv1.WriteChange_ObjectCreate{ObjectCreate: create(ctUser, nil)}}
	for name, c := range map[string]*call{"user create with a password": apply(userSecret, true), "user create without": apply(userNoSecret, false)} {
		if r := stepFourShape(objectCreateOp, c); r != nil {
			t.Errorf("%s refused at step 4: %v", name, r)
		}
		if r := shapeCheck(c); r != nil {
			t.Errorf("%s refused by shapeCheck: %v", name, r)
		}
	}
	// The same presence mismatch is still refused, by shapeCheck.
	if r := shapeCheck(apply(userSecret, false)); r == nil {
		t.Error("a create that declares a secret but carries none was accepted")
	}
	if r := shapeCheck(apply(userNoSecret, true)); r == nil {
		t.Error("a create that carries a secret it did not declare was accepted")
	}
	// A kind with an Arm keeps its step-4 rule: a reset wants the secret, an enable must not carry one.
	reset := WriteOp{Arm: func(*connectorv1.WriteChange) bool { return true }, WantsSecret: true}
	enable := WriteOp{Arm: func(*connectorv1.WriteChange) bool { return true }}
	if r := stepFourShape(reset, &call{name: "apply", secret: false}); r == nil {
		t.Error("a reset with no secret_input was accepted")
	}
	if r := stepFourShape(enable, &call{name: "apply", secret: true}); r == nil {
		t.Error("an enable carrying secret_input was accepted")
	}
	if r := stepFourShape(reset, &call{name: "apply", secret: true}); r != nil {
		t.Errorf("a reset with secret_input refused: %v", r)
	}
}

// CC-TS-07: userParameters (Terminal Services blob) is never written, whatever the spelling.
func TestUserParameters_deny_listed(t *testing.T) {
	for _, name := range []string{"userParameters", "userparameters", "USERPARAMETERS", "1.2.840.113556.1.4.138", "userParameters;binary"} {
		for _, createInitial := range []bool{false, true} {
			_, r := prepareEdits(schema, []*connectorv1.AttributeEdit{set(name, "x")}, createInitial)
			if code(r) != connectorv1.ErrorCode_ERROR_CODE_ATTRIBUTE_NOT_ALLOWED {
				t.Errorf("%q create=%v: got %v, want ATTRIBUTE_NOT_ALLOWED", name, createInitial, code(r))
			}
		}
	}
	// The deny check itself, not through EditableAttr.
	for _, n := range []string{"userParameters", "USERPARAMETERS"} {
		if !isDenied(n) {
			t.Errorf("isDenied(%q) = false", n)
		}
	}
}

// A schema that gives the userParameters attributeID another ldapDisplayName is still refused (OID match).
func TestUserParameters_renamed_refused_by_OID(t *testing.T) {
	renamed := fakeSchema{
		attrs: map[string]string{"tsblob": "tsBlob"},
		oids:  map[string]string{"tsblob": "1.2.840.113556.1.4.138"},
	}
	_, r := prepareEdits(renamed, []*connectorv1.AttributeEdit{set("tsBlob", "x")}, false)
	if code(r) != connectorv1.ErrorCode_ERROR_CODE_ATTRIBUTE_NOT_ALLOWED {
		t.Fatalf("renamed userParameters: got %v", code(r))
	}
}

func TestDenyList_userParameters_OID_row(t *testing.T) {
	if !isDeniedOID("1.2.840.113556.1.4.138") {
		t.Fatal("the userParameters OID row is missing from the deny-list")
	}
	if !isDenied("1.2.840.113556.1.4.138") {
		t.Fatal("isDenied does not match the OID")
	}
}

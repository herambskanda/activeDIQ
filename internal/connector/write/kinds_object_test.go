package write

import (
	"context"

	"errors"
	"github.com/skenzeriq/activediq/internal/connector/ad"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/connector/tier0"
	"github.com/skenzeriq/activediq/internal/directory/ldapfilter"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// fakeSchema stands in for ad.Session.EditableAttr: the pure vetting is all that is tested here; the
// directory behaviour of kinds 1-3 is proved against Samba in wk_lab_test.go.
type fakeSchema struct{ attrs map[string]string }

func (f fakeSchema) EditableAttr(name string) (string, ldapfilter.Syntax, error) {
	if c, ok := f.attrs[strings.ToLower(name)]; ok {
		return c, ldapfilter.SynString, nil
	}
	return "", 0, errors.New("not in the snapshot")
}

func (fakeSchema) Do(_ context.Context, _ func(*ad.Tx) error) error { return errors.New("unused") }

var schema = fakeSchema{attrs: map[string]string{
	"description": "description", "displayname": "displayName", "samaccountname": "sAMAccountName",
	// the deny-listed names are in the schema snapshot on purpose: the list must win over the schema
	"unicodepwd": "unicodePwd", "useraccountcontrol": "userAccountControl", "member": "member",
	"1.2.840.113556.1.4.90": "unicodePwd",
}}

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
			c.secret = &connectorv1.SecretValue{}
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
}

func TestCapabilitiesSupported(t *testing.T) {
	for _, c := range Capabilities() {
		if c.GetState() != connectorv1.SupportState_SUPPORT_STATE_SUPPORTED {
			t.Errorf("%s: %s", c.GetOperation(), c.GetState())
		}
	}
}

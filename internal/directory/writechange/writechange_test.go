package writechange_test

import (
	"reflect"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/skenzeriq/activediq/internal/directory/writechange"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

func txt(s string) *connectorv1.EditValue {
	return &connectorv1.EditValue{Value: &connectorv1.EditValue_Text{Text: s}}
}

func TestRoundTrip(t *testing.T) {
	create := &connectorv1.WriteChange{Change: &connectorv1.WriteChange_ObjectCreate{ObjectCreate: &connectorv1.ObjectCreate{
		ObjectClass: connectorv1.DirectoryObjectClass_DIRECTORY_OBJECT_CLASS_GROUP, RdnValue: "a,b+c\"d",
		GroupScope: connectorv1.GroupScope_GROUP_SCOPE_UNIVERSAL, GroupIsSecurity: true, AccountEnabled: true, HasSecretInput: true,
		Initial: []*connectorv1.AttributeEdit{{Attribute: "description", Op: connectorv1.EditOp_EDIT_OP_SET, Values: []*connectorv1.EditValue{txt("ü ~ x:y")}}},
	}}}
	update := &connectorv1.WriteChange{Change: &connectorv1.WriteChange_ObjectUpdate{ObjectUpdate: &connectorv1.ObjectUpdate{Edits: []*connectorv1.AttributeEdit{
		{Attribute: "mail", Op: connectorv1.EditOp_EDIT_OP_CLEAR},
		{Attribute: "otherTelephone", Op: connectorv1.EditOp_EDIT_OP_ADD_VALUE, Values: []*connectorv1.EditValue{
			txt("1"), {Value: &connectorv1.EditValue_Int32Value{Int32Value: -3}}, {Value: &connectorv1.EditValue_Boolean{Boolean: true}},
			{Value: &connectorv1.EditValue_Octets{Octets: []byte{0, 255}}},
			{Value: &connectorv1.EditValue_ObjectRef{ObjectRef: &connectorv1.Guid{Value: make([]byte, 16)}}}}},
	}}}}
	del := &connectorv1.WriteChange{Change: &connectorv1.WriteChange_ObjectDelete{ObjectDelete: &connectorv1.ObjectDelete{}}}
	for _, c := range []*connectorv1.WriteChange{create, update, del} {
		key, attrs, err := writechange.Encode(c)
		if err != nil {
			t.Fatal(err)
		}
		back, err := writechange.Decode(key, attrs)
		if err != nil {
			t.Fatal(err)
		}
		if !proto.Equal(c, back) {
			t.Fatalf("%s: round trip differs", key)
		}
	}
}

func TestDecodeRefusesWhatEncodeCannotProduce(t *testing.T) {
	_, attrs, _ := writechange.Encode(&connectorv1.WriteChange{Change: &connectorv1.WriteChange_ObjectCreate{ObjectCreate: &connectorv1.ObjectCreate{
		ObjectClass: connectorv1.DirectoryObjectClass_DIRECTORY_OBJECT_CLASS_USER, RdnValue: "x"}}})
	dup := append(append(attrs[:0:0], attrs...), attrs[0])
	if _, err := writechange.Decode(writechange.KeyObjectCreate, dup); err == nil {
		t.Fatal("duplicate structural field accepted")
	}
	if _, err := writechange.Decode("ad.object.createUser", attrs); err == nil {
		t.Fatal("unknown key accepted")
	}
}

func TestGroupMemberKindsRoundTrip(t *testing.T) {
	const m = "0a1b2c3d-0000-4000-8000-00000000abcd"
	for _, key := range []string{writechange.KeyGroupMemberAdd, writechange.KeyGroupMemberRemove} {
		for _, class := range []string{"user", "computer", "contact", "group"} {
			attrs, err := writechange.GroupMemberAttrs(m, class)
			if err != nil {
				t.Fatal(err)
			}
			ch, err := writechange.Decode(key, attrs)
			if err != nil {
				t.Fatalf("%s/%s: %v", key, class, err)
			}
			k2, back, err := writechange.Encode(ch)
			if err != nil || k2 != key || !reflect.DeepEqual(back, attrs) {
				t.Fatalf("%s/%s: %v %v %v", key, class, k2, back, err)
			}
		}
	}
}

func TestGroupMemberDecodeRefusesAnythingElse(t *testing.T) {
	const m = "0a1b2c3d-0000-4000-8000-00000000abcd"
	good, _ := writechange.GroupMemberAttrs(m, "user")
	bad := [][]step.Attr{
		nil,
		good[:1],
		good[1:],
		append(append([]step.Attr(nil), good...), good[0]),
		append(append([]step.Attr(nil), good...), attr("~extra", "x")),
		{attr(writechange.AttrMember, "0A1B2C3D-0000-4000-8000-00000000ABCD"), good[1]},
		{attr(writechange.AttrMember, "not-a-guid"), good[1]},
		{good[0], attr(writechange.AttrMemberClass, "organizationalUnit")},
		{good[0], attr(writechange.AttrMemberClass, "foreignSecurityPrincipal")},
		{{Name: writechange.AttrMember, Secret: true}, good[1]},
	}
	for i, a := range bad {
		if _, err := writechange.Decode(writechange.KeyGroupMemberAdd, a); err == nil {
			t.Errorf("case %d decoded", i)
		}
	}
	if _, err := writechange.GroupMemberAttrs(m, "organizationalUnit"); err == nil {
		t.Error("an OU is not a member class")
	}
}

func attr(name, v string) step.Attr { return step.Attr{Name: name, Values: []string{v}} }

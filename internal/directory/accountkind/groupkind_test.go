package accountkind

import (
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/skenzeriq/activediq/internal/platform/operation/digest"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

const gm = "0a1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d"

func TestGroupKindsRoundTrip(t *testing.T) {
	for _, key := range []string{KeyGroupMemberAdd, KeyGroupMemberRemove} {
		for _, cls := range []string{ClassUser, ClassComputer, ClassContact, ClassGroup} {
			attrs := []digest.Attr{{Name: AttrMember, Values: []string{gm}}, {Name: AttrMemberClass, Values: []string{cls}}}
			ch, err := GroupChangeFromAttrs(key, attrs)
			if err != nil {
				t.Fatalf("%s/%s: %v", key, cls, err)
			}
			back, err := GroupAttrsOf(key, ch)
			if err != nil {
				t.Fatal(err)
			}
			ch2, err := GroupChangeFromAttrs(key, back)
			if err != nil || !proto.Equal(ch, ch2) {
				t.Fatalf("%s/%s: not stable", key, cls)
			}
		}
	}
}

func TestGroupKindsRefuseStrayAttrs(t *testing.T) {
	ok := func() []digest.Attr {
		return []digest.Attr{{Name: AttrMember, Values: []string{gm}}, {Name: AttrMemberClass, Values: []string{ClassUser}}}
	}
	bad := map[string][]digest.Attr{
		"none":        nil,
		"extra":       append(ok(), digest.Attr{Name: "x", Values: []string{"1"}}),
		"dup":         {ok()[0], ok()[0]},
		"dn member":   {{Name: AttrMember, Values: []string{"CN=a,DC=x"}}, ok()[1]},
		"upper guid":  {{Name: AttrMember, Values: []string{"0A1B2C3D-4E5F-6A7B-8C9D-0E1F2A3B4C5D"}}, ok()[1]},
		"ou class":    {ok()[0], {Name: AttrMemberClass, Values: []string{"organizationalUnit"}}},
		"secret flag": {ok()[0], {Name: AttrMemberClass, Secret: true}},
		"two values":  {ok()[0], {Name: AttrMemberClass, Values: []string{"user", "group"}}},
	}
	for n, a := range bad {
		if _, err := GroupChangeFromAttrs(KeyGroupMemberAdd, a); err == nil {
			t.Errorf("%s accepted", n)
		}
	}
	if _, err := GroupChangeFromAttrs(KeyUnlock, ok()); err == nil {
		t.Error("a non-group key accepted")
	}
	// An arm of the other kind, and a class outside the matrix, are not encodable.
	add := &connectorv1.WriteChange{Change: &connectorv1.WriteChange_GroupMemberAdd{GroupMemberAdd: &connectorv1.GroupMemberAdd{
		Member: &connectorv1.Guid{Value: make([]byte, 16)}, MemberClass: connectorv1.DirectoryObjectClass_DIRECTORY_OBJECT_CLASS_ORGANIZATIONAL_UNIT}}}
	if _, err := GroupAttrsOf(KeyGroupMemberAdd, add); err == nil {
		t.Error("OU member class encoded")
	}
	if _, err := GroupAttrsOf(KeyGroupMemberRemove, add); err == nil {
		t.Error("wrong arm encoded")
	}
}

func TestComputerResetCarriesNoSecretAndNoAttrs(t *testing.T) {
	ch, err := ChangeFromAttrs(KeyComputerReset, nil)
	if err != nil || ch.GetComputerAccountReset() == nil {
		t.Fatalf("%v", err)
	}
	if _, err := AttrsOf(KeyComputerReset, ch, true); err == nil {
		t.Error("secret input accepted for kind 13")
	}
	if _, err := AttrsOf(KeyComputerReset, ch, false); err != nil {
		t.Error(err)
	}
	if _, err := ChangeFromAttrs(KeyComputerReset, []digest.Attr{{Name: AttrSecret, Secret: true}}); err == nil {
		t.Error("attrs accepted")
	}
	if sp, _ := ByKey(KeyComputerReset); sp.AllowsClass(ClassUser) || !sp.AllowsClass(ClassComputer) {
		t.Error("kind 13 class matrix")
	}
}

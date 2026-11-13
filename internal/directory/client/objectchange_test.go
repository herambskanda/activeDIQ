package client

import (
	"errors"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/accountkind"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/secret"
)

const (
	objID = "11111111-2222-3333-4444-555555555555"
	objNC = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	objNP = "99999999-8888-7777-6666-555555555555"
)

func objOp(key string, attrs ...step.Attr) WriteOp {
	return WriteOp{DigestKind: key, Target: authority.TargetRef{Connection: "c1", GUID: objID, NC: objNC}, Attrs: attrs}
}

func one(n, v string) step.Attr { return step.Attr{Name: n, Values: []string{v}} }

// TestKindTableStructureClass: the object move, rename and restore rows carry the move class. The closed
// list, the classes and the one-WriteKind-per-row rule for every row are TestKindTableClosed in write_test.go.
func TestKindTableStructureClass(t *testing.T) {
	for _, k := range []string{DigestObjectMove, DigestObjectRename, DigestObjectRestore} {
		if kindTable[k].Class != ClassMove {
			t.Errorf("%s: class %q, want move", k, kindTable[k].Class)
		}
	}
}

func TestObjectChangeConstructors(t *testing.T) {
	w, err := objOp(DigestObjectMove, one(AttrNewParent, objNP), one(AttrNewParentNC, objNC)).derive()
	if err != nil {
		t.Fatal(err)
	}
	m := w.change.GetObjectMove()
	if m == nil || formatUUID(m.GetNewParent().GetObject().GetValue()) != objNP || formatUUID(m.GetNewParent().GetNcGuid().GetValue()) != objNC {
		t.Fatalf("move change: %v", w.change)
	}
	w, err = objOp(DigestObjectRename, one(AttrNewRDN, "Smith, J+\"x\"")).derive()
	if err != nil || w.change.GetObjectRename().GetNewRdnValue() != "Smith, J+\"x\"" {
		t.Fatalf("rename change: %v %v", w.change, err)
	}
	w, err = objOp(DigestObjectRestore, one(AttrNewParent, objNP), one(AttrNewParentNC, objNC), one(AttrRDN, "Bob")).derive()
	if err != nil {
		t.Fatal(err)
	}
	if r := w.change.GetObjectRestore(); r == nil || r.GetRdnValue() != "Bob" || formatUUID(r.GetNewParent().GetObject().GetValue()) != objNP {
		t.Fatalf("restore change: %v", w.change)
	}
}

func TestObjectChangeRefusesMalformedAttrs(t *testing.T) {
	bad := map[string]WriteOp{
		"missing nc":          objOp(DigestObjectMove, one(AttrNewParent, objNP)),
		"extra attr":          objOp(DigestObjectMove, one(AttrNewParent, objNP), one(AttrNewParentNC, objNC), one("x", "y")),
		"upper-case parent":   objOp(DigestObjectMove, one(AttrNewParent, "99999999-8888-7777-6666-55555555555A"), one(AttrNewParentNC, objNC)),
		"two values":          objOp(DigestObjectRename, step.Attr{Name: AttrNewRDN, Values: []string{"a", "b"}}),
		"empty rdn":           objOp(DigestObjectRename, one(AttrNewRDN, "")),
		"secret":              objOp(DigestObjectRename, step.Attr{Name: AttrNewRDN, Values: []string{"a"}, Secret: true}),
		"duplicate":           objOp(DigestObjectRename, one(AttrNewRDN, "a"), one(AttrNewRDN, "a")),
		"restore without rdn": objOp(DigestObjectRestore, one(AttrNewParent, objNP), one(AttrNewParentNC, objNC)),
	}
	for name, op := range bad {
		if _, err := op.derive(); !errors.Is(err, ErrInvalidOp) {
			t.Errorf("%s: %v", name, err)
		}
	}
	op := objOp(DigestObjectRename, one(AttrNewRDN, "a"))
	op.Target.Parent = objNP
	if _, err := op.derive(); !errors.Is(err, ErrInvalidOp) {
		t.Errorf("target parent: %v", err)
	}
	op = objOp(DigestObjectRename, one(AttrNewRDN, "a"))
	op.Target.GUID = "11111111-2222-3333-4444-55555555555A"
	if _, err := op.derive(); !errors.Is(err, ErrInvalidOp) {
		t.Errorf("upper-case target: %v", err)
	}
}

// Acceptance 2 / CC-WK-31: keys outside the registered set are unknown kinds. All ten kinds of contract
// 8.10.1 are registered now, so the unknown ones are misspelled or invented keys.
func TestUnregisteredKindsAreUnknown(t *testing.T) {
	for _, k := range []string{"ad.object.createUser", "AD.object.move", "ad.object.Create", "ad.user.reset", ""} {
		_, err := objOp(k).derive()
		if k == "" {
			if !errors.Is(err, ErrInvalidOp) {
				t.Errorf("empty: %v", err)
			}
			continue
		}
		if !errors.Is(err, ErrUnknownKind) {
			t.Errorf("%q: %v", k, err)
		}
	}
}

// A secret handed to a kind that carries none is refused, not dropped (kinds 4-6 and the account kinds).
func TestSecretInputOnKindsWithoutOneIsRefused(t *testing.T) {
	for _, op := range []WriteOp{
		objOp(DigestObjectMove, one(AttrNewParent, objNP), one(AttrNewParentNC, objNC)),
		objOp(DigestObjectRename, one(AttrNewRDN, "x")),
		{DigestKind: accountkind.KeyUnlock, Target: acctTarget},
	} {
		op.SecretInput = secret.FromBytes([]byte("Passw0rd!"))
		if _, err := op.derive(); !errors.Is(err, ErrInvalidOp) {
			t.Errorf("%s: got %v, want ErrInvalidOp", op.DigestKind, err)
		}
	}
}

package client

import (
	"fmt"

	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// change derives the WriteChange of kind from the operation's Attrs: one constructor per kind, and
// nothing the digest does not cover reaches the wire. A kind with no constructor sends no change.
// An operation whose Attrs do not have exactly the shape of the kind is ErrInvalidOp.
func (op WriteOp) change(kind connectorv1.WriteKind) (*connectorv1.WriteChange, error) {
	switch kind {
	case connectorv1.WriteKind_WRITE_KIND_OBJECT_MOVE:
		return op.moveChange()
	case connectorv1.WriteKind_WRITE_KIND_OBJECT_RENAME:
		return op.renameChange()
	case connectorv1.WriteKind_WRITE_KIND_OBJECT_RESTORE:
		return op.restoreChange()
	}
	return nil, nil
}

func (op WriteOp) moveChange() (*connectorv1.WriteChange, error) {
	v, err := op.objectAttrs(AttrNewParent, AttrNewParentNC)
	if err != nil {
		return nil, err
	}
	np, err := writeTarget(v[AttrNewParent], v[AttrNewParentNC])
	if err != nil {
		return nil, err
	}
	return &connectorv1.WriteChange{Change: &connectorv1.WriteChange_ObjectMove{ObjectMove: &connectorv1.ObjectMove{NewParent: np}}}, nil
}

func (op WriteOp) renameChange() (*connectorv1.WriteChange, error) {
	v, err := op.objectAttrs(AttrNewRDN)
	if err != nil {
		return nil, err
	}
	return &connectorv1.WriteChange{Change: &connectorv1.WriteChange_ObjectRename{ObjectRename: &connectorv1.ObjectRename{NewRdnValue: v[AttrNewRDN]}}}, nil
}

func (op WriteOp) restoreChange() (*connectorv1.WriteChange, error) {
	v, err := op.objectAttrs(AttrNewParent, AttrNewParentNC, AttrRDN)
	if err != nil {
		return nil, err
	}
	np, err := writeTarget(v[AttrNewParent], v[AttrNewParentNC])
	if err != nil {
		return nil, err
	}
	return &connectorv1.WriteChange{Change: &connectorv1.WriteChange_ObjectRestore{ObjectRestore: &connectorv1.ObjectRestore{NewParent: np, RdnValue: v[AttrRDN]}}}, nil
}

// objectAttrs checks the shape shared by kinds 4 to 6 and returns each attribute's one value. The
// target carries no Class, Parent or RDN (they would be digest-covered fields the connector cannot
// recompute); Target.GUID and Target.NC are canonical lower-case GUID text, because the connector
// renders them from bytes and recomputes the digest from that text.
func (op WriteOp) objectAttrs(names ...string) (map[string]string, error) {
	t := op.Target
	if t.Class != "" || t.Parent != "" || t.RDN != "" || !canonicalUUID(t.GUID) || !canonicalUUID(string(t.NC)) {
		return nil, fmt.Errorf("%w: object target", ErrInvalidOp)
	}
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	out := map[string]string{}
	for _, a := range op.Attrs {
		if !want[a.Name] || a.Secret || len(a.Values) != 1 || a.Values[0] == "" {
			return nil, fmt.Errorf("%w: attribute", ErrInvalidOp)
		}
		if _, dup := out[a.Name]; dup {
			return nil, fmt.Errorf("%w: attribute", ErrInvalidOp)
		}
		out[a.Name] = a.Values[0]
	}
	if len(out) != len(names) {
		return nil, fmt.Errorf("%w: attribute", ErrInvalidOp)
	}
	return out, nil
}

func writeTarget(object, nc string) (*connectorv1.WriteTarget, error) {
	if !canonicalUUID(object) || !canonicalUUID(nc) {
		return nil, fmt.Errorf("%w: parent", ErrInvalidOp)
	}
	o, _ := parseUUID(object)
	n, _ := parseUUID(nc)
	return &connectorv1.WriteTarget{Object: &connectorv1.Guid{Value: o}, NcGuid: &connectorv1.Guid{Value: n}}, nil
}

// canonicalUUID is true for the lower-case 8-4-4-4-12 form.
func canonicalUUID(s string) bool {
	b, err := parseUUID(s)
	return err == nil && formatUUID(b) == s
}

package writechange

import (
	"fmt"

	"github.com/skenzeriq/activediq/internal/platform/operation/digest"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// Edit is one attribute edit of an update, with text values. Op is "set", "clear", "add" or "remove".
type Edit struct {
	Op        string
	Attribute string
	Values    []string
}

// CreateSpec is a user create as the lifecycle Action plans it. Every attribute value is text.
type CreateSpec struct {
	// Class is the object class label ("user", "group", "computer", "contact", "organizationalUnit");
	// empty means user.
	Class string
	RDN   string
	// GroupScope ("global", "domainLocal", "universal") and GroupSecurity apply to a group only.
	GroupScope    string
	GroupSecurity bool
	// Enabled creates the account enabled; a user then needs a password (HasSecret).
	Enabled   bool
	HasSecret bool
	Set       []Edit // Op "set" only
}

func ops() map[string]connectorv1.EditOp {
	return map[string]connectorv1.EditOp{
		"set": connectorv1.EditOp_EDIT_OP_SET, "clear": connectorv1.EditOp_EDIT_OP_CLEAR,
		"add": connectorv1.EditOp_EDIT_OP_ADD_VALUE, "remove": connectorv1.EditOp_EDIT_OP_REMOVE_VALUE,
	}
}

func edits(in []Edit) ([]*connectorv1.AttributeEdit, error) {
	var out []*connectorv1.AttributeEdit
	for _, e := range in {
		op, ok := ops()[e.Op]
		if !ok {
			return nil, ErrEncoding
		}
		ae := &connectorv1.AttributeEdit{Attribute: e.Attribute, Op: op}
		for _, v := range e.Values {
			ae.Values = append(ae.Values, &connectorv1.EditValue{Value: &connectorv1.EditValue_Text{Text: v}})
		}
		out = append(out, ae)
	}
	return out, nil
}

// CreateAttrs returns the digest attributes of a create. It goes through Encode, so the list is
// the one the connector's Decode round-trips.
func CreateAttrs(c CreateSpec) ([]digest.Attr, error) {
	ed, err := edits(c.Set)
	if err != nil {
		return nil, err
	}
	class := connectorv1.DirectoryObjectClass_DIRECTORY_OBJECT_CLASS_USER
	if c.Class != "" {
		var ok bool
		if class, ok = ClassOf(c.Class); !ok {
			return nil, ErrEncoding
		}
	}
	oc := &connectorv1.ObjectCreate{ObjectClass: class, RdnValue: c.RDN,
		Initial: ed, AccountEnabled: c.Enabled, HasSecretInput: c.HasSecret, GroupIsSecurity: c.GroupSecurity}
	if c.GroupScope != "" {
		for k, v := range scopeNames {
			if v == c.GroupScope {
				oc.GroupScope = k
			}
		}
		if oc.GroupScope == 0 {
			return nil, ErrEncoding
		}
	}
	_, attrs, err := Encode(&connectorv1.WriteChange{Change: &connectorv1.WriteChange_ObjectCreate{ObjectCreate: oc}})
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	return attrs, nil
}

// UpdateAttrs returns the digest attributes of an update.
func UpdateAttrs(in []Edit) ([]digest.Attr, error) {
	ed, err := edits(in)
	if err != nil {
		return nil, err
	}
	_, attrs, err := Encode(&connectorv1.WriteChange{Change: &connectorv1.WriteChange_ObjectUpdate{ObjectUpdate: &connectorv1.ObjectUpdate{Edits: ed}}})
	return attrs, err
}

// GroupMemberAttrs returns the digest attributes of kinds 11 and 12: the member's objectGUID (canonical
// lower-case text) and the class the Action declared ("user", "computer", "contact" or "group"). It goes
// through Encode, so the list is the one the connector's Decode round-trips.
func GroupMemberAttrs(member, class string) ([]digest.Attr, error) {
	g, err := guidFromText(member)
	if err != nil {
		return nil, err
	}
	c, ok := ClassOf(class)
	if !ok {
		return nil, ErrEncoding
	}
	_, attrs, err := Encode(&connectorv1.WriteChange{Change: &connectorv1.WriteChange_GroupMemberAdd{
		GroupMemberAdd: &connectorv1.GroupMemberAdd{Member: g, MemberClass: c}}})
	return attrs, err
}

// Package writechange is the one place a plan-digest attribute list and the connector's typed
// WriteChange are converted into each other (contract §8.10.2 rules 4 and 5). The server derives the
// WriteChange from the digest-covered Attrs with Decode; the connector recomputes the digest from the
// WriteChange it received with Encode. Both sides therefore agree by construction, and no wire field
// can differ from what the digest covers.
//
// Encoding (names are the step.Attr names; a name that starts with "~" is a structural field, any
// other name is "<op>:<ldapDisplayName>"):
//
//	create: ~class, ~rdn, ~scope, ~security, ~enabled, ~secret (presence only), set:<attr>…
//	update: set:/clear:/add:/remove:<attr>
//	delete: no attributes
//
// Values are tagged: s:text, i:int32, l:int64, b:true|false, g:uuid, o:hex octets, t:RFC3339Nano.
package writechange

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// Digest keys of the kinds this package encodes (contract §8.10.1).
const (
	KeyObjectCreate = "ad.object.create"
	KeyObjectUpdate = "ad.object.update"
	KeyObjectDelete = "ad.object.delete"
)

// ErrEncoding is returned for an Attrs list or a change that does not round-trip. It carries no value.
var ErrEncoding = errors.New("writechange: change is not encodable")

var classNames = map[connectorv1.DirectoryObjectClass]string{
	connectorv1.DirectoryObjectClass_DIRECTORY_OBJECT_CLASS_USER:                "user",
	connectorv1.DirectoryObjectClass_DIRECTORY_OBJECT_CLASS_GROUP:               "group",
	connectorv1.DirectoryObjectClass_DIRECTORY_OBJECT_CLASS_COMPUTER:            "computer",
	connectorv1.DirectoryObjectClass_DIRECTORY_OBJECT_CLASS_CONTACT:             "contact",
	connectorv1.DirectoryObjectClass_DIRECTORY_OBJECT_CLASS_ORGANIZATIONAL_UNIT: "organizationalUnit",
}

// ClassName is the digest spelling of a class ("user"), or "" for an unknown one.
func ClassName(c connectorv1.DirectoryObjectClass) string { return classNames[c] }

// ClassOf is the inverse of ClassName.
func ClassOf(name string) (connectorv1.DirectoryObjectClass, bool) {
	for c, n := range classNames {
		if n == name {
			return c, true
		}
	}
	return 0, false
}

var scopeNames = map[connectorv1.GroupScope]string{
	connectorv1.GroupScope_GROUP_SCOPE_GLOBAL:       "global",
	connectorv1.GroupScope_GROUP_SCOPE_DOMAIN_LOCAL: "domainLocal",
	connectorv1.GroupScope_GROUP_SCOPE_UNIVERSAL:    "universal",
}

var opPrefix = map[connectorv1.EditOp]string{
	connectorv1.EditOp_EDIT_OP_SET:          "set:",
	connectorv1.EditOp_EDIT_OP_CLEAR:        "clear:",
	connectorv1.EditOp_EDIT_OP_ADD_VALUE:    "add:",
	connectorv1.EditOp_EDIT_OP_REMOVE_VALUE: "remove:",
}

// Encode returns the digest attributes of a change. It refuses an arm it does not encode.
func Encode(c *connectorv1.WriteChange) (key string, attrs []step.Attr, err error) {
	switch x := c.GetChange().(type) {
	case *connectorv1.WriteChange_ObjectCreate:
		oc := x.ObjectCreate
		cls := classNames[oc.GetObjectClass()]
		if cls == "" {
			return "", nil, ErrEncoding
		}
		attrs = append(attrs, one("~class", cls), one("~rdn", oc.GetRdnValue()))
		if s := scopeNames[oc.GetGroupScope()]; s != "" {
			attrs = append(attrs, one("~scope", s))
		}
		if oc.GetGroupIsSecurity() {
			attrs = append(attrs, one("~security", "true"))
		}
		if oc.GetAccountEnabled() {
			attrs = append(attrs, one("~enabled", "true"))
		}
		if oc.GetHasSecretInput() {
			attrs = append(attrs, step.Attr{Name: "~secret", Secret: true})
		}
		for _, e := range oc.GetInitial() {
			if e.GetOp() != connectorv1.EditOp_EDIT_OP_SET {
				return "", nil, ErrEncoding
			}
			a, err := editAttr(e)
			if err != nil {
				return "", nil, err
			}
			attrs = append(attrs, a)
		}
		return KeyObjectCreate, attrs, nil
	case *connectorv1.WriteChange_ObjectUpdate:
		for _, e := range x.ObjectUpdate.GetEdits() {
			a, err := editAttr(e)
			if err != nil {
				return "", nil, err
			}
			attrs = append(attrs, a)
		}
		return KeyObjectUpdate, attrs, nil
	case *connectorv1.WriteChange_ObjectDelete:
		return KeyObjectDelete, nil, nil
	}
	return "", nil, ErrEncoding
}

// Decode derives the typed change for a digest key from its attributes. It is Encode's inverse and
// refuses a list Encode could not have produced (an unknown structural field, a duplicate one, an
// unparsable value), so a caller cannot smuggle a field the digest does not pin.
func Decode(key string, attrs []step.Attr) (*connectorv1.WriteChange, error) {
	switch key {
	case KeyObjectDelete:
		if len(attrs) != 0 {
			return nil, ErrEncoding
		}
		return &connectorv1.WriteChange{Change: &connectorv1.WriteChange_ObjectDelete{ObjectDelete: &connectorv1.ObjectDelete{}}}, nil
	case KeyObjectUpdate:
		u := &connectorv1.ObjectUpdate{}
		for _, a := range attrs {
			e, err := decodeEdit(a)
			if err != nil {
				return nil, err
			}
			u.Edits = append(u.Edits, e)
		}
		return &connectorv1.WriteChange{Change: &connectorv1.WriteChange_ObjectUpdate{ObjectUpdate: u}}, nil
	case KeyObjectCreate:
		oc := &connectorv1.ObjectCreate{}
		seen := map[string]bool{}
		for _, a := range attrs {
			if !strings.HasPrefix(a.Name, "~") {
				e, err := decodeEdit(a)
				if err != nil || e.Op != connectorv1.EditOp_EDIT_OP_SET {
					return nil, ErrEncoding
				}
				oc.Initial = append(oc.Initial, e)
				continue
			}
			if seen[a.Name] {
				return nil, ErrEncoding
			}
			seen[a.Name] = true
			if a.Name == "~secret" {
				if !a.Secret {
					return nil, ErrEncoding
				}
				oc.HasSecretInput = true
				continue
			}
			if a.Secret || len(a.Values) != 1 {
				return nil, ErrEncoding
			}
			v := a.Values[0]
			switch a.Name {
			case "~class":
				c, ok := ClassOf(v)
				if !ok {
					return nil, ErrEncoding
				}
				oc.ObjectClass = c
			case "~rdn":
				oc.RdnValue = v
			case "~scope":
				for s, n := range scopeNames {
					if n == v {
						oc.GroupScope = s
					}
				}
				if oc.GroupScope == 0 {
					return nil, ErrEncoding
				}
			case "~security":
				oc.GroupIsSecurity = v == "true"
			case "~enabled":
				oc.AccountEnabled = v == "true"
			default:
				return nil, ErrEncoding
			}
		}
		if oc.ObjectClass == 0 || !seen["~rdn"] {
			return nil, ErrEncoding
		}
		return &connectorv1.WriteChange{Change: &connectorv1.WriteChange_ObjectCreate{ObjectCreate: oc}}, nil
	}
	return nil, ErrEncoding
}

func one(name, v string) step.Attr { return step.Attr{Name: name, Values: []string{v}} }

func editAttr(e *connectorv1.AttributeEdit) (step.Attr, error) {
	p, ok := opPrefix[e.GetOp()]
	if !ok || e.GetAttribute() == "" || strings.HasPrefix(e.GetAttribute(), "~") {
		return step.Attr{}, ErrEncoding
	}
	a := step.Attr{Name: p + e.GetAttribute()}
	for _, v := range e.GetValues() {
		s, err := encodeValue(v)
		if err != nil {
			return step.Attr{}, err
		}
		a.Values = append(a.Values, s)
	}
	return a, nil
}

func decodeEdit(a step.Attr) (*connectorv1.AttributeEdit, error) {
	if a.Secret {
		return nil, ErrEncoding
	}
	for op, p := range opPrefix {
		if name, ok := strings.CutPrefix(a.Name, p); ok && name != "" {
			e := &connectorv1.AttributeEdit{Attribute: name, Op: op}
			for _, s := range a.Values {
				v, err := decodeValue(s)
				if err != nil {
					return nil, err
				}
				e.Values = append(e.Values, v)
			}
			return e, nil
		}
	}
	return nil, ErrEncoding
}

func encodeValue(v *connectorv1.EditValue) (string, error) {
	switch x := v.GetValue().(type) {
	case *connectorv1.EditValue_Text:
		return "s:" + x.Text, nil
	case *connectorv1.EditValue_Int32Value:
		return "i:" + strconv.FormatInt(int64(x.Int32Value), 10), nil
	case *connectorv1.EditValue_Int64Value:
		return "l:" + strconv.FormatInt(x.Int64Value, 10), nil
	case *connectorv1.EditValue_Boolean:
		return "b:" + strconv.FormatBool(x.Boolean), nil
	case *connectorv1.EditValue_ObjectRef:
		b := x.ObjectRef.GetValue()
		if len(b) != 16 {
			return "", ErrEncoding
		}
		h := hex.EncodeToString(b)
		return "g:" + h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], nil
	case *connectorv1.EditValue_Octets:
		return "o:" + hex.EncodeToString(x.Octets), nil
	case *connectorv1.EditValue_Time:
		if at := x.Time.GetAt(); at != nil {
			return "t:" + at.AsTime().UTC().Format(time.RFC3339Nano), nil
		}
	}
	return "", ErrEncoding
}

func decodeValue(s string) (*connectorv1.EditValue, error) {
	tag, rest, ok := strings.Cut(s, ":")
	if !ok {
		return nil, ErrEncoding
	}
	var out connectorv1.EditValue
	switch tag {
	case "s":
		out.Value = &connectorv1.EditValue_Text{Text: rest}
	case "i":
		n, err := strconv.ParseInt(rest, 10, 32)
		if err != nil {
			return nil, ErrEncoding
		}
		out.Value = &connectorv1.EditValue_Int32Value{Int32Value: int32(n)}
	case "l":
		n, err := strconv.ParseInt(rest, 10, 64)
		if err != nil {
			return nil, ErrEncoding
		}
		out.Value = &connectorv1.EditValue_Int64Value{Int64Value: n}
	case "b":
		b, err := strconv.ParseBool(rest)
		if err != nil {
			return nil, ErrEncoding
		}
		out.Value = &connectorv1.EditValue_Boolean{Boolean: b}
	case "g":
		if len(rest) != 36 {
			return nil, ErrEncoding
		}
		b, err := hex.DecodeString(strings.ReplaceAll(rest, "-", ""))
		if err != nil || len(b) != 16 {
			return nil, ErrEncoding
		}
		out.Value = &connectorv1.EditValue_ObjectRef{ObjectRef: &connectorv1.Guid{Value: b}}
	case "o":
		b, err := hex.DecodeString(rest)
		if err != nil {
			return nil, ErrEncoding
		}
		out.Value = &connectorv1.EditValue_Octets{Octets: b}
	case "t":
		t, err := time.Parse(time.RFC3339Nano, rest)
		if err != nil {
			return nil, ErrEncoding
		}
		out.Value = &connectorv1.EditValue_Time{Time: &connectorv1.TimeValue{Kind: &connectorv1.TimeValue_At{At: timestamppb.New(t)}}}
	default:
		return nil, fmt.Errorf("%w", ErrEncoding)
	}
	return &out, nil
}

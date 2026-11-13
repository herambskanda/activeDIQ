package objects

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// ObjectKind is the kind of object a Template creates or modifies (DM-50).
type ObjectKind string

// The object kinds a Template covers.
const (
	KindUser     ObjectKind = "user"
	KindGroup    ObjectKind = "group"
	KindComputer ObjectKind = "computer"
	KindContact  ObjectKind = "contact"
	KindOU       ObjectKind = "ou"
)

// Valid reports whether k is a template object kind.
func (k ObjectKind) Valid() bool {
	switch k {
	case KindUser, KindGroup, KindComputer, KindContact, KindOU:
		return true
	}
	return false
}

// Provider is where the template's object lives.
type Provider string

// Providers.
const (
	ProviderAD     Provider = "ad"
	ProviderEntra  Provider = "entra"
	ProviderHybrid Provider = "hybrid"
)

// Purpose is what the template is used for.
type Purpose string

// Template purposes.
const (
	PurposeCreate Purpose = "create"
	PurposeModify Purpose = "modify"
)

// Mode is how the form shows a field.
type Mode string

// Field modes. A hidden field is not shown and cannot be set by the technician; a read-only field is
// shown with its default and cannot be changed.
const (
	ModeEditable Mode = "editable"
	ModeReadOnly Mode = "readOnly"
	ModeHidden   Mode = "hidden"
)

// FieldRule is the form rule for one attribute: whether it is visible and editable, whether it is
// mandatory, its default and the managed pick list (DM-53) that constrains its input.
type FieldRule struct {
	Attribute string `json:"attribute"`
	Mode      Mode   `json:"mode"`
	Mandatory bool   `json:"mandatory,omitempty"`
	Default   string `json:"default,omitempty"`
	PickList  string `json:"pickList,omitempty"` // an AttributeList ID (DM-53)
}

// Pin points at one version of another definition. A Template pins the NamingFormat version it uses,
// so a later publish of the format changes no existing template (DM-51 lifecycle).
type Pin struct {
	ID      string `json:"id"`
	Version int    `json:"version"`
}

// Scope is how far a duplicate check looks.
type Scope string

// Duplicate-check scopes (ADM-020).
const (
	ScopeDomain Scope = "domain"
	ScopeForest Scope = "forest"
	ScopeEntra  Scope = "entra"
)

// DuplicateCheck names the attributes that must be unlikely to repeat and how far to look. It is an
// advisory check at Plan; only the DC's atomic create decides uniqueness of the keyed names.
type DuplicateCheck struct {
	Attributes []string `json:"attributes"`
	Scope      Scope    `json:"scope"`
}

// Template is the data of a DM-50 template. Its ID and version live in the store.
type Template struct {
	Name              string              `json:"name"`
	Kind              ObjectKind          `json:"kind"`
	Provider          Provider            `json:"provider"`
	Purpose           Purpose             `json:"purpose"`
	Fields            []FieldRule         `json:"fields"`
	NamingFormats     map[NamePurpose]Pin `json:"namingFormats,omitempty"`
	PasswordPolicy    *Pin                `json:"passwordPolicy,omitempty"` // a DM-52 reference, owned by helpdesk
	DuplicateCheck    *DuplicateCheck     `json:"duplicateCheck,omitempty"`
	AllowedContainers []string            `json:"allowedContainers,omitempty"` // OU objectGUIDs (DM-50.I4)
}

var guidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// IsGUID reports whether s is a canonical lower-case GUID.
func IsGUID(s string) bool { return guidRE.MatchString(s) }

// Normalize lower-cases GUIDs so a stored template compares byte-for-byte. It does not validate.
func (t Template) Normalize() Template {
	t.AllowedContainers = lowerAll(t.AllowedContainers)
	for i := range t.Fields {
		t.Fields[i].PickList = strings.ToLower(t.Fields[i].PickList)
	}
	return t
}

func lowerAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.ToLower(s)
	}
	return out
}

// namingAllowed is which naming purposes make sense for which kind.
var namingAllowed = map[ObjectKind][]NamePurpose{
	KindUser:     {PurposeSAMAccountName, PurposeUPNPrefix, PurposeCN, PurposeDisplayName, PurposeMailAlias},
	KindGroup:    {PurposeSAMAccountName, PurposeCN, PurposeDisplayName, PurposeMailAlias},
	KindComputer: {PurposeSAMAccountName, PurposeCN},
	KindContact:  {PurposeCN, PurposeDisplayName, PurposeMailAlias},
	KindOU:       {PurposeCN},
}

// Validate reports why the template is malformed. It runs at save and publish.
func (t Template) Validate() error {
	n := strings.TrimSpace(t.Name)
	if n == "" || len([]rune(n)) > 120 || hasControl(n) {
		return violation("name", "needs 1 to 120 printable characters")
	}
	if !t.Kind.Valid() {
		return violation("kind", "%q is not a template object kind", t.Kind)
	}
	switch t.Provider {
	case ProviderAD, ProviderEntra, ProviderHybrid:
	default:
		return violation("provider", "%q is not ad, entra or hybrid", t.Provider)
	}
	if t.Purpose != PurposeCreate && t.Purpose != PurposeModify {
		return violation("purpose", "%q is not create or modify", t.Purpose)
	}
	if len(t.Fields) > 200 {
		return violation("fields", "at most 200 fields")
	}
	seen := map[string]bool{}
	for i, f := range t.Fields {
		fld := fmt.Sprintf("fields[%d]", i)
		key := strings.ToLower(f.Attribute)
		switch {
		case !validAttr(f.Attribute):
			return violation(fld, "attribute %q is not a valid attribute name", f.Attribute)
		case seen[key]:
			return violation(fld, "attribute %q is listed twice", f.Attribute)
		case f.Mode != ModeEditable && f.Mode != ModeReadOnly && f.Mode != ModeHidden:
			return violation(fld, "mode %q is not editable, readOnly or hidden", f.Mode)
		case f.Mode != ModeEditable && f.Mandatory && f.Default == "":
			return violation(fld, "a %s mandatory field needs a default, or nobody can fill it", f.Mode)
		case f.PickList != "" && !IsGUID(strings.ToLower(f.PickList)):
			return violation(fld, "pick list must be an attribute list ID")
		case len(f.Default) > 1024 || hasControl(f.Default):
			return violation(fld, "default is too long or has control characters")
		}
		seen[key] = true
	}
	for p, pin := range t.NamingFormats {
		if !slices.Contains(namingAllowed[t.Kind], p) {
			return violation("namingFormats", "a %s template has no %s name", t.Kind, p)
		}
		if !IsGUID(strings.ToLower(pin.ID)) || pin.Version < 1 {
			return violation("namingFormats."+string(p), "must pin a naming format ID and a version of 1 or more")
		}
	}
	if pp := t.PasswordPolicy; pp != nil {
		if t.Kind != KindUser && t.Kind != KindComputer {
			return violation("passwordPolicy", "a %s has no password", t.Kind)
		}
		if !IsGUID(strings.ToLower(pp.ID)) || pp.Version < 1 {
			return violation("passwordPolicy", "must pin a policy ID and a version of 1 or more")
		}
	}
	if d := t.DuplicateCheck; d != nil {
		if len(d.Attributes) == 0 || len(d.Attributes) > 8 {
			return violation("duplicateCheck.attributes", "needs 1 to 8 attributes")
		}
		for _, a := range d.Attributes {
			if !validAttr(a) {
				return violation("duplicateCheck.attributes", "%q is not a valid attribute name", a)
			}
		}
		switch d.Scope {
		case ScopeDomain, ScopeForest:
			if t.Provider == ProviderEntra {
				return violation("duplicateCheck.scope", "an Entra template cannot check a %s", d.Scope)
			}
		case ScopeEntra:
			if t.Provider == ProviderAD {
				return violation("duplicateCheck.scope", "an AD template cannot check Entra")
			}
		default:
			return violation("duplicateCheck.scope", "%q is not domain, forest or entra", d.Scope)
		}
	}
	if len(t.AllowedContainers) > 500 {
		return violation("allowedContainers", "at most 500 containers")
	}
	for _, c := range t.AllowedContainers {
		if !IsGUID(strings.ToLower(c)) {
			return violation("allowedContainers", "%q is not an OU objectGUID (containers are GUIDs, never DNs)", c)
		}
	}
	return nil
}

// ContainerAllowed reports whether an OU may hold objects made from the template. A template with no
// list allows every container the technician's scope reaches; with a list, only those. Either way the
// template grants nothing (DM-50.I3): the scope check still runs on the step.
func (t Template) ContainerAllowed(ouGUID string) bool {
	return len(t.AllowedContainers) == 0 || slices.Contains(lowerAll(t.AllowedContainers), strings.ToLower(ouGUID))
}

// CheckInput applies the form rules to the technician's input and returns every violation, each naming
// its field; nil means the input is acceptable. It is pure: it reads no directory and no database, so a
// create Action's Plan calls it first and blocks the item before any directory read.
//
//   - A mandatory field must have a value, from the input or the template's default.
//   - A hidden field must not be supplied; its default (if any) applies.
//   - A read-only field may only repeat its default.
//
// Attributes the template does not list are not judged here: the form defines what the technician sees,
// the Action's own input schema defines what exists.
func (t Template) CheckInput(in Input) []*ViolationError {
	var out []*ViolationError
	for _, f := range t.Fields {
		v := in.get(f.Attribute)
		switch f.Mode {
		case ModeHidden:
			if v != "" {
				out = append(out, &ViolationError{f.Attribute, "is hidden by the template and cannot be set"})
			}
		case ModeReadOnly:
			if v != "" && !strings.EqualFold(v, f.Default) {
				out = append(out, &ViolationError{f.Attribute, "is read-only in the template and cannot be changed"})
			}
		}
		if f.Mandatory && v == "" && strings.TrimSpace(f.Default) == "" {
			out = append(out, &ViolationError{f.Attribute, "is mandatory and has no value"})
		}
	}
	return out
}

// Effective returns the input with the template's defaults filled in for empty fields. Call it after
// CheckInput returned no violations.
func (t Template) Effective(in Input) Input {
	out := make(Input, len(in)+len(t.Fields))
	for k, v := range in {
		out[k] = v
	}
	for _, f := range t.Fields {
		if in.get(f.Attribute) == "" && f.Default != "" {
			out[f.Attribute] = f.Default
		}
	}
	return out
}

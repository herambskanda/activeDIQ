package report

import (
	"fmt"
	"slices"
	"strconv"

	"github.com/skenzeriq/activediq/internal/platform/authz"
)

// Category groups library definitions in the UI.
type Category string

// Categories of the 2a library.
const (
	CategoryUsers     Category = "users"
	CategoryPasswords Category = "passwords"
	CategoryGroups    Category = "groups"
	CategoryComputers Category = "computers"
	CategoryContacts  Category = "contacts"
	CategoryOUs       Category = "ous"
)

// Valid reports whether c is a defined category.
func (c Category) Valid() bool {
	switch c {
	case CategoryUsers, CategoryPasswords, CategoryGroups, CategoryComputers, CategoryContacts, CategoryOUs:
		return true
	}
	return false
}

// CaveatID names a header text such as "accurate to the sync interval".
type CaveatID string

// Definition is a report: data, not code (contract §3.4). One engine runs every definition.
//
// Versions (FR-03): a shipped definition never changes. A change is a new Version in a new file
// (usr-01.v2.json) and the old file stays, so a stored run always names the exact definition it
// ran. The SHA-256 of the shipped file is recorded by the run path, not held here.
type Definition struct {
	ID          DefinitionID
	Version     int
	Category    Category
	Title       string
	Description string
	Dataset     DatasetID
	Columns     []ColumnID // default column set, in order
	Sort        []SortKey  // default sort, at most MaxSortKeys
	Presets     []Preset   // at least one; Presets[0] opens without Generate (FR-04)
	Params      []ParamSpec
	PerDC       *PerDCSpec // USR-04 and PWD-03 only
	Caveats     []CaveatID
}

// Preset is a named variant of a definition.
type Preset struct {
	ID       string
	Names    []string // the ManageEngine names it answers (FR-02 "Also known as")
	Where    Expr     // nil means all rows
	Hidden   []HiddenGroup
	Columns  []ColumnID // nil means the definition's
	Sort     []SortKey
	Top      int // 0 means no top-N
	Requires *Subjects
}

// HiddenGroup is a set of rows counted in the header and not stored (E2). A Locked group cannot be
// shown: a run that names it in ShowHidden is refused. It carries a narrowing the admin may not undo,
// such as the domains where replicated logon is not usable (AC-16).
type HiddenGroup struct {
	ID     string
	Label  string
	Where  Expr
	Locked bool
}

// Subjects says a preset needs objects named by GUID (GRP-02, GRP-03).
type Subjects struct{ Min, Max int }

// ParamKind is the kind of a definition parameter.
type ParamKind uint8

const (
	paramInvalid ParamKind = iota
	ParamDays
	ParamGUIDList
	ParamEnum
)

// ParamSpec declares one parameter a run may set. A Days parameter has a floor (Min) and a ceiling
// (Max): the 30-day floor on replicated-logon thresholds is Min 30 (spec §6.4).
type ParamSpec struct {
	Name     string
	Kind     ParamKind
	Default  *ParamValue
	Min, Max int64    // Days only
	Choices  []string // Enum only
	Required bool
}

// ParamValue is a typed parameter value: whole days, a GUID list or an enum ID.
type ParamValue struct {
	kind ParamKind
	days int64
	enum string
	ids  []authz.ObjectID
}

// DaysP is a Days parameter value.
func DaysP(n int64) ParamValue { return ParamValue{kind: ParamDays, days: n} }

// EnumP is an Enum parameter value.
func EnumP(id string) ParamValue { return ParamValue{kind: ParamEnum, enum: id} }

// GUIDsP is a GUIDList parameter value.
func GUIDsP(ids ...authz.ObjectID) ParamValue {
	return ParamValue{kind: ParamGUIDList, ids: slices.Clone(ids)}
}

// Kind returns the value's kind.
func (p ParamValue) Kind() ParamKind { return p.kind }

// PerDCSpec marks a definition that reads per-DC attributes live (USR-04, PWD-03).
type PerDCSpec struct{ Scope PerDCScope }

// Key is "<id>@<version>", the form audit and logs use.
func (d Definition) Key() string { return string(d.ID) + "@" + strconv.Itoa(d.Version) }

// FileName is the name of the shipped file: usr-01.v2.json.
func (d Definition) FileName() string { return string(d.ID) + ".v" + strconv.Itoa(d.Version) + ".json" }

// Preset returns the preset with the given ID; the empty ID is the default preset.
func (d Definition) Preset(id string) (Preset, bool) {
	if id == "" && len(d.Presets) > 0 {
		return d.Presets[0], true
	}
	for _, p := range d.Presets {
		if p.ID == id {
			return p, true
		}
	}
	return Preset{}, false
}

func (d Definition) param(name string) (ParamSpec, bool) {
	for _, p := range d.Params {
		if p.Name == name {
			return p, true
		}
	}
	return ParamSpec{}, false
}

// Validate checks a definition's own structure. It cannot check names against a dataset: use
// ValidateAgainst for that.
func (d Definition) Validate() error {
	bad := func(path, format string, a ...any) error { return verrf(CodeInvalidDefinition, path, format, a...) }
	if !d.ID.Valid() {
		return bad("id", "definition ID %q must match %s", d.ID, definitionPattern)
	}
	if d.Version < 1 {
		return bad("version", "version must be at least 1 (FR-03)")
	}
	if !d.Category.Valid() {
		return bad("category", "unknown category %q", d.Category)
	}
	if d.Title == "" {
		return bad("title", "no title")
	}
	if !d.Dataset.Valid() {
		return bad("dataset", "dataset ID %q is malformed", d.Dataset)
	}
	if len(d.Columns) == 0 || len(d.Columns) > MaxQueryCols {
		return bad("columns", "a definition lists 1 to %d columns", MaxQueryCols)
	}
	if err := checkSort(d.Sort, "sort", CodeInvalidDefinition); err != nil {
		return err
	}
	if len(d.Presets) == 0 {
		return bad("presets", "a definition needs at least one preset")
	}
	seen := map[string]bool{}
	for i, p := range d.Presets {
		path := fmt.Sprintf("presets[%d]", i)
		if !presetIDPattern.MatchString(p.ID) || seen[p.ID] {
			return bad(path, "preset ID %q is malformed or duplicated", p.ID)
		}
		seen[p.ID] = true
		if err := checkSort(p.Sort, path+".sort", CodeInvalidDefinition); err != nil {
			return err
		}
		if p.Top < 0 || p.Top > 100000 {
			return bad(path, "top is out of range")
		}
		if p.Requires != nil && (p.Requires.Min < 1 || p.Requires.Max < p.Requires.Min || p.Requires.Max > 100) {
			return bad(path, "subjects range is invalid")
		}
		hid := map[string]bool{}
		for _, h := range p.Hidden {
			if !presetIDPattern.MatchString(h.ID) || hid[h.ID] || h.Label == "" || h.Where == nil {
				return bad(path, "hidden group %q is malformed or duplicated", h.ID)
			}
			hid[h.ID] = true
		}
	}
	names := map[string]bool{}
	for i, p := range d.Params {
		path := fmt.Sprintf("params[%d]", i)
		if !paramNamePattern.MatchString(p.Name) || names[p.Name] {
			return bad(path, "parameter name %q is malformed or duplicated", p.Name)
		}
		names[p.Name] = true
		switch p.Kind {
		case ParamDays:
			if p.Min < 1 || p.Max < p.Min || p.Max > maxDaysNumber {
				return bad(path, "days parameter %q needs 1 <= min <= max <= %d", p.Name, maxDaysNumber)
			}
		case ParamEnum:
			if len(p.Choices) == 0 {
				return bad(path, "enum parameter %q has no choices", p.Name)
			}
		case ParamGUIDList:
		default:
			return bad(path, "parameter %q has no kind", p.Name)
		}
		if p.Default != nil {
			if err := p.accepts(*p.Default); err != nil {
				return bad(path, "the default of %q is not acceptable", p.Name)
			}
		}
	}
	if d.PerDC != nil && (d.PerDC.Scope <= perDCScopeInvalid || d.PerDC.Scope > ScopeAll) {
		return bad("perDC", "no per-DC scope")
	}
	return nil
}

// accepts checks a value against the spec and returns the code to report.
func (p ParamSpec) accepts(v ParamValue) error {
	if v.kind != p.Kind {
		return verr(CodeBadValue, "params")
	}
	switch p.Kind {
	case ParamDays:
		if v.days < p.Min {
			return verr(CodeBelowFloor, "params")
		}
		if v.days > p.Max {
			return verr(CodeAboveCeiling, "params")
		}
	case ParamEnum:
		if !slices.Contains(p.Choices, v.enum) {
			return verr(CodeBadValue, "params")
		}
	case ParamGUIDList:
		if len(v.ids) == 0 || len(v.ids) > MaxInValues {
			return verr(CodeBadValue, "params")
		}
		for _, id := range v.ids {
			if id.IsZero() {
				return verr(CodeBadValue, "params")
			}
		}
	}
	return nil
}

func checkSort(keys []SortKey, path string, code Code) error {
	if len(keys) > MaxSortKeys {
		return verrf(code, path, "at most %d sort keys", MaxSortKeys)
	}
	for i, k := range keys {
		if !k.Column.Valid() || !k.Dir.Valid() {
			return verrf(code, fmt.Sprintf("%s[%d]", path, i), "malformed sort key")
		}
	}
	return nil
}

// ValidateAgainst checks a definition against its dataset: Validate, then every preset is resolved
// with default parameters (and sample values for required ones), so a broken definition stops
// start-up (contract §3.6).
func (d Definition) ValidateAgainst(ds Dataset) error {
	if err := d.Validate(); err != nil {
		return err
	}
	if d.Dataset != ds.ID {
		return verr(CodeUnknownDataset, "dataset")
	}
	if d.PerDC != nil && !slices.ContainsFunc(ds.Columns, Column.IsPerDC) {
		return verrf(CodeInvalidDefinition, "perDC", "dataset %s has no per-DC column", ds.ID)
	}
	for _, pr := range d.Presets {
		p := RunParams{Params: map[string]ParamValue{}}
		for _, spec := range d.Params {
			if spec.Required && spec.Default == nil {
				p.Params[spec.Name] = sampleParam(spec)
			}
		}
		if pr.Requires != nil {
			for i := 0; i < pr.Requires.Min; i++ {
				p.Subjects = append(p.Subjects, authz.ObjectID{byte(i + 1)})
			}
		}
		if _, err := Resolve(d, pr.ID, p, ds); err != nil {
			if v, ok := err.(ValidationError); ok {
				v.Path = fmt.Sprintf("presets[%s].%s", pr.ID, v.Path)
				return v
			}
			return err
		}
	}
	return nil
}

func sampleParam(s ParamSpec) ParamValue {
	switch s.Kind {
	case ParamDays:
		return DaysP(s.Min)
	case ParamEnum:
		return EnumP(s.Choices[0])
	}
	return GUIDsP(authz.ObjectID{1})
}

package report

import (
	"fmt"
	"slices"
)

// Dataset is a registered, read-only source of report rows (EP-8). It names tables its owner owns
// and the columns a report may select, filter and sort. It is plain data: the registry in
// store/reportsql quotes and compiles it.
type Dataset struct {
	ID        DatasetID
	Base      Relation        // the FROM: one owned table plus a fixed row predicate; the base anchor "t"
	RowKey    Fragment        // unique per row within a run: object GUID, or an edge key
	Anchors   []Anchor        // at least one RowAnchor; every RowAnchor must be in scope for the row to exist
	Rels      []Rel           // every other relation a fragment may read, through {rel.<id>}
	Columns   []Column        //
	Freshness FreshnessSource // which watermark says how current the rows are
	Tables    []string        // every table any anchor or rel names; Boot checks the owner map
}

// Relation is the dataset's FROM.
type Relation struct {
	Table Ident
	Where Fragment // fixed predicate, optional
	Joins []RowJoin
}

// RowJoin joins a RowAnchor into the FROM (edge datasets such as group_members).
type RowJoin struct {
	Anchor AnchorID
	On     Fragment
}

// AnchorMode says what the compiler does with an anchor's rows (contract §3.3, §4.3).
type AnchorMode uint8

const (
	anchorInvalid AnchorMode = iota
	RowAnchor                // the row is visible only if the anchor's row is in scope
	FilterAnchor             // out-of-scope rows do not exist for the fragment
	MaskAnchor               // read whatever the scope; identity columns are NULL outside it
)

// Anchor is a relation over a table whose rows are directory objects (they carry the scope columns).
type Anchor struct {
	ID         AnchorID
	Table      Ident
	Mode       AnchorMode
	Project    []Ident // the columns the compiler's subselect exposes to fragments
	Identity   []Ident // MaskAnchor only: columns exposed as NULL when the row is out of scope
	Connection Ident
	NC         Ident
	Object     Ident
	Parent     Ident
	Ancestry   Ident
	Complete   Ident
}

// RelKind says what a Rel holds.
type RelKind uint8

const (
	relInvalid RelKind = iota
	RelEdge            // links, closure edges
	RelInput           // policy-input values (D4)
)

// Rel is a relation that holds no directory-object identity of its own. Its projection may hold
// only GUID, int, bool, time and enum columns, never text; reportsql.NewRegistry checks that
// against the schema.
type Rel struct {
	ID      AnchorID
	Kind    RelKind
	Table   Ident
	Project []Ident
	Where   Fragment
}

// EnumValue is one choice of an enum column.
type EnumValue struct {
	ID       string
	Label    string
	SortRank int
}

// UnknownInputMissing is the reserved enum ID of a derived state whose input is missing (FR-09).
const UnknownInputMissing = "unknown_input_missing"

// Column is one column of a dataset.
type Column struct {
	ID          ColumnID
	Label       string
	Type        ValueType
	Enum        []EnumValue  // TypeEnum only
	Source      ColumnSource // exactly one of Attr, JSONAttr, Derived, PerDC
	Filter      []Op         // operators the column accepts; empty means not filterable
	Sortable    bool
	Default     bool
	Count       bool     // Derived only: counts other objects; RP11 compares it
	UnknownWhen ColumnID // Derived non-enum only: the state column whose unknown_input_missing makes this cell unknown
}

// ColumnSource is sealed: Attr, JSONAttr, Derived or PerDC.
type ColumnSource interface{ columnSource() }

// Attr reads a column of the base table.
type Attr struct{ Col Ident }

// JSONAttr reads a key of the attributes document (the key is bound, never concatenated).
type JSONAttr struct {
	Col Ident
	Key string
	As  ValueType
}

// Derived is evaluated in the query from constant SQL with slots.
type Derived struct{ SQL Fragment }

// PerDC is filled after the query from a live per-DC read, never from SQL (contract §6.5). Part says
// which part of the read the column shows; the zero value is the aggregate itself.
type PerDC struct {
	Attr PerDCAttr
	Agg  PerDCAgg
	Part PerDCPart
	// Of is the attribute whose aggregate picks the DC for PartAtWinner (the failure count on the DC of the
	// latest failed logon); it is unused by every other part.
	Of PerDCAttr
}

func (Attr) columnSource()     {}
func (JSONAttr) columnSource() {}
func (Derived) columnSource()  {}
func (PerDC) columnSource()    {}

// FreshnessSource says which watermark describes a dataset's currency.
type FreshnessSource uint8

const (
	freshInvalid     FreshnessSource = iota
	FreshNCWatermark                 // the last successful sync pass of the covered naming contexts
	FreshPolicyRead                  // the last read of the policy inputs
	FreshPerDC                       // a live per-DC read
	freshEnd
)

// Column returns the column with the given ID.
func (d Dataset) Column(id ColumnID) (Column, bool) {
	for _, c := range d.Columns {
		if c.ID == id {
			return c, true
		}
	}
	return Column{}, false
}

// IsPerDC reports whether the column is filled by a per-DC read.
func (c Column) IsPerDC() bool { _, ok := c.Source.(PerDC); return ok }

// Accepts reports whether the column accepts the operator.
func (c Column) Accepts(op Op) bool { return slices.Contains(c.Filter, op) }

// HasEnum reports whether the column's enum holds the ID.
func (c Column) HasEnum(id string) bool {
	return slices.ContainsFunc(c.Enum, func(e EnumValue) bool { return e.ID == id })
}

// Validate checks a dataset's structure: IDs, uniqueness, operator and type fit, fragment slots,
// the unknown-state rules and that every table is listed. It cannot check the schema or the owner
// map: reportsql.NewRegistry and CheckTables do. A failure is a ValidationError with
// CodeInvalidDataset.
func (d Dataset) Validate() error {
	bad := func(path, format string, a ...any) error { return verrf(CodeInvalidDataset, path, format, a...) }
	if !d.ID.Valid() {
		return bad("id", "dataset ID %q must match <owner>.<name>", d.ID)
	}
	if !d.Base.Table.Valid() {
		return bad("base.table", "invalid table %q", d.Base.Table)
	}
	if d.Freshness <= freshInvalid || d.Freshness >= freshEnd {
		return bad("freshness", "no freshness source")
	}
	if len(d.Tables) == 0 {
		return bad("tables", "no tables listed")
	}
	tables := map[string]bool{}
	for _, t := range d.Tables {
		if !Ident(t).Valid() {
			return bad("tables", "invalid table name %q", t)
		}
		tables[t] = true
	}
	if !tables[string(d.Base.Table)] {
		return bad("tables", "base table %q is not listed", d.Base.Table)
	}
	if d.RowKey.IsZero() {
		return bad("rowKey", "no row key")
	}
	ids := map[AnchorID]string{"t": "base"}
	anchors := map[AnchorID]Anchor{}
	rowAnchors := 0
	for i, a := range d.Anchors {
		p := fmt.Sprintf("anchors[%d]", i)
		if !a.ID.Valid() {
			return bad(p, "invalid anchor ID %q", a.ID)
		}
		if prev, dup := ids[a.ID]; dup && !(a.ID == "t" && prev == "base") {
			return bad(p, "anchor ID %q is already used by %s", a.ID, prev)
		}
		ids[a.ID] = "an anchor"
		anchors[a.ID] = a
		if a.Mode <= anchorInvalid || a.Mode > MaskAnchor {
			return bad(p, "anchor %q has no mode", a.ID)
		}
		if a.Mode == RowAnchor {
			rowAnchors++
		}
		if !tables[string(a.Table)] {
			return bad(p, "anchor table %q is not listed in Tables", a.Table)
		}
		for _, c := range append(slices.Clone(a.Project), a.Identity...) {
			if !c.Valid() {
				return bad(p, "invalid column %q", c)
			}
		}
		for _, c := range []Ident{a.Connection, a.NC, a.Object, a.Parent, a.Ancestry, a.Complete} {
			if !c.Valid() {
				return bad(p, "anchor %q lacks one of its six scope columns", a.ID)
			}
		}
		if len(a.Identity) > 0 && a.Mode != MaskAnchor {
			return bad(p, "only a MaskAnchor has identity columns")
		}
		if a.Mode == MaskAnchor && len(a.Identity) == 0 {
			return bad(p, "a MaskAnchor needs identity columns")
		}
	}
	if rowAnchors == 0 {
		return bad("anchors", "a dataset needs at least one RowAnchor")
	}
	rels := map[AnchorID]bool{}
	for i, r := range d.Rels {
		p := fmt.Sprintf("rels[%d]", i)
		if !r.ID.Valid() {
			return bad(p, "invalid relation ID %q", r.ID)
		}
		if _, dup := ids[r.ID]; dup {
			return bad(p, "relation ID %q is already used", r.ID)
		}
		ids[r.ID] = "a relation"
		rels[r.ID] = true
		if r.Kind <= relInvalid || r.Kind > RelInput {
			return bad(p, "relation %q has no kind", r.ID)
		}
		if !tables[string(r.Table)] {
			return bad(p, "relation table %q is not listed in Tables", r.Table)
		}
		if len(r.Project) == 0 {
			return bad(p, "relation %q projects nothing", r.ID)
		}
		for _, c := range r.Project {
			if !c.Valid() {
				return bad(p, "invalid column %q", c)
			}
		}
	}
	// Fragments: every slot must be declared, and only MaskAnchors have in_scope.
	checkFrag := func(path string, f Fragment) error {
		parts, err := f.Parts()
		if err != nil {
			if v, ok := err.(ValidationError); ok {
				v.Path = path
				return v
			}
			return err
		}
		for _, pt := range parts {
			switch pt.Kind {
			case SlotRel:
				if _, isAnchor := anchors[pt.ID]; !(rels[pt.ID] || isAnchor && pt.ID != "t") {
					return bad(path, "{rel.%s} is not declared", pt.ID)
				}
			case SlotInScope:
				if a, ok := anchors[pt.ID]; !ok || a.Mode != MaskAnchor {
					return bad(path, "{in_scope.%s} needs a MaskAnchor of that name", pt.ID)
				}
			}
		}
		return nil
	}
	if err := checkFrag("rowKey", d.RowKey); err != nil {
		return err
	}
	if !d.Base.Where.IsZero() {
		if err := checkFrag("base.where", d.Base.Where); err != nil {
			return err
		}
	}
	for i, j := range d.Base.Joins {
		p := fmt.Sprintf("base.joins[%d]", i)
		if a, ok := anchors[j.Anchor]; !ok || a.Mode != RowAnchor {
			return bad(p, "join %q must name a declared RowAnchor", j.Anchor)
		}
		if err := checkFrag(p, j.On); err != nil {
			return err
		}
	}
	for i, r := range d.Rels {
		if !r.Where.IsZero() {
			if err := checkFrag(fmt.Sprintf("rels[%d].where", i), r.Where); err != nil {
				return err
			}
		}
	}
	return d.validateColumns(checkFrag)
}

func (d Dataset) validateColumns(checkFrag func(string, Fragment) error) error {
	bad := func(path, format string, a ...any) error { return verrf(CodeInvalidDataset, path, format, a...) }
	if len(d.Columns) == 0 {
		return bad("columns", "no columns")
	}
	byID := map[ColumnID]Column{}
	for _, c := range d.Columns {
		if _, dup := byID[c.ID]; dup {
			return bad("columns", "duplicate column %q", c.ID)
		}
		byID[c.ID] = c
	}
	for i, c := range d.Columns {
		p := fmt.Sprintf("columns[%d]", i)
		if !c.ID.Valid() {
			return bad(p, "invalid column ID %q", c.ID)
		}
		if c.Label == "" {
			return bad(p, "column %q has no label", c.ID)
		}
		if c.Type <= TypeInvalid || c.Type > TypeTextList {
			return bad(p, "column %q has no type", c.ID)
		}
		if c.Type != TypeEnum && len(c.Enum) > 0 {
			return bad(p, "column %q has enum values but is not an enum", c.ID)
		}
		if c.Type == TypeEnum {
			if len(c.Enum) == 0 {
				return bad(p, "enum column %q has no values", c.ID)
			}
			seen := map[string]bool{}
			for _, e := range c.Enum {
				if len(e.ID) == 0 || len(e.ID) > 64 || !columnIDPattern.MatchString(e.ID) || e.Label == "" || seen[e.ID] {
					return bad(p, "enum column %q has an invalid or duplicate value %q", c.ID, e.ID)
				}
				seen[e.ID] = true
			}
		}
		for _, op := range c.Filter {
			if !op.Valid() {
				return verrf(CodeUnknownOperator, p, "column %q lists an undefined operator", c.ID)
			}
			if !opFitsType(op, c.Type) {
				return bad(p, "column %q (%s) cannot accept operator %s", c.ID, c.Type, op)
			}
		}
		switch s := c.Source.(type) {
		case Attr:
			if !s.Col.Valid() {
				return bad(p, "column %q: invalid attribute column", c.ID)
			}
		case JSONAttr:
			if !s.Col.Valid() || s.Key == "" || len(s.Key) > 128 {
				return bad(p, "column %q: invalid JSON attribute", c.ID)
			}
			switch s.As {
			case TypeText, TypeInt, TypeBool, TypeTime:
			default:
				return bad(p, "column %q: a JSON attribute reads as text, int, bool or time", c.ID)
			}
			if s.As != c.Type {
				return bad(p, "column %q: JSON attribute type %s differs from the column type %s", c.ID, s.As, c.Type)
			}
		case Derived:
			if err := checkFrag(p, s.SQL); err != nil {
				return err
			}
		case PerDC:
			if err := s.check(c.Type); err != nil {
				return bad(p, "column %q: %v", c.ID, err)
			}
		default:
			return bad(p, "column %q has no source", c.ID)
		}
		_, derived := c.Source.(Derived)
		if c.Count && !derived {
			return bad(p, "column %q: only a Derived column can be a Count", c.ID)
		}
		holdsUnknown := c.HasEnum(UnknownInputMissing)
		if c.Type == TypeEnum && holdsUnknown && !derived {
			return bad(p, "column %q holds %s but is not Derived", c.ID, UnknownInputMissing)
		}
		if c.UnknownWhen != "" {
			state, ok := byID[c.UnknownWhen]
			_, stateDerived := state.Source.(Derived)
			switch {
			case !derived || c.Type == TypeEnum:
				return bad(p, "column %q: UnknownWhen is for Derived non-enum columns", c.ID)
			case !ok || state.Type != TypeEnum || !stateDerived || !state.HasEnum(UnknownInputMissing):
				return bad(p, "column %q: UnknownWhen %q is not a Derived enum column holding %s", c.ID, c.UnknownWhen, UnknownInputMissing)
			}
		}
	}
	return nil
}

// opFitsType says whether an operator can apply to a column type.
func opFitsType(op Op, t ValueType) bool {
	switch op {
	case OpPresent, OpAbsent:
		return true
	case OpEq, OpNe, OpIn:
		return t != TypeTextList
	case OpLt, OpLe, OpGt, OpGe:
		return t == TypeInt || t == TypeTime || t == TypeText
	case OpContains:
		return t == TypeText || t == TypeTextList
	case OpPrefix:
		return t == TypeText
	case OpWithinLastDays, OpOlderThanDays, OpWithinNextDays:
		return t == TypeTime
	}
	return false
}

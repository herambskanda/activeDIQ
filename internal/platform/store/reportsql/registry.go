package reportsql

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/skenzeriq/activediq/internal/platform/report"
)

// Options configures NewRegistry.
type Options struct {
	// Schema is checked against every identifier of every dataset. Required.
	Schema Schema
	// SecretKey says whether a JSON attribute key is a secret (D8, TM-TB15-T3). Required when any
	// dataset reads a JSONAttr; inventory exports the predicate it already uses (row B3).
	SecretKey func(key string) bool
}

// Registry holds the datasets the compiler may query, quoted once at build time (contract §3.1).
// Compile only concatenates the quoted text, fixed keywords and the placeholders it numbers itself.
type Registry struct {
	ds    map[report.DatasetID]*dataset
	order []report.DatasetID
}

// Dataset is a registered dataset with its identifiers pre-quoted. It has no exported fields and
// only a Registry makes one.
type Dataset struct{ d *dataset }

// ID returns the dataset's ID ("" for the zero Dataset).
func (d Dataset) ID() report.DatasetID {
	if d.d == nil {
		return ""
	}
	return d.d.src.ID
}

type frag struct{ parts []report.Part }

type anchor struct {
	src                              report.Anchor
	table                            string
	project, identity                string // joined, quoted; project excludes identity
	projectCols, identityCols        []string
	conn, nc, obj, parent, anc, done string
}

type rel struct {
	src     report.Rel
	table   string
	project []string
	where   *frag
}

type column struct {
	src  report.Column
	attr string // quoted column, Attr and JSONAttr
	frag *frag  // Derived
}

type join struct {
	a  *anchor
	on *frag
}

type dataset struct {
	src       report.Dataset
	base      string
	baseWhere *frag
	rowKey    *frag
	joins     []join
	anchors   map[report.AnchorID]*anchor
	rels      map[report.AnchorID]*rel
	cols      map[report.ColumnID]*column
}

func quote(id report.Ident) string { return pgx.Identifier{string(id)}.Sanitize() }

// NewRegistry validates and pre-quotes the datasets. It fails, naming the dataset and the place,
// on: a dataset that fails report.Dataset.Validate; a table, column or scope column the schema does
// not have; a Rel projection, or a MaskAnchor's non-identity projection, that is not GUID, int,
// bool, time or enum (no text, no jsonb); a fragment that uses a word outside the allowlist
// (fragcheck.go: functions, keywords, casts), a schema-qualified name, a table, or a slot the dataset
// does not declare; a JSON key in the secret set; and a column whose type does not fit its source.
func NewRegistry(opt Options, ds ...report.Dataset) (*Registry, error) {
	if opt.Schema == nil {
		return nil, errors.New("reportsql: NewRegistry needs a Schema")
	}
	r := &Registry{ds: map[report.DatasetID]*dataset{}}
	for _, src := range ds {
		if _, dup := r.ds[src.ID]; dup {
			return nil, fmt.Errorf("reportsql: duplicate dataset %q", src.ID)
		}
		d, err := buildDataset(opt, src)
		if err != nil {
			return nil, fmt.Errorf("reportsql: dataset %q: %w", src.ID, err)
		}
		r.ds[src.ID] = d
		r.order = append(r.order, src.ID)
	}
	return r, nil
}

// Dataset returns the registered dataset.
func (r *Registry) Dataset(id report.DatasetID) (Dataset, bool) {
	d, ok := r.ds[id]
	if !ok {
		return Dataset{}, false
	}
	return Dataset{d: d}, true
}

// IDs lists the registered datasets in registration order.
func (r *Registry) IDs() []report.DatasetID { return slices.Clone(r.order) }

func buildDataset(opt Options, src report.Dataset) (*dataset, error) {
	if err := src.Validate(); err != nil {
		return nil, err
	}
	sch := opt.Schema
	for _, t := range src.Tables {
		if _, ok := sch.Column(t, ""); !ok && !slices.Contains(sch.Tables(), t) {
			return nil, fmt.Errorf("table %q is not in the schema", t)
		}
	}
	d := &dataset{src: src, base: quote(src.Base.Table),
		anchors: map[report.AnchorID]*anchor{}, rels: map[report.AnchorID]*rel{}, cols: map[report.ColumnID]*column{}}
	tableNames := map[string]bool{}
	for _, t := range sch.Tables() {
		tableNames[strings.ToLower(t)] = true
	}
	for _, t := range src.Tables {
		tableNames[strings.ToLower(t)] = true
	}
	mkFrag := func(path string, f report.Fragment) (*frag, error) {
		if f.IsZero() {
			return nil, nil
		}
		parts, err := f.Parts()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if err := checkFragment(parts, tableNames); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		return &frag{parts: parts}, nil
	}
	// An alias is a name a fragment writes through a slot; it may not also be a table, or a subselect
	// that reads FROM an alias could read the table instead.
	aliases := []string{}
	for _, a := range src.Anchors {
		aliases = append(aliases, string(a.ID))
	}
	for _, r := range src.Rels {
		aliases = append(aliases, string(r.ID))
	}
	for _, id := range aliases {
		if tableNames[strings.ToLower(id)] {
			return nil, fmt.Errorf("anchor or relation ID %q is also a table name", id)
		}
	}
	var err error
	if d.rowKey, err = mkFrag("rowKey", src.RowKey); err != nil {
		return nil, err
	}
	if d.baseWhere, err = mkFrag("base.where", src.Base.Where); err != nil {
		return nil, err
	}
	for i, a := range src.Anchors {
		ca, err := buildAnchor(sch, a)
		if err != nil {
			return nil, fmt.Errorf("anchors[%d] %q: %w", i, a.ID, err)
		}
		d.anchors[a.ID] = ca
	}
	if ta, ok := d.anchors["t"]; ok && ta.src.Table != src.Base.Table {
		return nil, errors.New(`anchor "t" must be over the base table`)
	}
	joined := map[report.AnchorID]bool{}
	for i, j := range src.Base.Joins {
		on, err := mkFrag(fmt.Sprintf("base.joins[%d]", i), j.On)
		if err != nil {
			return nil, err
		}
		if on == nil {
			return nil, fmt.Errorf("base.joins[%d]: no ON condition", i)
		}
		d.joins = append(d.joins, join{a: d.anchors[j.Anchor], on: on})
		joined[j.Anchor] = true
	}
	for _, a := range src.Anchors {
		if a.Mode == report.RowAnchor && a.ID != "t" && !joined[a.ID] {
			return nil, fmt.Errorf("RowAnchor %q is not joined into the FROM, so its scope could not be applied", a.ID)
		}
	}
	for i, r := range src.Rels {
		cr := &rel{src: r, table: quote(r.Table)}
		for _, c := range r.Project {
			k, ok := sch.Column(string(r.Table), string(c))
			if !ok {
				return nil, fmt.Errorf("rels[%d] %q: table %q has no column %q", i, r.ID, r.Table, c)
			}
			if !projectable(k) {
				return nil, fmt.Errorf("rels[%d] %q: column %q is %s; a relation projects only GUID, int, bool, time or enum columns", i, r.ID, c, k)
			}
			cr.project = append(cr.project, quote(c))
		}
		if cr.where, err = mkFrag(fmt.Sprintf("rels[%d].where", i), r.Where); err != nil {
			return nil, err
		}
		d.rels[r.ID] = cr
	}
	for i, c := range src.Columns {
		cc := &column{src: c}
		path := fmt.Sprintf("columns[%d] %q", i, c.ID)
		switch s := c.Source.(type) {
		case report.Attr:
			k, ok := sch.Column(string(src.Base.Table), string(s.Col))
			if !ok {
				return nil, fmt.Errorf("%s: base table has no column %q", path, s.Col)
			}
			if !fits(c.Type, k) {
				return nil, fmt.Errorf("%s: %s column %q cannot back a %s column", path, k, s.Col, c.Type)
			}
			cc.attr = quote(s.Col)
		case report.JSONAttr:
			k, ok := sch.Column(string(src.Base.Table), string(s.Col))
			if !ok || k != KindJSON {
				return nil, fmt.Errorf("%s: %q is not a json column of the base table", path, s.Col)
			}
			if opt.SecretKey == nil {
				return nil, fmt.Errorf("%s: no SecretKey predicate configured; refusing to read a JSON attribute", path)
			}
			if opt.SecretKey(s.Key) {
				return nil, fmt.Errorf("%s: JSON attribute key is in the secret set", path)
			}
			if s.As == report.TypeTime {
				return nil, fmt.Errorf("%s: a JSON attribute cannot be read as time; use a typed column", path)
			}
			cc.attr = quote(s.Col)
		case report.Derived:
			if cc.frag, err = mkFrag(path, s.SQL); err != nil {
				return nil, err
			}
		}
		d.cols[c.ID] = cc
	}
	return d, nil
}

func findAnchor(src report.Dataset, id report.AnchorID) (report.Anchor, bool) {
	for _, a := range src.Anchors {
		if a.ID == id {
			return a, true
		}
	}
	return report.Anchor{}, false
}

func buildAnchor(sch Schema, a report.Anchor) (*anchor, error) {
	t := string(a.Table)
	need := func(what string, col report.Ident, want ColKind) (string, error) {
		k, ok := sch.Column(t, string(col))
		if !ok {
			return "", fmt.Errorf("table %q has no %s column %q", t, what, col)
		}
		if k != want {
			return "", fmt.Errorf("%s column %q is %s, want %s", what, col, k, want)
		}
		return quote(col), nil
	}
	ca := &anchor{src: a, table: quote(a.Table)}
	var err error
	for _, s := range []struct {
		dst  *string
		what string
		col  report.Ident
		want ColKind
	}{{&ca.conn, "connection", a.Connection, KindGUID}, {&ca.nc, "nc", a.NC, KindGUID}, {&ca.obj, "object", a.Object, KindGUID},
		{&ca.parent, "parent", a.Parent, KindGUID}, {&ca.anc, "ancestry", a.Ancestry, KindGUIDList}, {&ca.done, "complete", a.Complete, KindBool}} {
		if *s.dst, err = need(s.what, s.col, s.want); err != nil {
			return nil, err
		}
	}
	for _, c := range a.Identity {
		if _, ok := sch.Column(t, string(c)); !ok {
			return nil, fmt.Errorf("table %q has no identity column %q", t, c)
		}
		ca.identityCols = append(ca.identityCols, quote(c))
	}
	for _, c := range a.Project {
		k, ok := sch.Column(t, string(c))
		if !ok {
			return nil, fmt.Errorf("table %q has no column %q", t, c)
		}
		if slices.Contains(a.Identity, c) {
			continue
		}
		if a.Mode == report.MaskAnchor && !projectable(k) {
			return nil, fmt.Errorf("MaskAnchor column %q is %s; a MaskAnchor's non-identity projection may hold only GUID, int, bool, time or enum columns (name it as an identity column to mask it)", c, k)
		}
		ca.projectCols = append(ca.projectCols, quote(c))
	}
	ca.project = strings.Join(ca.projectCols, ", ")
	ca.identity = strings.Join(ca.identityCols, ", ")
	return ca, nil
}

// fits says whether a table column of kind k can back a report column of type t.
func fits(t report.ValueType, k ColKind) bool {
	switch t {
	case report.TypeText:
		return k == KindText || k == KindEnum
	case report.TypeEnum:
		return k == KindEnum || k == KindText
	case report.TypeInt:
		return k == KindInt
	case report.TypeBool:
		return k == KindBool
	case report.TypeTime:
		return k == KindTime
	case report.TypeGUID:
		return k == KindGUID
	case report.TypeTextList:
		return k == KindTextList
	}
	return false
}

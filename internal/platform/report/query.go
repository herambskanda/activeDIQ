package report

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/skenzeriq/activediq/internal/platform/authz"
)

// Depth says whether a narrowing root covers the OU's whole subtree or only its direct children.
type Depth uint8

const (
	depthInvalid Depth = iota
	DepthSubtree
	DepthOneLevel
)

func (d Depth) String() string {
	switch d {
	case DepthSubtree:
		return "subtree"
	case DepthOneLevel:
		return "one_level"
	}
	return "invalid"
}

// NarrowRoot is an OU the admin included or excluded, by connection and objectGUID (never a DN).
type NarrowRoot struct {
	Connection authz.ObjectID
	Root       authz.ObjectID
	Depth      Depth
}

// Narrowing is what the admin picked: it narrows the runner's scope and never widens it (§4.4).
// Empty means the scope alone decides.
type Narrowing struct {
	Connections []authz.ObjectID
	Include     []NarrowRoot
	Exclude     []NarrowRoot
}

// MaxNarrowing is the most entries each narrowing list may hold.
const MaxNarrowing = 64

func (n Narrowing) validate() error {
	if len(n.Connections) > MaxNarrowing || len(n.Include) > MaxNarrowing || len(n.Exclude) > MaxNarrowing {
		return verr(CodeBadNarrowing, "narrowing")
	}
	for _, c := range n.Connections {
		if c.IsZero() {
			return verr(CodeBadNarrowing, "narrowing.connections")
		}
	}
	for _, list := range [][]NarrowRoot{n.Include, n.Exclude} {
		for _, r := range list {
			if r.Connection.IsZero() || r.Root.IsZero() || (r.Depth != DepthSubtree && r.Depth != DepthOneLevel) {
				return verr(CodeBadNarrowing, "narrowing.roots")
			}
		}
	}
	return nil
}

// RunParams is the decoded body of a run request: only typed, named inputs. There is no field that
// carries LDAP or SQL text, and DecodeRunParams refuses any key it does not know (FR-05, AC-05).
type RunParams struct {
	Connections []authz.ObjectID
	Include     []NarrowRoot
	Exclude     []NarrowRoot
	Params      map[string]ParamValue
	Filters     []Expr // AND-ed with the preset's filter
	Columns     []ColumnID
	Sort        []SortKey
	ShowHidden  []string // hidden-group IDs to include
	Subjects    []authz.ObjectID
}

// Query is the fully resolved AST one run executes. Only Resolve builds it: a Query made any other
// way is not Valid and the compiler refuses it.
type Query struct {
	Dataset    DatasetID
	Columns    []ColumnID // 1..64; output order is export order is digest order
	Where      Expr       // SQL part: no PerDC column appears
	PerDCWhere Expr       // per-DC part: only PerDC columns
	Hidden     []HiddenGroup
	Sort       []SortKey // the compiler appends the row key as the final tie-break
	Top        int
	Narrowing  Narrowing
	Subjects   []authz.ObjectID

	resolved bool
}

// Valid reports whether the Query came from Resolve.
func (q Query) Valid() bool { return q.resolved }

// Resolve checks a run request against its definition and dataset and returns the Query to
// execute. It returns a ValidationError and the zero Query for: a dataset that is not def's, an
// unknown preset, parameter, column or operator, an operator the column does not accept, a value
// that does not fit, a missing required parameter, a value below its floor, a PerDC column mixed
// into a SQL term, and more than MaxQueryCols columns. Errors name a place and never echo values.
func Resolve(def Definition, preset string, p RunParams, ds Dataset) (Query, error) {
	if err := def.Validate(); err != nil {
		return Query{}, err
	}
	if def.Dataset != ds.ID || !ds.ID.Valid() {
		return Query{}, verr(CodeUnknownDataset, "dataset")
	}
	pr, ok := def.Preset(preset)
	if !ok {
		return Query{}, verr(CodeUnknownPreset, "preset")
	}
	r := &resolver{def: def, ds: ds, vals: map[string]ParamValue{}}
	if err := r.params(p); err != nil {
		return Query{}, err
	}
	q := Query{Dataset: ds.ID, Top: pr.Top}
	var err error
	if q.Columns, err = r.columnList(p, pr); err != nil {
		return Query{}, err
	}
	if q.Sort, err = r.sortKeys(p, pr); err != nil {
		return Query{}, err
	}
	var terms []Expr
	if pr.Where != nil {
		terms = append(terms, pr.Where)
	}
	terms = append(terms, p.Filters...)
	if len(terms) > 0 {
		e, err := r.expr(And{Terms: terms}, "where", 0)
		if err != nil {
			return Query{}, err
		}
		if r.nodes > MaxExprNodes {
			return Query{}, verr(CodeTooComplex, "where")
		}
		if q.Where, q.PerDCWhere, err = r.split(e); err != nil {
			return Query{}, err
		}
	}
	if q.Hidden, err = r.hidden(p, pr); err != nil {
		return Query{}, err
	}
	if q.Subjects, err = subjects(p, pr); err != nil {
		return Query{}, err
	}
	q.Narrowing = Narrowing{
		Connections: slices.Clone(p.Connections),
		Include:     slices.Clone(p.Include),
		Exclude:     slices.Clone(p.Exclude),
	}
	if err := q.Narrowing.validate(); err != nil {
		return Query{}, err
	}
	q.resolved = true
	return q, nil
}

type resolver struct {
	def   Definition
	ds    Dataset
	vals  map[string]ParamValue // effective value of every parameter that has one
	nodes int
}

// params fixes the effective value of each declared parameter and refuses any other name.
func (r *resolver) params(p RunParams) error {
	for name := range p.Params {
		if _, ok := r.def.param(name); !ok {
			return verr(CodeUnknownParameter, "params."+safeKey(name))
		}
	}
	for _, spec := range r.def.Params {
		v, given := p.Params[spec.Name]
		switch {
		case given:
		case spec.Default != nil:
			v = *spec.Default
		case spec.Required:
			return verr(CodeMissingParameter, "params."+spec.Name)
		default:
			continue
		}
		if err := spec.accepts(v); err != nil {
			code, _ := CodeOf(err)
			return verr(code, "params."+spec.Name)
		}
		r.vals[spec.Name] = v
	}
	return nil
}

func (r *resolver) columnList(p RunParams, pr Preset) ([]ColumnID, error) {
	cols := r.def.Columns
	if pr.Columns != nil {
		cols = pr.Columns
	}
	if p.Columns != nil {
		cols = p.Columns
	}
	if len(cols) == 0 {
		return nil, verr(CodeUnknownColumn, "columns")
	}
	if len(cols) > MaxQueryCols {
		return nil, verr(CodeTooManyColumns, "columns")
	}
	seen := map[ColumnID]bool{}
	for i, c := range cols {
		if _, ok := r.ds.Column(c); !ok {
			return nil, verr(CodeUnknownColumn, fmt.Sprintf("columns[%d]", i))
		}
		if seen[c] {
			return nil, verr(CodeDuplicateColumn, fmt.Sprintf("columns[%d]", i))
		}
		seen[c] = true
	}
	return slices.Clone(cols), nil
}

func (r *resolver) sortKeys(p RunParams, pr Preset) ([]SortKey, error) {
	keys := r.def.Sort
	if pr.Sort != nil {
		keys = pr.Sort
	}
	if p.Sort != nil {
		keys = p.Sort
	}
	if len(keys) > MaxSortKeys {
		return nil, verr(CodeBadSort, "sort")
	}
	for i, k := range keys {
		path := fmt.Sprintf("sort[%d]", i)
		c, ok := r.ds.Column(k.Column)
		if !ok {
			return nil, verr(CodeUnknownColumn, path)
		}
		if !c.Sortable || !k.Dir.Valid() {
			return nil, verr(CodeBadSort, path)
		}
	}
	return slices.Clone(keys), nil
}

// hidden returns the preset's hidden groups, minus those the admin chose to show.
func (r *resolver) hidden(p RunParams, pr Preset) ([]HiddenGroup, error) {
	known := map[string]bool{}
	for _, h := range pr.Hidden {
		known[h.ID] = true
	}
	for _, id := range p.ShowHidden {
		if !known[id] {
			return nil, verr(CodeUnknownParameter, "showHidden")
		}
	}
	var out []HiddenGroup
	for i, h := range pr.Hidden {
		if slices.Contains(p.ShowHidden, h.ID) {
			continue
		}
		r.nodes = 0
		e, err := r.expr(h.Where, fmt.Sprintf("hidden[%d]", i), 0)
		if err != nil {
			return nil, err
		}
		if cols := columns(e, nil); slices.ContainsFunc(cols, func(c ColumnID) bool { col, _ := r.ds.Column(c); return col.IsPerDC() }) {
			return nil, verr(CodePerDCMisplaced, fmt.Sprintf("hidden[%d]", i))
		}
		out = append(out, HiddenGroup{ID: h.ID, Label: h.Label, Where: e})
	}
	return out, nil
}

func subjects(p RunParams, pr Preset) ([]authz.ObjectID, error) {
	if pr.Requires == nil {
		if len(p.Subjects) > 0 {
			return nil, verr(CodeUnknownParameter, "subjects")
		}
		return nil, nil
	}
	if len(p.Subjects) < pr.Requires.Min {
		return nil, verr(CodeMissingParameter, "subjects")
	}
	if len(p.Subjects) > pr.Requires.Max {
		return nil, verr(CodeSubjects, "subjects")
	}
	for _, s := range p.Subjects {
		if s.IsZero() {
			return nil, verr(CodeSubjects, "subjects")
		}
	}
	return slices.Clone(p.Subjects), nil
}

// expr checks one expression against the dataset and returns a copy with every parameter replaced
// by its value.
func (r *resolver) expr(e Expr, path string, depth int) (Expr, error) {
	if depth > MaxExprDepth {
		return nil, verr(CodeTooComplex, path)
	}
	if r.nodes++; r.nodes > MaxExprNodes {
		return nil, verr(CodeTooComplex, path)
	}
	switch x := e.(type) {
	case And:
		ts, err := r.terms(x.Terms, path+".and", depth)
		return And{ts}, err
	case Or:
		ts, err := r.terms(x.Terms, path+".or", depth)
		return Or{ts}, err
	case Not:
		t, err := r.expr(x.Term, path+".not", depth+1)
		return Not{t}, err
	case Cmp:
		return r.cmp(x, path+".cmp")
	}
	return nil, verr(CodeInvalidQuery, path)
}

func (r *resolver) terms(ts []Expr, path string, depth int) ([]Expr, error) {
	if len(ts) == 0 {
		return nil, verr(CodeInvalidQuery, path)
	}
	if len(ts) > MaxExprTerms {
		return nil, verr(CodeTooComplex, path)
	}
	out := make([]Expr, 0, len(ts))
	for i, t := range ts {
		e, err := r.expr(t, fmt.Sprintf("%s[%d]", path, i), depth+1)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

func (r *resolver) cmp(c Cmp, path string) (Expr, error) {
	col, ok := r.ds.Column(c.Column)
	if !ok {
		return nil, verr(CodeUnknownColumn, path+".col")
	}
	if !c.Op.Valid() {
		return nil, verr(CodeUnknownOperator, path+".op")
	}
	if !col.Accepts(c.Op) {
		return nil, verr(CodeOperatorNotAllowed, path+".op")
	}
	hasValue := c.Value.Type() != TypeInvalid
	given := 0
	for _, b := range []bool{hasValue, len(c.Values) > 0, c.Param != ""} {
		if b {
			given++
		}
	}
	out := Cmp{Column: c.Column, Op: c.Op}
	switch {
	case c.Op.takesNoValue():
		if given != 0 {
			return nil, verr(CodeBadValue, path+".value")
		}
		return out, nil
	case given != 1:
		return nil, verr(CodeBadValue, path+".value")
	case c.Param != "":
		v, err := r.paramValue(c.Param, path+".param")
		if err != nil {
			return nil, err
		}
		switch v.kind {
		case ParamDays:
			c.Value = IntV(v.days)
		case ParamEnum:
			c.Value = EnumV(v.enum)
		case ParamGUIDList:
			for _, id := range v.ids {
				c.Values = append(c.Values, GUIDV(id))
			}
		}
	}
	if c.Op == OpIn {
		if len(c.Values) == 0 || c.Value.Type() != TypeInvalid {
			return nil, verr(CodeBadValue, path+".values")
		}
		if len(c.Values) > MaxInValues {
			return nil, verr(CodeTooManyValues, path+".values")
		}
		for i, v := range c.Values {
			if err := valueFits(col, c.Op, v, fmt.Sprintf("%s.values[%d]", path, i)); err != nil {
				return nil, err
			}
		}
		out.Values = slices.Clone(c.Values)
		return out, nil
	}
	if len(c.Values) > 0 {
		return nil, verr(CodeBadValue, path+".values")
	}
	if err := valueFits(col, c.Op, c.Value, path+".value"); err != nil {
		return nil, err
	}
	out.Value = c.Value
	return out, nil
}

func (r *resolver) paramValue(name, path string) (ParamValue, error) {
	if _, ok := r.def.param(name); !ok {
		return ParamValue{}, verr(CodeUnknownParameter, "params."+safeKey(name))
	}
	v, ok := r.vals[name]
	if !ok {
		return ParamValue{}, verr(CodeMissingParameter, path)
	}
	return v, nil
}

// valueFits checks that v can be compared with col by op.
func valueFits(col Column, op Op, v Value, path string) error {
	if err := v.check(path); err != nil {
		return err
	}
	want := col.Type
	switch {
	case op.relative():
		if v.t != TypeInt || v.i < 1 || v.i > maxDaysNumber {
			return verr(CodeBadValue, path)
		}
		return nil
	case op == OpContains || op == OpPrefix:
		want = TypeText
	}
	if v.t != want {
		return verr(CodeBadValue, path)
	}
	if want == TypeEnum && !col.HasEnum(v.s) {
		return verr(CodeBadValue, path)
	}
	return nil
}

// split separates the top-level conjuncts of the resolved filter into the SQL part and the per-DC
// part. A conjunct that touches both kinds of column cannot be evaluated by either and is refused.
func (r *resolver) split(e Expr) (sql, perDC Expr, err error) {
	var sqlTerms, dcTerms []Expr
	for _, t := range conjuncts(e) {
		var nDC, nSQL int
		for _, c := range columns(t, nil) {
			if col, _ := r.ds.Column(c); col.IsPerDC() {
				nDC++
			} else {
				nSQL++
			}
		}
		switch {
		case nDC > 0 && nSQL > 0:
			return nil, nil, verr(CodePerDCMisplaced, "where")
		case nDC > 0:
			dcTerms = append(dcTerms, t)
		default:
			sqlTerms = append(sqlTerms, t)
		}
	}
	return join(sqlTerms), join(dcTerms), nil
}

func conjuncts(e Expr) []Expr {
	if a, ok := e.(And); ok {
		var out []Expr
		for _, t := range a.Terms {
			out = append(out, conjuncts(t)...)
		}
		return out
	}
	return []Expr{e}
}

func join(ts []Expr) Expr {
	switch len(ts) {
	case 0:
		return nil
	case 1:
		return ts[0]
	}
	return And{ts}
}

// Validate re-checks a Query against the dataset: the invariants the compiler relies on. It is how
// a Query read back from storage (a stored run's filters) is trusted again.
func (q Query) Validate(ds Dataset) error {
	if !q.resolved {
		return verr(CodeInvalidQuery, "query")
	}
	if q.Dataset != ds.ID {
		return verr(CodeUnknownDataset, "dataset")
	}
	if len(q.Columns) == 0 || len(q.Columns) > MaxQueryCols {
		return verr(CodeTooManyColumns, "columns")
	}
	for _, c := range q.Columns {
		if _, ok := ds.Column(c); !ok {
			return verr(CodeUnknownColumn, "columns")
		}
	}
	r := &resolver{ds: ds, def: Definition{}}
	for _, part := range []struct {
		e    Expr
		path string
		dc   bool
	}{{q.Where, "where", false}, {q.PerDCWhere, "perDCWhere", true}} {
		if part.e == nil {
			continue
		}
		if _, err := r.expr(part.e, part.path, 0); err != nil {
			return err
		}
		for _, c := range columns(part.e, nil) {
			if col, _ := ds.Column(c); col.IsPerDC() != part.dc {
				return verr(CodePerDCMisplaced, part.path)
			}
		}
	}
	return nil
}

// Hash is the SHA-256 of the canonical JSON of the Query. Two requests that mean the same query have
// the same hash, so a run can be reused (§6.1) and the filters can be hashed in audit without values.
func (q Query) Hash() [32]byte {
	n := q.Narrowing
	type root struct {
		Connection string `json:"connection"`
		Root       string `json:"root"`
		Depth      string `json:"depth"`
	}
	roots := func(rs []NarrowRoot) []root {
		out := make([]root, 0, len(rs))
		for _, r := range rs {
			out = append(out, root{GUIDString(r.Connection), GUIDString(r.Root), r.Depth.String()})
		}
		slices.SortFunc(out, func(a, b root) int {
			return strings.Compare(a.Connection+a.Root+a.Depth, b.Connection+b.Root+b.Depth)
		})
		return out
	}
	guids := func(ids []authz.ObjectID) []string {
		out := make([]string, 0, len(ids))
		for _, id := range ids {
			out = append(out, GUIDString(id))
		}
		slices.Sort(out)
		return out
	}
	type sortKey struct {
		Column ColumnID `json:"column"`
		Dir    string   `json:"dir"`
	}
	sorts := make([]sortKey, 0, len(q.Sort))
	for _, k := range q.Sort {
		sorts = append(sorts, sortKey{k.Column, k.Dir.String()})
	}
	type hidden struct {
		ID    string `json:"id"`
		Where Expr   `json:"where"`
	}
	hs := make([]hidden, 0, len(q.Hidden))
	for _, h := range q.Hidden {
		hs = append(hs, hidden{h.ID, h.Where})
	}
	doc := struct {
		Dataset    DatasetID  `json:"dataset"`
		Columns    []ColumnID `json:"columns"`
		Where      Expr       `json:"where"`
		PerDCWhere Expr       `json:"perDCWhere"`
		Hidden     []hidden   `json:"hidden"`
		Sort       []sortKey  `json:"sort"`
		Top        int        `json:"top"`
		Conns      []string   `json:"connections"`
		Include    []root     `json:"include"`
		Exclude    []root     `json:"exclude"`
		Subjects   []string   `json:"subjects"`
	}{q.Dataset, q.Columns, q.Where, q.PerDCWhere, hs, sorts, q.Top, guids(n.Connections), roots(n.Include), roots(n.Exclude), guids(q.Subjects)}
	b, err := json.Marshal(doc)
	if err != nil {
		// Every field is a plain type or an Expr built by Resolve; a failure here is a programming error.
		panic("report: hashing a query: " + err.Error())
	}
	return sha256.Sum256(b)
}

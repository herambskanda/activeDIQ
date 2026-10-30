package reportsql

import (
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store"
)

// CompiledSQL is SQL text only this package produces (RP1). It never holds a value: every value is
// a numbered placeholder bound through Query's arguments.
type CompiledSQL string

// Inputs are the run's bound inputs. Now is bound once and is the only time any column sees.
type Inputs struct {
	Now time.Time
	// Limit, when positive, caps the rows read (the run path passes its row cap plus one). The
	// smaller of Limit and the preset's Top applies.
	Limit int
}

type outCol struct {
	col     *column
	unknown int // index in cells of the state column that makes this cell unknown, or -1
}

// Query is a compiled query. Its fields are unexported: only Compile and CompileCount build one.
type Query struct {
	sql     CompiledSQL
	args    []any
	out     []outCol // requested columns, then auxiliary state columns
	nReq    int
	nHidden int
	reasons []string
}

// ScopeReasons says why the scope renders narrower than the assignments suggest: the reasons the
// producer recorded in the ReadScope, then the compiler's own ("scope_empty", "scope_term_invalid",
// "scope_term_unsupported:<kind>"). A scope that renders FALSE is not an error (contract §4.3).
func (q Query) ScopeReasons() []string { return append([]string(nil), q.reasons...) }

type argKey struct {
	cast string
	v    any
}

type builder struct {
	d       *dataset
	args    []any
	idx     map[argKey]int
	now     time.Time
	nowSQL  string
	plan    *scopePlan
	relSQL  map[report.AnchorID]string
	reasons []string
}

func (b *builder) bind(cast string, v any) string {
	k := argKey{cast, v}
	if i, ok := b.idx[k]; ok {
		return "$" + strconv.Itoa(i) + "::" + cast
	}
	b.args = append(b.args, v)
	i := len(b.args)
	b.idx[k] = i
	return "$" + strconv.Itoa(i) + "::" + cast
}

// bindList binds a slice (not comparable, so never shared).
func (b *builder) bindList(cast string, v any) string {
	b.args = append(b.args, v)
	return "$" + strconv.Itoa(len(b.args)) + "::" + cast
}

func (b *builder) nowParam() string {
	if b.nowSQL == "" {
		b.nowSQL = b.bind("timestamptz", b.now)
	}
	return b.nowSQL
}

func newBuilder(ds Dataset, scope authz.ReadScope, in Inputs) (*builder, error) {
	if ds.d == nil {
		return nil, ErrInvalidQuery
	}
	if in.Now.IsZero() {
		return nil, ErrNoNow
	}
	b := &builder{d: ds.d, idx: map[argKey]int{}, now: in.Now.UTC(), relSQL: map[report.AnchorID]string{}}
	var err error
	if b.plan, err = b.planScope(scope); err != nil {
		return nil, err
	}
	var produced []string
	for _, r := range scope.Reasons() {
		produced = append(produced, string(r))
	}
	b.reasons = append(produced, b.reasons...)
	return b, nil
}

// Compile turns a resolved report.Query and the runner's read scope into one parameterised query.
func Compile(q report.Query, ds Dataset, scope authz.ReadScope, in Inputs) (Query, error) {
	return compile(q, ds, scope, in, false)
}

// CompileCount is Compile's count(*) over the same FROM and WHERE (contract §5).
func CompileCount(q report.Query, ds Dataset, scope authz.ReadScope, in Inputs) (Query, error) {
	return compile(q, ds, scope, in, true)
}

func compile(q report.Query, ds Dataset, scope authz.ReadScope, in Inputs, count bool) (Query, error) {
	b, err := newBuilder(ds, scope, in)
	if err != nil {
		return Query{}, err
	}
	d := b.d
	if err := q.Validate(d.src); err != nil {
		return Query{}, err
	}
	if err := checkNarrowing(q.Narrowing); err != nil {
		return Query{}, err
	}
	out := Query{}
	var sel []string
	if !count {
		rk, err := b.expand(d.rowKey)
		if err != nil {
			return Query{}, err
		}
		sel = append(sel, "("+rk+")::text")
		pos := map[report.ColumnID]int{}
		for _, id := range q.Columns {
			c, ok := d.cols[id]
			if !ok {
				return Query{}, ErrUnknownColumn
			}
			e, err := b.outExpr(c)
			if err != nil {
				return Query{}, err
			}
			pos[id] = len(out.out)
			out.out = append(out.out, outCol{col: c, unknown: -1})
			sel = append(sel, e)
		}
		out.nReq = len(out.out)
		for i := range out.out {
			w := out.out[i].col.src.UnknownWhen
			if w == "" {
				continue
			}
			p, ok := pos[w]
			if !ok {
				st := d.cols[w]
				e, err := b.outExpr(st)
				if err != nil {
					return Query{}, err
				}
				p = len(out.out)
				pos[w] = p
				out.out = append(out.out, outCol{col: st, unknown: -1})
				sel = append(sel, e)
			}
			out.out[i].unknown = p
		}
		for _, h := range q.Hidden {
			p, err := b.expr(h.Where, 0)
			if err != nil {
				return Query{}, err
			}
			sel = append(sel, "COALESCE(("+p+"), false)")
			out.nHidden++
		}
	}

	var from strings.Builder
	from.WriteString(" FROM " + d.base + ` AS "t"`)
	for _, j := range d.joins {
		on, err := b.expand(j.on)
		if err != nil {
			return Query{}, err
		}
		from.WriteString(" JOIN " + j.a.table + ` AS "` + string(j.a.src.ID) + `" ON (` + on + ")")
	}

	var where []string
	if d.baseWhere != nil {
		w, err := b.expand(d.baseWhere)
		if err != nil {
			return Query{}, err
		}
		where = append(where, "("+w+")")
	}
	for _, a := range d.src.Anchors {
		if a.Mode != report.RowAnchor {
			continue
		}
		ca, alias := d.anchors[a.ID], `"`+string(a.ID)+`"`
		where = append(where, "("+b.scopeSQL(ca, alias)+")")
		if n := b.narrowSQL(q.Narrowing, ca, alias); n != "" {
			where = append(where, "("+n+")")
		}
	}
	if len(q.Subjects) > 0 {
		ta, ok := d.anchors["t"]
		if !ok {
			return Query{}, ErrNoSubjects
		}
		ids := make([]string, 0, len(q.Subjects))
		for _, s := range q.Subjects {
			ids = append(ids, report.GUIDString(s))
		}
		where = append(where, `("t".`+ta.obj+" = ANY("+b.bindList("uuid[]", ids)+"))")
	}
	if q.Where != nil {
		w, err := b.expr(q.Where, 0)
		if err != nil {
			return Query{}, err
		}
		where = append(where, "("+w+")")
	}
	if q.PerDCWhere != nil {
		return Query{}, ErrPerDCInSQL
	}

	var sb strings.Builder
	if count {
		sb.WriteString("SELECT count(*)")
	} else {
		sb.WriteString("SELECT " + strings.Join(sel, ", "))
	}
	sb.WriteString(from.String())
	sb.WriteString(" WHERE " + strings.Join(where, " AND "))
	if !count {
		ord, err := b.orderBy(q.Sort)
		if err != nil {
			return Query{}, err
		}
		sb.WriteString(" ORDER BY " + ord)
		limit := int64(in.Limit)
		if q.Top > 0 && (limit <= 0 || int64(q.Top) < limit) {
			limit = int64(q.Top)
		}
		if limit > 0 {
			sb.WriteString(" LIMIT " + b.bind("bigint", limit))
		}
	}
	out.sql = CompiledSQL(sb.String())
	out.args = b.args
	out.reasons = b.reasons
	return out, nil
}

// ---- fragments ----------------------------------------------------------------------------------

func (b *builder) expand(f *frag) (string, error) {
	var sb strings.Builder
	for _, p := range f.parts {
		switch p.Kind {
		case report.SlotLiteral:
			sb.WriteString(p.Text)
		case report.SlotBase:
			sb.WriteString(`"t"`)
		case report.SlotNow:
			sb.WriteString(b.nowParam())
		case report.SlotRel:
			s, err := b.relation(p.ID)
			if err != nil {
				return "", err
			}
			sb.WriteString(s)
		case report.SlotInScope:
			sb.WriteString(`"` + string(p.ID) + `".in_scope`)
		}
	}
	return sb.String(), nil
}

// relation builds {rel.<id>}: a subselect the compiler writes itself (contract §3.3).
func (b *builder) relation(id report.AnchorID) (string, error) {
	if s, ok := b.relSQL[id]; ok {
		return s, nil
	}
	alias := `"` + string(id) + `"`
	var s string
	if a, ok := b.d.anchors[id]; ok {
		if a.src.Mode == report.RowAnchor {
			// A joined RowAnchor is already in FROM, with its scope in WHERE: the slot is its alias.
			return alias, nil
		}
		scope := b.scopeSQL(a, alias)
		switch a.src.Mode {
		case report.FilterAnchor:
			s = "(SELECT " + a.project + " FROM " + a.table + " AS " + alias + " WHERE " + scope + ") AS " + alias
		case report.MaskAnchor:
			cols := append([]string{}, a.projectCols...)
			for _, c := range a.identityCols {
				cols = append(cols, "CASE WHEN "+scope+" THEN "+alias+"."+c+" END AS "+c)
			}
			cols = append(cols, scope+" AS in_scope")
			s = "(SELECT " + strings.Join(cols, ", ") + " FROM " + a.table + " AS " + alias + ") AS " + alias
		default:
			return "", ErrInvalidQuery
		}
	} else if r, ok := b.d.rels[id]; ok {
		s = "(SELECT " + strings.Join(r.project, ", ") + " FROM " + r.table + " AS " + alias
		if r.where != nil {
			w, err := b.expand(r.where)
			if err != nil {
				return "", err
			}
			s += " WHERE (" + w + ")"
		}
		s += ") AS " + alias
	} else {
		return "", ErrInvalidQuery
	}
	b.relSQL[id] = s
	return s, nil
}

// ---- columns ------------------------------------------------------------------------------------

func sqlType(t report.ValueType) string {
	switch t {
	case report.TypeInt:
		return "bigint"
	case report.TypeBool:
		return "boolean"
	case report.TypeTime:
		return "timestamptz"
	case report.TypeGUID:
		return "uuid"
	case report.TypeTextList:
		return "text[]"
	}
	return "text"
}

// rawExpr is a column's value expression, cast to its type.
func (b *builder) rawExpr(c *column) (string, error) {
	t := sqlType(c.src.Type)
	switch s := c.src.Source.(type) {
	case report.Attr:
		return `("t".` + c.attr + ")::" + t, nil
	case report.JSONAttr:
		doc := `"t".` + c.attr
		key := b.bind("text", s.Key)
		switch s.As {
		case report.TypeInt:
			return "(CASE WHEN jsonb_typeof(" + doc + " -> " + key + ") = 'number' AND (" + doc + " ->> " + key + ") ~ '^-?[0-9]{1,18}$' THEN (" + doc + " ->> " + key + ")::bigint END)", nil
		case report.TypeBool:
			return "(CASE WHEN jsonb_typeof(" + doc + " -> " + key + ") = 'boolean' THEN (" + doc + " ->> " + key + ")::boolean END)", nil
		}
		return "(" + doc + " ->> " + key + ")::text", nil
	case report.Derived:
		e, err := b.expand(c.frag)
		if err != nil {
			return "", err
		}
		return "(" + e + ")::" + t, nil
	case report.PerDC:
		return "NULL::" + t, nil
	}
	return "", ErrUnknownColumn
}

// outExpr is the select-list form: GUIDs come back as text.
func (b *builder) outExpr(c *column) (string, error) {
	e, err := b.rawExpr(c)
	if err != nil {
		return "", err
	}
	if c.src.Type == report.TypeGUID {
		return "(" + e + ")::text", nil
	}
	return e, nil
}

// ---- filters ------------------------------------------------------------------------------------

func (b *builder) expr(e report.Expr, depth int) (string, error) {
	if depth > report.MaxExprDepth {
		return "", ErrInvalidQuery
	}
	join := func(ts []report.Expr, op string) (string, error) {
		if len(ts) == 0 || len(ts) > report.MaxExprTerms {
			return "", ErrInvalidQuery
		}
		parts := make([]string, 0, len(ts))
		for _, t := range ts {
			s, err := b.expr(t, depth+1)
			if err != nil {
				return "", err
			}
			parts = append(parts, "("+s+")")
		}
		return strings.Join(parts, " "+op+" "), nil
	}
	switch x := e.(type) {
	case report.And:
		return join(x.Terms, "AND")
	case report.Or:
		return join(x.Terms, "OR")
	case report.Not:
		s, err := b.expr(x.Term, depth+1)
		return "NOT (" + s + ")", err
	case report.Cmp:
		return b.cmp(x)
	}
	return "", ErrInvalidQuery
}

func (b *builder) value(c report.Column, v report.Value) (any, string, error) {
	if v.Type() != c.Type {
		return nil, "", ErrBadValue
	}
	switch c.Type {
	case report.TypeText, report.TypeEnum:
		s := v.Text()
		if strings.IndexByte(s, 0) >= 0 {
			return nil, "", ErrNulInText
		}
		if !utf8.ValidString(s) {
			return nil, "", ErrInvalidUTF8
		}
		if len(s) > report.MaxTextValue || (c.Type == report.TypeEnum && !c.HasEnum(s)) {
			return nil, "", ErrBadValue
		}
		return s, "text", nil
	case report.TypeInt:
		return v.Int(), "bigint", nil
	case report.TypeBool:
		return v.Bool(), "boolean", nil
	case report.TypeTime:
		return v.Time().UTC(), "timestamptz", nil
	case report.TypeGUID:
		if v.GUID().IsZero() {
			return nil, "", ErrBadValue
		}
		return report.GUIDString(v.GUID()), "uuid", nil
	}
	return nil, "", ErrBadValue
}

func (b *builder) cmp(c report.Cmp) (string, error) {
	col, ok := b.d.cols[c.Column]
	if !ok {
		return "", ErrUnknownColumn
	}
	if col.src.IsPerDC() {
		return "", ErrPerDCInSQL
	}
	if !c.Op.Valid() || !col.src.Accepts(c.Op) {
		return "", ErrBadOperator
	}
	if c.Param != "" {
		return "", ErrInvalidQuery
	}
	e, err := b.rawExpr(col)
	if err != nil {
		return "", err
	}
	var pred string
	switch c.Op {
	case report.OpPresent:
		pred = "(" + e + " IS NOT NULL)"
	case report.OpAbsent:
		pred = "(" + e + " IS NULL)"
	case report.OpIn:
		if len(c.Values) == 0 {
			return "", ErrBadValue
		}
		if len(c.Values) > report.MaxInValues {
			return "", ErrTooManyValues
		}
		arr, cast, err := b.valueList(col.src, c.Values)
		if err != nil {
			return "", err
		}
		pred = "COALESCE(" + e + " = ANY(" + b.bindList(cast+"[]", arr) + "), false)"
	case report.OpContains, report.OpPrefix:
		if c.Value.Type() != report.TypeText {
			return "", ErrBadValue
		}
		var p store.LikePattern
		if c.Op == report.OpContains {
			p, err = store.LikePattern{}.Contains(c.Value.Text())
		} else {
			p, err = store.LikePattern{}.Prefix(c.Value.Text())
		}
		if err != nil {
			return "", err
		}
		if len(c.Value.Text()) > report.MaxTextValue {
			return "", ErrBadValue
		}
		if col.src.Type == report.TypeTextList {
			pred = "COALESCE(" + b.bind("text", c.Value.Text()) + " = ANY(" + e + "), false)"
		} else {
			pred = "COALESCE(" + e + ` ILIKE ` + b.bind("text", p) + ` ESCAPE '\', false)`
		}
	case report.OpWithinLastDays, report.OpOlderThanDays, report.OpWithinNextDays:
		if c.Value.Type() != report.TypeInt || c.Value.Int() < 0 || c.Value.Int() > 3660 {
			return "", ErrBadValue
		}
		span := "(" + b.bind("bigint", c.Value.Int()) + " * interval '24 hours')"
		now := b.nowParam()
		switch c.Op {
		case report.OpWithinLastDays:
			pred = "COALESCE(" + e + " > " + now + " - " + span + " AND " + e + " <= " + now + ", false)"
		case report.OpOlderThanDays:
			pred = "COALESCE(" + e + " <= " + now + " - " + span + ", false)"
		default:
			pred = "COALESCE(" + e + " > " + now + " AND " + e + " <= " + now + " + " + span + ", false)"
		}
	default:
		v, cast, err := b.value(col.src, c.Value)
		if err != nil {
			return "", err
		}
		p := b.bind(cast, v)
		switch c.Op {
		case report.OpEq:
			pred = "COALESCE(" + e + " = " + p + ", false)"
		case report.OpNe:
			pred = "(" + e + " IS DISTINCT FROM " + p + ")"
		case report.OpLt:
			pred = "COALESCE(" + e + " < " + p + ", false)"
		case report.OpLe:
			pred = "COALESCE(" + e + " <= " + p + ", false)"
		case report.OpGt:
			pred = "COALESCE(" + e + " > " + p + ", false)"
		case report.OpGe:
			pred = "COALESCE(" + e + " >= " + p + ", false)"
		default:
			return "", ErrBadOperator
		}
	}
	if w := col.src.UnknownWhen; w != "" {
		st := b.d.cols[w]
		se, err := b.rawExpr(st)
		if err != nil {
			return "", err
		}
		return "CASE WHEN " + se + " = " + b.bind("text", report.UnknownInputMissing) + " THEN NULL ELSE (" + pred + ") END", nil
	}
	return pred, nil
}

func (b *builder) valueList(c report.Column, vs []report.Value) (any, string, error) {
	var cast string
	var strs []string
	var ints []int64
	var bools []bool
	var times []time.Time
	for _, v := range vs {
		x, ct, err := b.value(c, v)
		if err != nil {
			return nil, "", err
		}
		cast = ct
		switch t := x.(type) {
		case string:
			strs = append(strs, t)
		case int64:
			ints = append(ints, t)
		case bool:
			bools = append(bools, t)
		case time.Time:
			times = append(times, t)
		}
	}
	switch {
	case strs != nil:
		return strs, cast, nil
	case ints != nil:
		return ints, cast, nil
	case bools != nil:
		return bools, cast, nil
	}
	return times, cast, nil
}

// ---- order --------------------------------------------------------------------------------------

// orderBy renders the sort keys and the row key (ordinal 1) as the final tie-break. NULLs sort last
// in both directions so a page boundary never depends on the direction.
func (b *builder) orderBy(keys []report.SortKey) (string, error) {
	var parts []string
	for _, k := range keys {
		if !k.Dir.Valid() {
			return "", ErrBadSortDirection
		}
		c, ok := b.d.cols[k.Column]
		if !ok {
			return "", ErrUnknownColumn
		}
		if c.src.IsPerDC() {
			return "", ErrPerDCInSQL
		}
		if !c.src.Sortable {
			return "", ErrBadOperator
		}
		e, err := b.rawExpr(c)
		if err != nil {
			return "", err
		}
		if c.src.Type == report.TypeEnum {
			var sb strings.Builder
			sb.WriteString("CASE " + e)
			for _, ev := range c.src.Enum {
				sb.WriteString(" WHEN " + b.bind("text", ev.ID) + " THEN " + strconv.Itoa(ev.SortRank))
			}
			sb.WriteString(" END")
			e = sb.String()
		}
		dir := "ASC"
		if k.Dir == report.Desc {
			dir = "DESC"
		}
		parts = append(parts, e+" "+dir+" NULLS LAST")
	}
	parts = append(parts, "1")
	return strings.Join(parts, ", "), nil
}

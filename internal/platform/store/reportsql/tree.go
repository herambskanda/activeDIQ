package reportsql

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store"
)

// CompileTree is the third statement family over the one scope renderer (ADR-0011 amendment E3, spec
// ad-explorer-read-api X3): the OU-tree reads of AD Explorer. It draws the caller's ReadScope with the same
// planScope/scopeSQL as Compile and CompileSearch; there is no second renderer, no per-row Admits and no
// scope copied into a column. The statements are fixed templates: a value is a bound parameter and an
// identifier was checked against the schema and quoted once in NewTreeSource.
//
// Only live rows of AD connections (nc_guid IS NOT NULL) are ever read (X6). A hidden row is absent, never
// refused: the statements cannot tell "hidden" from "not there" (X5).

// TreeSource names the directory_objects anchor and the four columns the tree reads. inventory registers it
// once, as it registers datasets and the search source.
type TreeSource struct {
	objects                 *anchor
	kind, state, rdn, label string
}

// NewTreeSource checks every identifier against the schema and quotes it once.
func NewTreeSource(sch Schema, objects report.Anchor, kind, state, rdn, display report.Ident) (TreeSource, error) {
	var s TreeSource
	a, err := buildAnchor(sch, objects)
	if err != nil {
		return s, fmt.Errorf("reportsql: tree objects: %w", err)
	}
	if k, ok := sch.Column(string(objects.Table), "tenant_id"); !ok || k != KindGUID {
		return s, fmt.Errorf("reportsql: tree objects: tenant_id missing or not guid")
	}
	for _, c := range []struct {
		dst  *string
		col  report.Ident
		want ColKind
	}{{&s.kind, kind, KindEnum}, {&s.state, state, KindEnum}, {&s.rdn, rdn, KindText}, {&s.label, display, KindText}} {
		k, ok := sch.Column(string(objects.Table), string(c.col))
		if !ok || k != c.want {
			return s, fmt.Errorf("reportsql: tree objects: column %q missing or not %s", c.col, c.want)
		}
		*c.dst = quote(c.col)
	}
	s.objects = a
	return s, nil
}

// TreeOp picks one of the three statements.
type TreeOp int

// The operations.
const (
	// TreeChildren pages the live children of Parent in Connection (view containers or all).
	TreeChildren TreeOp = 1 + iota
	// TreeRoots lists the admitted containers whose parent is absent or not admitted.
	TreeRoots
	// TreeNode reads one admitted node and its contiguous admitted ancestor path.
	TreeNode
)

// Tree limits (spec §4).
const (
	MaxTreeLimit       = 200
	MaxTreeRoots       = 500
	MaxTreeExamine     = 5000
	DefaultTreeProbe   = 50
	treeContainerKinds = "'ou', 'container'"
)

// TreeAfter is the keyset position of a children page: (isLeaf, lower(rdn) COLLATE "C", objectGuid). The
// caller signs it into the opaque cursor (the search cursor codec) and verifies it before it comes back;
// this package treats it as a plain value and binds every field.
type TreeAfter struct {
	Leaf   bool
	Name   string // lower-cased rdn, as the statement returns it
	Object string
}

// TreeQuery is the typed input of one tree statement.
type TreeQuery struct {
	Op TreeOp
	// Connection is required for children and node, optional for roots (zero means every connection).
	Connection string
	// Object is the parent (children) or the node (node), a canonical GUID.
	Object string
	// ContainersOnly is view=containers.
	ContainersOnly bool
	After          *TreeAfter
	// Limit is the page size, 1..MaxTreeLimit (children only; roots read MaxTreeRoots+1).
	Limit int
	// Examine is W_e: the child rows read before the scope cut, 1..MaxTreeExamine (children only).
	Examine int
	// Probe bounds the child rows one hasChildren probe reads before the scope cut; 0 means
	// DefaultTreeProbe. A probe that reads that many without finding an admitted child answers true.
	Probe int
	Scope authz.ReadScope
}

// ref wraps the rdn so the sort key is one expression everywhere.
func (s TreeSource) name(alias string) string {
	return "(lower(" + alias + "." + s.rdn + ") COLLATE \"C\")"
}

func (s TreeSource) leaf(alias string) string {
	return "(" + alias + "." + s.kind + " NOT IN (" + treeContainerKinds + "))"
}

// live is the Explorer's row filter (X6), the same for every alias.
func (s TreeSource) live(alias string) string {
	return alias + ".tenant_id = " + tenantExpr + " AND " + alias + "." + s.state + " = 'live' AND " + alias + "." + s.objects.nc + " IS NOT NULL"
}

// CompileTree renders one tree statement.
func CompileTree(src TreeSource, q TreeQuery) (Query, error) {
	if src.objects == nil {
		return Query{}, ErrInvalidQuery
	}
	b := &builder{idx: map[argKey]int{}}
	a := src.objects
	if q.Scope.Empty() {
		b.reason("scope_empty")
	}
	for _, r := range q.Scope.Reasons() {
		b.reason(string(r))
	}
	plan, err := b.planScope(q.Scope)
	if err != nil {
		return Query{}, err
	}
	b.plan = plan
	tbl := "public." + a.table
	var sql string
	meta := &treeMeta{op: q.Op}
	switch q.Op {
	case TreeChildren:
		if !validGUID(q.Connection) || !validGUID(q.Object) || q.Limit < 1 || q.Limit > MaxTreeLimit || q.Examine < 1 || q.Examine > MaxTreeExamine || q.Probe < 0 {
			return Query{}, ErrInvalidQuery
		}
		if q.After != nil && !validGUID(q.After.Object) {
			return Query{}, ErrInvalidQuery
		}
		probe := q.Probe
		if probe == 0 {
			probe = DefaultTreeProbe
		}
		meta.limit, meta.examine = q.Limit, q.Examine
		var w strings.Builder
		w.WriteString("t." + a.conn + " = " + b.bind("uuid", q.Connection) + " AND t." + a.parent + " = " + b.bind("uuid", q.Object) + " AND " + src.live("t"))
		// The parent itself must be live and admitted: a hidden or missing container answers like an empty
		// one (X5), whatever the caller checked first. One probe on the primary key.
		w.WriteString(" AND EXISTS (SELECT 1 FROM par)")
		if q.ContainersOnly {
			w.WriteString(" AND t." + src.kind + " IN (" + treeContainerKinds + ")")
		}
		if af := q.After; af != nil {
			w.WriteString(" AND (" + src.leaf("t") + ", " + src.name("t") + ", t." + a.obj + ") > (" +
				b.bind("bool", af.Leaf) + ", " + b.bind("text", af.Name) + " COLLATE \"C\", " + b.bind("uuid", af.Object) + ")")
		}
		// base is the unscoped work bound: at most W_e rows in index order. It is read once and shared by
		// the page and the "last examined" row the continuation needs.
		sql = "WITH par AS MATERIALIZED (SELECT 1 FROM " + tbl + " pp WHERE pp.tenant_id = " + tenantExpr + " AND pp." + a.conn + " = " + b.bind("uuid", q.Connection) + " AND pp." + a.obj + " = " + b.bind("uuid", q.Object) +
			" AND pp." + src.state + " = 'live' AND pp." + a.nc + " IS NOT NULL AND " + b.scopeSQL(a, "pp") + "), " +
			"base AS MATERIALIZED (SELECT t." + a.conn + " AS connection_id, t." + a.obj + " AS object_guid, t." + a.parent + " AS parent_guid, " +
			"t." + src.kind + " AS kind, t." + src.rdn + " AS rdn, t." + src.label + " AS display_name, " + src.leaf("t") + " AS leaf, " + src.name("t") + " AS nm, " +
			b.scopeSQL(a, "t") + " AS ok " +
			"FROM " + tbl + " t WHERE " + w.String() +
			" ORDER BY " + src.leaf("t") + ", " + src.name("t") + ", t." + a.obj + " LIMIT " + b.bind("int", q.Examine) + "), " +
			"meta AS (SELECT count(*) AS examined, (array_agg(leaf ORDER BY leaf DESC, nm DESC, object_guid DESC))[1] AS last_leaf, " +
			"(array_agg(nm ORDER BY leaf DESC, nm DESC, object_guid DESC))[1] AS last_nm, " +
			"(array_agg(object_guid ORDER BY leaf DESC, nm DESC, object_guid DESC))[1] AS last_guid FROM base), " +
			"page AS (SELECT * FROM base WHERE ok ORDER BY leaf, nm, object_guid LIMIT " + b.bind("int", q.Limit+1) + ") " +
			"SELECT m.examined, m.last_leaf, m.last_nm, m.last_guid::text, p.connection_id::text, p.object_guid::text, p.parent_guid::text, p.kind, p.rdn, p.display_name, p.leaf, p.nm, " +
			"CASE WHEN p.leaf THEN false ELSE COALESCE(hc.found, true) END " +
			"FROM meta m LEFT JOIN page p ON TRUE " +
			"LEFT JOIN LATERAL (SELECT COALESCE(bool_or(z.ok), false) OR count(*) >= " + b.bind("int", probe) + " AS found FROM (SELECT COALESCE(" + b.scopeSQL(a, "c") + ", false) AS ok FROM " + tbl + " c " +
			"WHERE c." + a.conn + " = p.connection_id AND c." + a.parent + " = p.object_guid AND " + src.live("c") + " ORDER BY " + src.leaf("c") + ", " + src.name("c") + ", c." + a.obj + " LIMIT " + b.bind("int", probe) + ") z) hc ON NOT COALESCE(p.leaf, true) " +
			"ORDER BY p.leaf, p.nm, p.object_guid"
	case TreeRoots:
		if q.Connection != "" && !validGUID(q.Connection) {
			return Query{}, ErrInvalidQuery
		}
		var w strings.Builder
		w.WriteString(src.live("t") + " AND t." + src.kind + " IN (" + treeContainerKinds + ")")
		if q.Connection != "" {
			w.WriteString(" AND t." + a.conn + " = " + b.bind("uuid", q.Connection))
		}
		w.WriteString(" AND " + b.scopeSQL(a, "t"))
		// A scalar subquery with LIMIT 1 is one primary-key probe per candidate; an EXISTS would be planned as
		// a hashed semi-join over the whole table. No parent row, or one that is not live, gives NULL: not a
		// root (fail closed).
		w.WriteString(" AND (t." + a.parent + " IS NULL OR COALESCE((SELECT (p." + src.state + " = 'live' AND p." + a.nc + " IS NOT NULL AND NOT " + b.scopeSQL(a, "p") + ") FROM " + tbl +
			" p WHERE p.tenant_id = " + tenantExpr + " AND p." + a.conn + " = t." + a.conn + " AND p." + a.obj + " = t." + a.parent + " LIMIT 1), false))")
		meta.limit = MaxTreeRoots
		sql = "SELECT t." + a.conn + "::text, t." + a.obj + "::text, NULL::text, t." + src.kind + ", t." + src.rdn + ", t." + src.label + " FROM " + tbl + " t WHERE " + w.String() +
			" ORDER BY t." + a.conn + ", " + src.name("t") + ", t." + a.obj + " LIMIT " + b.bind("int", MaxTreeRoots+1)
	case TreeNode:
		if !validGUID(q.Connection) || !validGUID(q.Object) {
			return Query{}, ErrInvalidQuery
		}
		// n is the node under the scope. The ancestors are read by GUID from the node's own ancestry
		// (nearest parent first); the path is the run of ancestors, from the nearest, that are live and
		// admitted. The first one that is not ends it: a hidden ancestor is never named.
		sql = "WITH n AS (SELECT t." + a.conn + " AS connection_id, t." + a.obj + " AS object_guid, t." + a.parent + " AS parent_guid, t." + src.kind + " AS kind, t." + src.rdn + " AS rdn, t." + src.label + " AS display_name, t." + a.anc + " AS anc " +
			"FROM " + tbl + " t WHERE t." + a.conn + " = " + b.bind("uuid", q.Connection) + " AND t." + a.obj + " = " + b.bind("uuid", q.Object) + " AND " + src.live("t") + " AND " + b.scopeSQL(a, "t") + "), " +
			"anc AS (SELECT u.ord, c." + a.obj + " AS object_guid, c." + a.parent + " AS parent_guid, c." + src.kind + " AS kind, c." + src.rdn + " AS rdn, c." + src.label + " AS display_name, " +
			"(c." + a.obj + " IS NOT NULL AND " + src.live("c") + " AND " + b.scopeSQL(a, "c") + ") AS ok " +
			"FROM n CROSS JOIN LATERAL unnest(n.anc) WITH ORDINALITY AS u(guid, ord) LEFT JOIN " + tbl + " c ON c.tenant_id = " + tenantExpr + " AND c." + a.conn + " = n.connection_id AND c." + a.obj + " = u.guid), " +
			"cut AS (SELECT COALESCE(min(ord) FILTER (WHERE NOT COALESCE(ok, false)), 9223372036854775807) AS c FROM anc) " +
			"SELECT 0::bigint AS ord, n.connection_id::text, n.object_guid::text, CASE WHEN (SELECT c FROM cut) > 1 THEN n.parent_guid::text END, n.kind, n.rdn, n.display_name FROM n " +
			"UNION ALL SELECT anc.ord, n.connection_id::text, anc.object_guid::text, CASE WHEN anc.ord + 1 < (SELECT c FROM cut) THEN anc.parent_guid::text END, anc.kind, anc.rdn, anc.display_name FROM anc CROSS JOIN n WHERE anc.ord < (SELECT c FROM cut) " +
			"ORDER BY ord DESC"
	default:
		return Query{}, ErrInvalidQuery
	}
	return Query{sql: CompiledSQL(sql), args: b.args, reasons: b.reasons, tree: meta}, nil
}

func validGUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case i == 8 || i == 13 || i == 18 || i == 23:
			if c != '-' {
				return false
			}
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}

type treeMeta struct {
	op      TreeOp
	limit   int
	examine int
}

// TreeNodeRow is one container or object of the tree. It carries no DN (X8).
type TreeNodeRow struct {
	Connection, Object, Parent string
	Kind                       string
	Rdn, DisplayName           string
	Leaf                       bool
	HasChildren                bool
	// Name is the sort key of the row, the value a TreeAfter carries.
	Name string
}

// TreeResult is the answer.
type TreeResult struct {
	// Rows are the page (children), the roots, or the node followed by nothing (Path holds the rest).
	Rows []TreeNodeRow
	// More says the container has rows past the page; Resume is where the next page starts. For roots,
	// More says there are more than MaxTreeRoots and there is no cursor.
	More   bool
	Resume *TreeAfter
	// Path is the admitted ancestor chain of a node, root first.
	Path []TreeNodeRow
	// Found is set for TreeNode when the node is live and admitted.
	Found        bool
	ScopeReasons []string
}

// ExecTree runs a compiled tree statement in tx.
func ExecTree(ctx context.Context, tx store.Tx, q Query) (TreeResult, error) {
	var res TreeResult
	if q.tree == nil {
		return res, ErrInvalidQuery
	}
	rs, err := tx.Query(ctx, string(q.sql), append([]any{pgx.QueryExecModeExec}, q.args...)...)
	if err != nil {
		return res, wrapErr(ctx, err)
	}
	defer rs.Close()
	res.ScopeReasons = q.ScopeReasons()
	m := q.tree
	switch m.op {
	case TreeChildren:
		var examined int64
		var lastLeaf *bool
		var lastNm, lastGuid *string
		var all []TreeNodeRow
		for rs.Next() {
			var conn, obj, parent, kind, rdn, disp, nm *string
			var leaf, hc *bool
			if err := rs.Scan(&examined, &lastLeaf, &lastNm, &lastGuid, &conn, &obj, &parent, &kind, &rdn, &disp, &leaf, &nm, &hc); err != nil {
				return res, wrapErr(ctx, err)
			}
			if obj == nil {
				continue
			}
			all = append(all, TreeNodeRow{Connection: *conn, Object: *obj, Parent: deref(parent), Kind: *kind, Rdn: *rdn, DisplayName: *disp, Leaf: *leaf, HasChildren: *hc, Name: *nm})
		}
		if err := rs.Err(); err != nil {
			return res, wrapErr(ctx, err)
		}
		if len(all) > m.limit {
			res.More = true
			res.Rows = all[:m.limit]
			last := res.Rows[m.limit-1]
			res.Resume = &TreeAfter{Leaf: last.Leaf, Name: last.Name, Object: last.Object}
			return res, nil
		}
		res.Rows = all
		if int(examined) >= m.examine && lastGuid != nil {
			// The examination ceiling stopped the read before the page filled: continue from the last
			// examined row, never from a count (spec §4).
			res.More = true
			res.Resume = &TreeAfter{Leaf: *lastLeaf, Name: *lastNm, Object: *lastGuid}
		}
	case TreeRoots:
		for rs.Next() {
			var r TreeNodeRow
			var parent *string
			if err := rs.Scan(&r.Connection, &r.Object, &parent, &r.Kind, &r.Rdn, &r.DisplayName); err != nil {
				return res, wrapErr(ctx, err)
			}
			r.Parent = deref(parent)
			res.Rows = append(res.Rows, r)
		}
		if err := rs.Err(); err != nil {
			return res, wrapErr(ctx, err)
		}
		if len(res.Rows) > m.limit {
			res.Rows, res.More = res.Rows[:m.limit], true
		}
	case TreeNode:
		for rs.Next() {
			var ord int64
			var r TreeNodeRow
			var obj, parent *string
			if err := rs.Scan(&ord, &r.Connection, &obj, &parent, &r.Kind, &r.Rdn, &r.DisplayName); err != nil {
				return res, wrapErr(ctx, err)
			}
			r.Object, r.Parent = deref(obj), deref(parent)
			if ord == 0 {
				res.Found = true
				res.Rows = append(res.Rows, r)
			} else {
				res.Path = append(res.Path, r)
			}
		}
		if err := rs.Err(); err != nil {
			return res, wrapErr(ctx, err)
		}
	}
	return res, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

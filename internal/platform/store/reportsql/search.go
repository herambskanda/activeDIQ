package reportsql

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/searchkey"
	"github.com/skenzeriq/activediq/internal/platform/store"
)

// Search is the one statement universal search runs (ADR-0011 rules 11-13). It renders the caller's
// ReadScope with the same scopeSQL the reports use, over the directory_objects anchor, and it is the only
// code that reads the search key table (SE1). The statement is a fixed template: a value is a bound
// parameter, an identifier was checked against the schema and quoted once at registration, and the key
// kinds, classes and groups are integer or string constants of this file.

// SearchSource names the key table, its trigram posting table and the directory_objects anchor. inventory registers it once, as it
// registers datasets.
type SearchSource struct {
	keys, trigrams string
	objects        *anchor
	// quoted object columns the result reads
	kind, state, enabled, display string
}

// NewSearchSource checks every identifier against the schema and quotes it once.
func NewSearchSource(sch Schema, keyTable, trigramTable report.Ident, objects report.Anchor, kind, state, enabled, display report.Ident) (SearchSource, error) {
	var s SearchSource
	for _, c := range []struct {
		col  string
		want ColKind
	}{{"tenant_id", KindGUID}, {"connection_id", KindGUID}, {"object_guid", KindGUID}, {"key_kind", KindInt}, {"key", KindText}, {"norm_version", KindInt}, {"key_id", KindInt}} {
		k, ok := sch.Column(string(keyTable), c.col)
		if !ok || k != c.want {
			return s, fmt.Errorf("reportsql: search key table %q: column %q missing or not %s", keyTable, c.col, c.want)
		}
	}
	for _, c := range []struct {
		col  string
		want ColKind
	}{{"tenant_id", KindGUID}, {"trgm", KindText}, {"key_id", KindInt}} {
		k, ok := sch.Column(string(trigramTable), c.col)
		if !ok || k != c.want {
			return s, fmt.Errorf("reportsql: search trigram table %q: column %q missing or not %s", trigramTable, c.col, c.want)
		}
	}
	a, err := buildAnchor(sch, objects)
	if err != nil {
		return s, fmt.Errorf("reportsql: search objects: %w", err)
	}
	for _, c := range []struct {
		dst *string
		col report.Ident
	}{{&s.kind, kind}, {&s.state, state}, {&s.enabled, enabled}, {&s.display, display}} {
		if _, ok := sch.Column(string(objects.Table), string(c.col)); !ok {
			return s, fmt.Errorf("reportsql: search objects: no column %q", c.col)
		}
		*c.dst = quote(c.col)
	}
	s.keys, s.trigrams, s.objects = quote(keyTable), quote(trigramTable), a
	return s, nil
}

// SearchClass is the match class, best first.
type SearchClass int16

// The classes.
const (
	ClassExact SearchClass = 1 + iota
	ClassPrefix
	ClassFuzzy
)

func (c SearchClass) String() string { return [...]string{"", "exact", "prefix", "fuzzy"}[c] }

// SearchType is the result group (and the type facet).
type SearchType int16

// The groups.
const (
	TypeUser SearchType = 1 + iota
	TypeGroup
	TypeComputer
	TypeContact
)

// AllSearchTypes lists the groups in display order.
var AllSearchTypes = []SearchType{TypeUser, TypeGroup, TypeComputer, TypeContact}

func (t SearchType) kinds() []string {
	switch t {
	case TypeUser:
		return []string{"user", "inetorgperson"}
	case TypeGroup:
		return []string{"group"}
	case TypeComputer:
		return []string{"computer", "gmsa"}
	case TypeContact:
		return []string{"contact"}
	}
	return nil
}

// Search limits.
const (
	MaxSearchGroupLimit = 50
	MaxSearchCeiling    = 100000
)

// SearchAfter is the rank tuple of a hit: the keyset position of a "show all" page. The caller signs it
// into an opaque cursor and verifies it before it comes back here (rule 12); this package treats it as a
// plain value and binds every field.
type SearchAfter struct {
	Class                         SearchClass
	Dead, Disabled, Whole, KeyLen int
	SimRank                       int
	Name                          string
	Connection, Object            string
}

// SearchQuery is the typed input of one search: normalised text and lookups from searchkey.Classify, no
// SQL.
type SearchQuery struct {
	Exact  []searchkey.Probe
	Prefix []searchkey.Prefix
	// Fuzzy is the trigram text; "" means no fuzzy class.
	Fuzzy string
	// Types is the facet; empty means every group.
	Types []SearchType
	// GroupLimit is the hits per group (1..MaxSearchGroupLimit); one more is read to set More.
	GroupLimit int
	// Ceiling is W: matched key rows per class above which the class is withheld (1..MaxSearchCeiling).
	Ceiling int
	// After, when set, starts after that rank tuple within each group.
	After *SearchAfter
	// Threshold is pg_trgm.word_similarity_threshold for the fuzzy class, 0.1..1. ExecSearch sets it for
	// the transaction and puts the earlier value back; this is the only place it is set (SE2).
	Threshold float32
}

// SearchScopes maps a permission to the ReadScope the producer gave for it. A kind whose permission has
// no entry (or an empty scope) is not searched at all.
type SearchScopes map[authz.Permission]authz.ReadScope

// fuzzyKindList is the call's kinds that have trigram postings (searchkey.Kind.FuzzyEligible). Migration
// 0074's trigger function builds postings for the same list.
func fuzzyKindList(kinds []searchkey.Kind) string {
	var parts []string
	for _, k := range kinds {
		if k.FuzzyEligible() {
			parts = append(parts, strconv.Itoa(int(k)))
		}
	}
	return strings.Join(parts, ", ")
}

// FuzzyKindPredicate is the literal list the migration's trigger function must carry.
func FuzzyKindPredicate() string { return fuzzyKindList(searchkey.AllKinds) }

const tenantExpr = `NULLIF(current_setting('app.tenant_id', true), '')::uuid`

const emptyKeys = `SELECT NULL::uuid AS connection_id, NULL::uuid AS object_guid, NULL::smallint AS key_kind, NULL::text AS key WHERE FALSE`

// CompileSearch renders the statement. The scope of each permission is planned with planScope and drawn
// with scopeSQL, the functions RP6 proves.
func CompileSearch(src SearchSource, q SearchQuery, scopes SearchScopes) (Query, error) {
	if q.Fuzzy != "" && (float64(q.Threshold) < store.MinTrigramThreshold || float64(q.Threshold) > store.MaxTrigramThreshold) {
		return Query{}, ErrInvalidQuery
	}
	if src.objects == nil || q.Ceiling < 1 || q.Ceiling > MaxSearchCeiling || q.GroupLimit < 1 || q.GroupLimit > MaxSearchGroupLimit {
		return Query{}, ErrInvalidQuery
	}
	b := &builder{idx: map[argKey]int{}}
	// Kinds are admitted only with a non-empty scope for their permission (rule 12): the set of kinds
	// depends on the caller's permissions, never on the extent of a scope.
	type permPlan struct {
		plan  *scopePlan
		kinds []searchkey.Kind
	}
	plans := map[authz.Permission]*permPlan{}
	var perms []authz.Permission
	allowed := map[searchkey.Kind]bool{}
	for _, k := range searchkey.AllKinds {
		p := authz.Permission(k.Permission())
		sc, ok := scopes[p]
		if !ok || sc.Empty() {
			if ok {
				b.reason("scope_empty")
			}
			continue
		}
		pp := plans[p]
		if pp == nil {
			plan, err := b.planScope(sc)
			if err != nil {
				return Query{}, err
			}
			for _, r := range sc.Reasons() {
				b.reason(string(r))
			}
			if plan.empty {
				continue
			}
			pp = &permPlan{plan: plan}
			plans[p] = pp
			perms = append(perms, p)
		}
		pp.kinds = append(pp.kinds, k)
		allowed[k] = true
	}
	// W+1 is bound on first use: a parameter no statement text refers to has no type and the server
	// refuses the statement.
	w1s := ""
	w1 := func() string {
		if w1s == "" {
			w1s = b.bind("int", q.Ceiling+1)
		}
		return w1s
	}
	limit := func(sel []string) string {
		if len(sel) == 0 {
			return emptyKeys
		}
		return "SELECT connection_id, object_guid, key_kind, key FROM (" + strings.Join(sel, " UNION ALL ") + ") u LIMIT " + w1()
	}
	keyCols := "k.connection_id, k.object_guid, k.key_kind, k.key"
	var exact, prefix, fuzzy []string
	for _, p := range q.Exact {
		if !allowed[p.Kind] {
			continue
		}
		exact = append(exact, "(SELECT "+keyCols+" FROM public."+src.keys+" k WHERE k.tenant_id = "+tenantExpr+" AND k.key_kind = "+strconv.Itoa(int(p.Kind))+
			" AND k.key = "+b.bind("text", p.Key)+" LIMIT "+w1()+")")
	}
	var wholeLo []string
	for _, p := range q.Prefix {
		if !allowed[p.Kind] {
			continue
		}
		cond := "k.key >= " + b.bind("text", p.Lo)
		if p.Bounded {
			cond += " AND k.key < " + b.bind("text", p.Hi)
		}
		wholeLo = append(wholeLo, p.Lo)
		prefix = append(prefix, "(SELECT "+keyCols+" FROM public."+src.keys+" k WHERE k.tenant_id = "+tenantExpr+" AND k.key_kind = "+strconv.Itoa(int(p.Kind))+
			" AND "+cond+" ORDER BY k.key LIMIT "+w1()+")")
	}
	if q.Fuzzy != "" {
		var ks []searchkey.Kind
		// In kind order, so the statement text is the same for the same caller.
		for _, k := range searchkey.AllKinds {
			if allowed[k] {
				ks = append(ks, k)
			}
		}
		if list := fuzzyKindList(ks); list != "" {
			// ADR-0011 rule 5a. Candidates: the key_ids holding at least the share t of the query's n
			// trigrams, from the tenant-led posting B-tree. The share is pg_trgm's own GIN consistency rule
			// for <%, a float4 division compared with the double threshold, so the set is a superset of the
			// matches (never a ceil(t*n) in double, which is tighter at some thresholds). Recheck: one
			// correlated lookup of the key per candidate, by (tenant_id, key_id), then <% as an ordinary
			// filter over rows the policy admitted. A plain join could become a hash join over a Seq Scan
			// of the key table; the LATERAL loop cannot.
			qt := b.bind("text", q.Fuzzy)
			thr := b.bind("float8", store.TrigramThresholdValue(float64(q.Threshold)))
			cands := "SELECT p.key_id FROM public." + src.trigrams + " p WHERE p.tenant_id = " + tenantExpr +
				" AND p.trgm = ANY (public.show_trgm(" + qt + ")) GROUP BY p.key_id" +
				" HAVING count(*)::real / NULLIF(cardinality(public.show_trgm(" + qt + ")), 0)::real >= " + thr
			fuzzy = append(fuzzy, "(SELECT r.connection_id, r.object_guid, r.key_kind, r.key FROM ("+cands+") c CROSS JOIN LATERAL (SELECT "+keyCols+
				" FROM public."+src.keys+" k WHERE k.tenant_id = "+tenantExpr+" AND k.key_id = c.key_id AND k.key_kind IN ("+list+
				") AND "+qt+" <% k.key LIMIT 1) r LIMIT "+w1()+")")
		}
	}
	if q.Fuzzy == "" {
		fuzzy = nil
	}

	var sb strings.Builder
	sb.WriteString("WITH m_exact AS MATERIALIZED (" + limit(exact) + "), m_prefix AS MATERIALIZED (" + limit(prefix) + "), m_fuzzy AS MATERIALIZED (" + limit(fuzzy) + "),")
	wbind := b.bind("int", q.Ceiling)
	sb.WriteString(" ceil AS (SELECT CASE WHEN (SELECT count(*) FROM m_exact) > " + wbind + " THEN 1 WHEN (SELECT count(*) FROM m_prefix) > " + wbind +
		" THEN 2 WHEN (SELECT count(*) FROM m_fuzzy) > " + wbind + " THEN 3 ELSE 0 END AS c),")
	sb.WriteString(" cand AS (SELECT 1 AS cls, * FROM m_exact WHERE (SELECT c FROM ceil) IN (0) OR 1 < (SELECT c FROM ceil)" +
		" UNION ALL SELECT 2, * FROM m_prefix WHERE (SELECT c FROM ceil) = 0 OR 2 < (SELECT c FROM ceil)" +
		" UNION ALL SELECT 3, * FROM m_fuzzy WHERE (SELECT c FROM ceil) = 0),")

	// The scope, per permission, over the kinds read under it.
	var scopeParts []string
	for _, p := range perms {
		pp := plans[p]
		b.plan = pp.plan
		var ks []string
		for _, k := range pp.kinds {
			ks = append(ks, strconv.Itoa(int(k)))
		}
		scopeParts = append(scopeParts, "(c.key_kind IN ("+strings.Join(ks, ", ")+") AND "+b.scopeSQL(src.objects, "t")+")")
	}
	scopeWhere := "FALSE"
	if len(scopeParts) > 0 {
		scopeWhere = strings.Join(scopeParts, " OR ")
	}
	types := q.Types
	if len(types) == 0 {
		types = AllSearchTypes
	}
	var kinds []string
	for _, t := range types {
		ks := t.kinds()
		if ks == nil {
			return Query{}, ErrInvalidQuery
		}
		kinds = append(kinds, ks...)
	}
	qtext := ""
	if q.Fuzzy != "" {
		qtext = b.bind("text", q.Fuzzy)
	}
	sim := "0"
	if qtext != "" {
		sim = "word_similarity(" + qtext + ", c.key)"
	}
	var lo string
	if len(wholeLo) > 0 {
		lo = b.bindList("text[]", wholeLo)
	} else {
		lo = "ARRAY[]::text[]"
	}
	t := func(col string) string { return "t." + col }
	live := "(" + t(src.state) + " IN ('live', 'active'))"
	grp := "CASE WHEN " + t(src.kind) + " IN ('user', 'inetorgperson') THEN 1 WHEN " + t(src.kind) + " = 'group' THEN 2 WHEN " + t(src.kind) + " IN ('computer', 'gmsa') THEN 3 ELSE 4 END"
	sb.WriteString(" hits AS (SELECT DISTINCT ON (t." + src.objects.conn + ", t." + src.objects.obj + ") t." + src.objects.conn + " AS connection_id, t." + src.objects.obj + " AS object_guid, " +
		t(src.kind) + " AS kind, " + t(src.state) + " AS state, " + t(src.enabled) + " AS enabled, COALESCE(" + t(src.display) + ", '') AS display_name, " +
		grp + " AS grp, c.cls AS cls, CASE WHEN " + live + " THEN 0 ELSE 1 END AS dead, CASE WHEN " + t(src.enabled) + " IS FALSE THEN 1 ELSE 0 END AS dis, " +
		"CASE WHEN c.cls = 2 AND c.key = ANY(" + lo + ") THEN 0 ELSE 1 END AS whole, CASE WHEN c.cls = 2 THEN char_length(c.key) ELSE 0 END AS klen, " +
		"CASE WHEN c.cls = 3 THEN 1000 - round((" + sim + ")::numeric * 1000)::int ELSE 0 END AS simr, " +
		"(lower(COALESCE(" + t(src.display) + ", '')) COLLATE \"C\") AS nm, (" + sim + ")::real AS sim " +
		"FROM cand c JOIN public." + src.objects.table + " t ON t." + "tenant_id" + " = " + tenantExpr + " AND t." + src.objects.conn + " = c.connection_id AND t." + src.objects.obj + " = c.object_guid " +
		"WHERE " + t(src.kind) + " = ANY(" + b.bindList("text[]", kinds) + ") AND (" + scopeWhere + ") " +
		"ORDER BY t." + src.objects.conn + ", t." + src.objects.obj + ", c.cls, CASE WHEN c.cls = 3 THEN -(" + sim + ") ELSE 0 END, CASE WHEN c.cls = 2 AND c.key = ANY(" + lo + ") THEN 0 ELSE 1 END, char_length(c.key)),")
	rank := "cls, dead, dis, whole, klen, simr, nm, connection_id, object_guid"
	sb.WriteString(" visible AS (SELECT h.*, count(*) OVER (PARTITION BY grp) AS grp_n FROM hits h),")
	after := ""
	if a := q.After; a != nil {
		after = " WHERE (cls, dead, dis, whole, klen, simr, nm, connection_id, object_guid) > (" +
			b.bind("smallint", int16(a.Class)) + ", " + b.bind("int", a.Dead) + ", " + b.bind("int", a.Disabled) + ", " + b.bind("int", a.Whole) + ", " +
			b.bind("int", a.KeyLen) + ", " + b.bind("int", a.SimRank) + ", " + b.bind("text", a.Name) + " COLLATE \"C\", " +
			b.bind("uuid", a.Connection) + ", " + b.bind("uuid", a.Object) + ")"
	}
	sb.WriteString(" paged AS (SELECT v.*, row_number() OVER (PARTITION BY grp ORDER BY " + rank + ") AS rn FROM visible v" + after + ")")
	sb.WriteString(" SELECT cl.c, p.connection_id::text, p.object_guid::text, p.kind, p.state, p.enabled, p.display_name, p.grp, p.cls, p.dead, p.dis, p.whole, p.klen, p.simr, p.nm, p.sim, p.grp_n " +
		"FROM ceil cl LEFT JOIN paged p ON p.rn <= " + b.bind("int", q.GroupLimit+1) +
		" ORDER BY p.grp, p.cls, p.dead, p.dis, p.whole, p.klen, p.simr, p.nm, p.connection_id, p.object_guid")
	return Query{sql: CompiledSQL(sb.String()), args: b.args, reasons: b.reasons, search: &searchMeta{limit: q.GroupLimit, fuzzy: q.Fuzzy != "", threshold: float64(q.Threshold)}}, nil
}

type searchMeta struct {
	limit     int
	fuzzy     bool
	threshold float64
}

// SearchHit is one admitted hit.
type SearchHit struct {
	Connection, Object string
	Kind               string
	State              string
	Enabled            *bool
	DisplayName        string
	Group              SearchType
	Class              SearchClass
	Similarity         float32
	Rank               SearchAfter
}

// SearchResult is the answer. Counts and More are nil when Refine is set (rule 12).
type SearchResult struct {
	Hits   []SearchHit
	Refine bool
	// Count is the number of admitted hits of each group and More says a group has more than the limit.
	Count map[SearchType]int
	More  map[SearchType]bool
	// ScopeReasons says why the scopes render narrower than the assignments suggest.
	ScopeReasons []string
}

// ExecSearch runs a compiled search and reads its rows. The statement is read-only and runs in tx, whose
// store-level statement timeout bounds it.
func ExecSearch(ctx context.Context, tx store.Tx, q Query) (SearchResult, error) {
	var res SearchResult
	if q.search == nil {
		return res, ErrInvalidQuery
	}
	if q.search.fuzzy {
		restore, err := store.SetTrigramThreshold(ctx, tx, q.search.threshold)
		if err != nil {
			return res, wrapErr(ctx, err)
		}
		defer restore()
	}
	rs, err := tx.Query(ctx, string(q.sql), append([]any{pgx.QueryExecModeExec}, q.args...)...)
	if err != nil {
		return res, wrapErr(ctx, err)
	}
	defer rs.Close()
	res.ScopeReasons = q.ScopeReasons()
	counts := map[SearchType]int{}
	seen := map[SearchType]int{}
	more := map[SearchType]bool{}
	for rs.Next() {
		var ceil int16
		var conn, obj, kind, state, name, nm *string
		var enabled *bool
		var grp, cls *int16
		var dead, dis, whole, klen, simr *int32
		var sim *float32
		var n *int64
		if err := rs.Scan(&ceil, &conn, &obj, &kind, &state, &enabled, &name, &grp, &cls, &dead, &dis, &whole, &klen, &simr, &nm, &sim, &n); err != nil {
			return res, wrapErr(ctx, err)
		}
		res.Refine = ceil > 0
		if obj == nil {
			continue
		}
		g := SearchType(*grp)
		counts[g] = int(*n)
		if seen[g]++; seen[g] > q.search.limit {
			more[g] = true
			continue
		}
		res.Hits = append(res.Hits, SearchHit{Connection: *conn, Object: *obj, Kind: *kind, State: *state, Enabled: enabled, DisplayName: *name,
			Group: g, Class: SearchClass(*cls), Similarity: *sim,
			Rank: SearchAfter{Class: SearchClass(*cls), Dead: int(*dead), Disabled: int(*dis), Whole: int(*whole), KeyLen: int(*klen), SimRank: int(*simr),
				Name: *nm, Connection: *conn, Object: *obj}})
	}
	if err := rs.Err(); err != nil {
		return res, wrapErr(ctx, err)
	}
	if !res.Refine {
		res.Count, res.More = counts, more
	}
	return res, nil
}

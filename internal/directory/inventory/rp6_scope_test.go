package inventory_test

import (
	"context"
	"fmt"
	"math/rand/v2"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/authz/authztest"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/reportsql"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

// RP6 (reports contract §4.6): the scope the report compiler renders into SQL and the read oracle
// authz.Evaluator.AuthorizeRead must admit the same rows. The trees are built through the
// inventory writer, including OU moves, so the compared rows carry the ancestry the writer
// maintains, not one the test typed in. The test lives here because platform packages may not
// import internal/directory (fitness-modules rule 2.1).

const (
	rp6Perm  authz.Permission = "reports.run"
	rp6Seeds                  = 80 // random worlds per PostgreSQL version
	rp6Scope                  = 6  // random scopes per world
)

type rpNode struct {
	guid   string
	conn   int // 0 or 1
	ou     bool
	parent int // index in the world, -1 for the NC head
}

type rpWorld struct {
	nodes  []rpNode
	ids    [2]authz.ObjectID // connection IDs
	stored map[string]row    // as read back from the table, by GUID
}

func rpGUID(seed, conn, idx int) string {
	return fmt.Sprintf("%08x-0000-4000-8000-%04x%08x", seed+1, conn, idx)
}

func rpID(s string) authz.ObjectID {
	id, err := authz.ParseObjectID(s)
	if err != nil {
		panic(err)
	}
	return id
}

// chain is the model's parent chain of node i, nearest parent first.
func (w *rpWorld) chain(i int) []string {
	var out []string
	for p := w.nodes[i].parent; p >= 0; p = w.nodes[p].parent {
		out = append(out, w.nodes[p].guid)
	}
	return out
}

func (w *rpWorld) inSubtree(i, root int) bool {
	for n := i; n >= 0; n = w.nodes[n].parent {
		if n == root {
			return true
		}
	}
	return false
}

func (w *rpWorld) head(conn int) int {
	for i, n := range w.nodes {
		if n.conn == conn && n.parent < 0 {
			return i
		}
	}
	panic("no head")
}

func (w *rpWorld) obs(i int) inventory.Observation {
	n := w.nodes[i]
	o := inventory.Observation{Object: inventory.GUID(n.guid), NC: inventory.GUID(w.nodes[w.head(n.conn)].guid), State: inventory.ObjLive}
	switch {
	case n.parent < 0:
		o.Kind, o.Class = inventory.KindOther, "domainDNS"
	case n.ou:
		o.Kind, o.Class = inventory.KindOU, "organizationalUnit"
	default:
		o.Kind, o.Class = inventory.KindUser, "user"
	}
	if n.parent >= 0 {
		o.Parent = inventory.GUID(w.nodes[n.parent].guid)
		for _, c := range w.chain(i) {
			o.Ancestry = append(o.Ancestry, inventory.GUID(c))
		}
	}
	return o
}

func (w *rpWorld) connObs(conn int) []inventory.Observation {
	var out []inventory.Observation
	for i, n := range w.nodes {
		if n.conn == conn {
			out = append(out, w.obs(i)) // parents precede children
		}
	}
	return out
}

// rpBuild makes a random forest per connection.
func rpBuild(r *rand.Rand, seed int) *rpWorld {
	w := &rpWorld{}
	for conn := 0; conn < 2; conn++ {
		h := len(w.nodes)
		w.nodes = append(w.nodes, rpNode{guid: rpGUID(seed, conn, 0), conn: conn, ou: true, parent: -1})
		ous := []int{h}
		for k := 1 + r.IntN(7); k > 0; k-- {
			p := ous[r.IntN(len(ous))]
			ous = append(ous, len(w.nodes))
			w.nodes = append(w.nodes, rpNode{guid: rpGUID(seed, conn, len(w.nodes)), conn: conn, ou: true, parent: p})
		}
		for k := 3 + r.IntN(12); k > 0; k-- {
			w.nodes = append(w.nodes, rpNode{guid: rpGUID(seed, conn, len(w.nodes)), conn: conn, parent: ous[r.IntN(len(ous))]})
		}
	}
	return w
}

// rpMove picks an OU and a new parent outside its own subtree; ok is false when there is none.
func (w *rpWorld) rpMove(r *rand.Rand) (x int, ok bool) {
	var ous []int
	for i, n := range w.nodes {
		if n.ou && n.parent >= 0 {
			ous = append(ous, i)
		}
	}
	if len(ous) == 0 {
		return 0, false
	}
	x = ous[r.IntN(len(ous))]
	var parents []int
	for i, n := range w.nodes {
		if n.ou && n.conn == w.nodes[x].conn && i != w.nodes[x].parent && !w.inSubtree(i, x) {
			parents = append(parents, i)
		}
	}
	if len(parents) == 0 {
		return 0, false
	}
	w.nodes[x].parent = parents[r.IntN(len(parents))]
	return x, true
}

// rpTerm is one scope term before it becomes an authz.ScopeTerm and an oracle root. At most one of
// the flaw flags is set.
type rpTerm struct {
	kind    authz.TermKind
	node    int
	wrongC  bool // names the other connection: matches nothing
	zeroC   bool // zero connection: invalid
	zeroR   bool // zero root: invalid
	unknown bool // a kind the compiler does not know
}

func (t rpTerm) invalid() bool { return t.zeroC || t.zeroR }

type rpLayer struct{ inc, exc []rpTerm }

func (w *rpWorld) scopeTerm(t rpTerm) authz.ScopeTerm {
	conn := w.nodes[t.node].conn
	if t.wrongC {
		conn = 1 - conn
	}
	st := authz.ScopeTerm{Kind: t.kind, Connection: w.ids[conn], Root: rpID(w.nodes[t.node].guid)}
	switch {
	case t.zeroC:
		st.Connection = authz.ObjectID{}
	case t.zeroR:
		st.Root = authz.ObjectID{}
	case t.unknown:
		st.Kind = 99
	}
	return st
}

func (w *rpWorld) terms(ts []rpTerm) []authz.ScopeTerm {
	var out []authz.ScopeTerm
	for _, t := range ts {
		out = append(out, w.scopeTerm(t))
	}
	return out
}

func (w *rpWorld) genTerm(r *rand.Rand, include bool) rpTerm {
	n := r.IntN(len(w.nodes))
	t := rpTerm{kind: authz.TermSubtree, node: n}
	switch k := r.IntN(10); {
	case k < 2:
		t.kind, t.node = authz.TermNamingContext, w.head(w.nodes[n].conn)
	case k < 4 && include:
		t.kind = authz.TermOneLevel
	}
	if r.IntN(100) < 7 { // a flawed term, rarely
		switch r.IntN(4) {
		case 0:
			t.wrongC = true
		case 1:
			t.zeroC = true
		case 2:
			t.zeroR = true
		default:
			t.unknown = true
		}
	}
	return t
}

func (w *rpWorld) genLayer(r *rand.Rand, minInc int) rpLayer {
	var l rpLayer
	for k := minInc + r.IntN(3); k > 0; k-- {
		l.inc = append(l.inc, w.genTerm(r, true))
	}
	for k := r.IntN(3); k > 0; k-- {
		l.exc = append(l.exc, w.genTerm(r, false))
	}
	return l
}

func root(w *rpWorld, t rpTerm) authz.ScopeRoot {
	return authz.ScopeRoot{ID: rpID(w.nodes[t.node].guid), OneLevel: t.kind == authz.TermOneLevel, Complete: true}
}

// grantOracle models what the compiler does with a grant: an unknown or invalid exclude, or an invalid
// include, drops the whole grant; an unknown include drops that term; a term naming the other
// connection can match nothing in this world, where every GUID lives in one connection.
func (w *rpWorld) grantOracle(l rpLayer) (authz.Scope, bool) {
	var s authz.Scope
	for _, t := range l.exc {
		if t.invalid() || t.unknown {
			return s, false
		}
		if !t.wrongC {
			s.Exclude = append(s.Exclude, root(w, t))
		}
	}
	for _, t := range l.inc {
		if t.invalid() {
			return s, false
		}
		if !t.unknown && !t.wrongC {
			s.Include = append(s.Include, root(w, t))
		}
	}
	return s, len(s.Include) > 0
}

// tokenOracle: any flawed term other than a wrong connection makes the whole token layer match nothing.
func (w *rpWorld) tokenOracle(l rpLayer) authz.Scope {
	var s authz.Scope
	for _, t := range slices.Concat(l.inc, l.exc) {
		if t.invalid() || t.unknown {
			return authz.Scope{Include: []authz.ScopeRoot{{}}}
		}
	}
	for _, t := range l.inc {
		if !t.wrongC {
			s.Include = append(s.Include, root(w, t))
		}
	}
	for _, t := range l.exc {
		if !t.wrongC {
			s.Exclude = append(s.Exclude, root(w, t))
		}
	}
	return s
}

type rpScope struct {
	grants []rpLayer
	token  *rpLayer
}

func (s rpScope) String() string {
	f := func(ts []rpTerm) string {
		var p []string
		for _, t := range ts {
			p = append(p, fmt.Sprintf("%v@%d%+v", t.kind, t.node, struct{ W, C, R, U bool }{t.wrongC, t.zeroC, t.zeroR, t.unknown}))
		}
		return strings.Join(p, ",")
	}
	var b strings.Builder
	for _, g := range s.grants {
		fmt.Fprintf(&b, "grant{+[%s] -[%s]} ", f(g.inc), f(g.exc))
	}
	if s.token != nil {
		fmt.Fprintf(&b, "token{+[%s] -[%s]}", f(s.token.inc), f(s.token.exc))
	}
	return b.String()
}

func (w *rpWorld) genScope(r *rand.Rand) rpScope {
	var s rpScope
	for k := 1 + r.IntN(3); k > 0; k-- {
		s.grants = append(s.grants, w.genLayer(r, 1))
	}
	if r.IntN(40) == 0 {
		s.grants = nil // the empty scope
	}
	switch k := r.IntN(10); {
	case k < 1:
		s.token = &rpLayer{} // a token that narrows to nothing
	case k < 5:
		l := w.genLayer(r, 1)
		s.token = &l
	}
	return s
}

func (w *rpWorld) readScope(s rpScope) authz.ReadScope {
	var gs []authz.ScopeGrant
	for _, g := range s.grants {
		gs = append(gs, authz.ScopeGrant{Include: w.terms(g.inc), Exclude: w.terms(g.exc)})
	}
	if s.token == nil {
		return authztest.ReadScope(gs...)
	}
	return authztest.ReadScopeWithToken(authz.TokenLayer{Include: w.terms(s.token.inc), Exclude: w.terms(s.token.exc)}, gs...)
}

// admits is the oracle: AuthorizeRead over the facts the table stores for node i.
func (w *rpWorld) admits(s rpScope, now time.Time, i int) bool {
	p := &authz.Principal{ID: "rp6"}
	for _, g := range s.grants {
		if sc, ok := w.grantOracle(g); ok {
			p.Assignments = append(p.Assignments, authz.Assignment{Role: authz.Role{Permissions: []authz.Permission{rp6Perm}}, Scope: sc})
		}
	}
	var tok *authz.Token
	if s.token != nil {
		sc := w.tokenOracle(*s.token)
		tok = &authz.Token{Permissions: []authz.Permission{rp6Perm}, ExpiresAt: now.Add(time.Hour), Scope: &sc}
	}
	st := w.stored[w.nodes[i].guid]
	t := authz.Target{ID: rpID(w.nodes[i].guid), Complete: st.Complete}
	for _, a := range st.Ancestry {
		t.Ancestors = append(t.Ancestors, rpID(a))
	}
	return authz.Evaluator{Now: func() time.Time { return now }}.AuthorizeRead(p, tok, rp6Perm, t).Allowed
}

func rpDataset(id string, edge bool) report.Dataset {
	anchor := func(a report.AnchorID) report.Anchor {
		return report.Anchor{ID: a, Table: "directory_objects", Mode: report.RowAnchor, Project: []report.Ident{"object_guid"},
			Connection: "connection_id", NC: "nc_guid", Object: "object_guid", Parent: "parent_guid", Ancestry: "ancestry", Complete: "ancestry_complete"}
	}
	ds := report.Dataset{
		ID:        report.DatasetID(id),
		Base:      report.Relation{Table: "directory_objects"},
		RowKey:    report.SQL("{t}.object_guid"),
		Anchors:   []report.Anchor{anchor("t")},
		Columns:   []report.Column{{ID: "object_guid", Label: "GUID", Type: report.TypeGUID, Source: report.Attr{Col: "object_guid"}, Sortable: true, Default: true}},
		Freshness: report.FreshNCWatermark,
		Tables:    []string{"directory_objects"},
	}
	if edge { // a row exists only when it and its parent are both in scope
		ds.Anchors = append(ds.Anchors, anchor("p"))
		ds.Base.Joins = []report.RowJoin{{Anchor: "p",
			On: report.SQL("{rel.p}.object_guid = {t}.parent_guid AND {rel.p}.connection_id = {t}.connection_id")}}
	}
	return ds
}

func rpDef(ds report.Dataset) report.Definition {
	return report.Definition{ID: "rp6-01", Version: 1, Category: report.CategoryUsers, Title: "RP6", Dataset: ds.ID,
		Columns: []report.ColumnID{"object_guid"}, Sort: []report.SortKey{{Column: "object_guid", Dir: report.Asc}},
		Presets: []report.Preset{{ID: "all"}}}
}

type rpRun struct {
	ds  reportsql.Dataset
	q   report.Query
	src report.Dataset
}

// run returns the keys the compiled query returns and its count(*), in one transaction.
func (e *env) rpRun(t *testing.T, r rpRun, scope authz.ReadScope, now time.Time) (keys []string, count int64) {
	t.Helper()
	in := reportsql.Inputs{Now: now}
	rowsQ, err := reportsql.Compile(r.q, r.ds, scope, in)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	cntQ, err := reportsql.CompileCount(r.q, r.ds, scope, in)
	if err != nil {
		t.Fatalf("CompileCount: %v", err)
	}
	err = e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error {
		n, err := reportsql.Exec(ctx, tx, rowsQ, 100, func(_ context.Context, rows []report.Row) error {
			for _, row := range rows {
				keys = append(keys, strings.ToLower(row.Key))
			}
			return nil
		})
		if err != nil {
			return err
		}
		if int(n) != len(keys) {
			return fmt.Errorf("Exec reported %d rows, delivered %d", n, len(keys))
		}
		count, err = reportsql.Count(ctx, tx, cntQ)
		return err
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	sort.Strings(keys)
	return keys, count
}

func Test_compiled_scope_matches_read_oracle(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		conns := [2]inventory.ConnectionID{
			e.conn(t, e.a, connection.KindADForest, connection.TransportLDAPS),
			e.conn(t, e.a, connection.KindADForest, connection.TransportLDAPS),
		}
		var reg *reportsql.Registry
		objSrc, edgeSrc := rpDataset("rp6.objects", false), rpDataset("rp6.edges", true)
		err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error {
			sc, err := reportsql.CatalogSchema(ctx, tx)
			if err != nil {
				return err
			}
			reg, err = reportsql.NewRegistry(reportsql.Options{Schema: sc, SecretKey: func(string) bool { return false }}, objSrc, edgeSrc)
			return err
		})
		if err != nil {
			t.Fatalf("registry: %v", err)
		}
		runs := map[bool]rpRun{}
		for edge, src := range map[bool]report.Dataset{false: objSrc, true: edgeSrc} {
			ds, _ := reg.Dataset(src.ID)
			q, err := report.Resolve(rpDef(src), "all", report.RunParams{}, src)
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			runs[edge] = rpRun{ds: ds, q: q, src: src}
		}

		clock := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
		now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
		var admitted, moves, flipped int
		start := time.Now()
		for seed := 0; seed < rp6Seeds; seed++ {
			r := rand.New(rand.NewPCG(uint64(seed), 0x6a09e667))
			w := rpBuild(r, seed)
			for c := range conns {
				w.ids[c] = rpID(string(conns[c]))
				clock = clock.Add(time.Minute)
				if _, err := e.populate(t, conns[c], clock, w.connObs(c)...); err != nil {
					t.Fatalf("seed %d: populate: %v", seed, err)
				}
			}
			for k := r.IntN(6); k > 0; k-- {
				x, ok := w.rpMove(r)
				if !ok {
					continue
				}
				moves++
				clock = clock.Add(time.Minute)
				if _, err := e.populate(t, conns[w.nodes[x].conn], clock, w.obs(x)); err != nil {
					t.Fatalf("seed %d: move: %v", seed, err)
				}
			}

			// What the table stores must be the model's chain: the oracle is fed stored facts, so
			// this keeps RP6 from agreeing with the compiler about a wrong tree.
			w.stored = map[string]row{}
			for c := range conns {
				for g, rw := range e.rows(t, e.a, conns[c]) {
					w.stored[g] = rw
				}
			}
			for i, n := range w.nodes {
				got, ok := w.stored[n.guid]
				if !ok || !got.Complete || !slices.Equal(got.Ancestry, w.chain(i)) {
					t.Fatalf("seed %d: stored row of node %d = %+v (found %v), model chain %v", seed, i, got, ok, w.chain(i))
				}
			}
			if r.IntN(100) < 15 { // some rows lose their ancestry guarantee: they must vanish from every scope
				for k := 1 + r.IntN(3); k > 0; k-- {
					i := r.IntN(len(w.nodes))
					// as the tenant: the table forces row-level security, so an owner statement would touch no row
					err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error {
						tag, err := tx.Exec(ctx, `UPDATE public.directory_objects SET ancestry_complete = false WHERE object_guid = $1::uuid`, w.nodes[i].guid)
						if err == nil && tag.RowsAffected() != 1 {
							err = fmt.Errorf("%d rows updated", tag.RowsAffected())
						}
						return err
					})
					if err != nil {
						t.Fatalf("seed %d: marking incomplete: %v", seed, err)
					}
					rw := w.stored[w.nodes[i].guid]
					rw.Complete = false
					w.stored[w.nodes[i].guid] = rw
					flipped++
				}
			}

			for k := 0; k < rp6Scope; k++ {
				sc := w.genScope(r)
				scope := w.readScope(sc)
				wantRows := map[bool][]string{}
				for i, n := range w.nodes {
					if !w.admits(sc, now, i) {
						continue
					}
					wantRows[false] = append(wantRows[false], n.guid)
				}
				// the edge dataset: a row exists only when the object and its parent are both admitted
				for i, n := range w.nodes {
					if n.parent >= 0 && w.admits(sc, now, i) && w.admits(sc, now, n.parent) {
						wantRows[true] = append(wantRows[true], n.guid)
					}
				}
				admitted += len(wantRows[false])
				for edge, run := range runs {
					want := wantRows[edge]
					sort.Strings(want)
					got, count := e.rpRun(t, run, scope, now)
					if !slices.Equal(got, want) || count != int64(len(want)) {
						t.Fatalf("seed %d scope %d edge=%v:\n compiled rows %d, count %d\n oracle rows   %d\n compiled-only %v\n oracle-only   %v\n scope: %s",
							seed, k, edge, len(got), count, len(want), diff(got, want), diff(want, got), sc)
					}
				}
			}
		}
		t.Logf("%d worlds, %d moves, %d rows marked incomplete, %d scopes, %d admitted rows compared, %s",
			rp6Seeds, moves, flipped, rp6Seeds*rp6Scope, admitted, time.Since(start).Round(time.Millisecond))
		if admitted == 0 || moves == 0 {
			t.Fatalf("the generator is degenerate: admitted=%d moves=%d", admitted, moves)
		}
	})
}

// diff returns the members of a that are not in b (both sorted).
func diff(a, b []string) []string {
	var out []string
	for _, x := range a {
		if _, found := slices.BinarySearch(b, x); !found {
			out = append(out, x)
		}
	}
	return out
}

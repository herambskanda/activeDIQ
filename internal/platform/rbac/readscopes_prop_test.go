package rbac

import (
	"fmt"
	"math/rand"
	"slices"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
)

// A node of a random inventory forest. parent is -1 for a naming-context head.
type pNode struct {
	id     string
	conn   string
	parent int
	ou     bool
	tier0  bool
}

type pForest struct{ nodes []pNode }

func guid(n int) string { return fmt.Sprintf("%08x-0000-4000-8000-%012x", 0xf0000000+n, n) }

// newForest builds two connections, each with a naming-context head, then random OUs and leaves, then
// random OU moves (never into the OU's own subtree). The tree after the moves is what the inventory
// writer stores once it rewrites descendants' ancestry (modules/reports.md §4.5); this test reads the
// tree through parent pointers, so it checks the producer's terms, not the writer. RP6 (B2) runs the
// same comparison through the writer and the compiled SQL.
func newForest(r *rand.Rand) *pForest {
	f := &pForest{}
	add := func(conn string, parent int, ou bool) int {
		f.nodes = append(f.nodes, pNode{id: guid(len(f.nodes) + 1), conn: conn, parent: parent, ou: ou, tier0: r.Intn(6) == 0})
		return len(f.nodes) - 1
	}
	conns := []string{conn, conn2}
	for _, c := range conns {
		add(c, -1, true)
	}
	for i := 0; i < 8+r.Intn(14); i++ {
		c := r.Intn(2)
		var ous []int
		for j, n := range f.nodes {
			if n.conn == conns[c] && n.ou {
				ous = append(ous, j)
			}
		}
		add(conns[c], ous[r.Intn(len(ous))], r.Intn(3) != 0)
	}
	for i := 0; i < r.Intn(5); i++ {
		var movable []int
		for j, n := range f.nodes {
			if n.parent >= 0 && n.ou {
				movable = append(movable, j)
			}
		}
		if len(movable) == 0 {
			break
		}
		m := movable[r.Intn(len(movable))]
		var dests []int
		for j, n := range f.nodes {
			if n.conn == f.nodes[m].conn && n.ou && j != m && !slices.Contains(f.chain(j), m) {
				dests = append(dests, j)
			}
		}
		f.nodes[m].parent = dests[r.Intn(len(dests))]
	}
	return f
}

// chain is the node and its ancestors, nearest first.
func (f *pForest) chain(i int) []int {
	var out []int
	for ; i >= 0; i = f.nodes[i].parent {
		out = append(out, i)
	}
	return out
}

func (f *pForest) head(i int) int { c := f.chain(i); return c[len(c)-1] }

func (f *pForest) ous(c string) []int {
	var out []int
	for i, n := range f.nodes {
		if n.ou && n.conn == c {
			out = append(out, i)
		}
	}
	return out
}

// matches evaluates one term against node i by the semantics the SQL compiler renders (reports §4.3):
// naming_context: the node's NC head is the root; subtree: the node is the root or below it;
// one level: the node's parent is the root.
func (f *pForest) matches(t authz.ScopeTerm, i int) bool {
	n := f.nodes[i]
	if t.Connection != mustID2(n.conn) || t.Root.IsZero() {
		return false
	}
	switch t.Kind {
	case authz.TermNamingContext:
		return mustID2(f.nodes[f.head(i)].id) == t.Root
	case authz.TermSubtree:
		for _, j := range f.chain(i) {
			if mustID2(f.nodes[j].id) == t.Root {
				return true
			}
		}
		return false
	case authz.TermOneLevel:
		return n.parent >= 0 && mustID2(f.nodes[n.parent].id) == t.Root
	}
	return false
}

func mustID2(s string) authz.ObjectID {
	id, err := authz.ParseObjectID(s)
	if err != nil {
		panic(err)
	}
	return id
}

func (f *pForest) anyMatch(ts []authz.ScopeTerm, i int) bool {
	return slices.ContainsFunc(ts, func(t authz.ScopeTerm) bool { return f.matches(t, i) })
}

// admits is the ReadScope read as a predicate over node i: the union of grants (include minus
// exclude), AND-ed with the token layer.
func (f *pForest) admits(s authz.ReadScope, i int) bool {
	if s.Empty() {
		return false
	}
	ok := false
	for _, g := range s.Terms() {
		if f.anyMatch(g.Include, i) && !f.anyMatch(g.Exclude, i) {
			ok = true
			break
		}
	}
	if !ok {
		return false
	}
	if l, has := s.Token(); has {
		return f.anyMatch(l.Include, i) && !f.anyMatch(l.Exclude, i)
	}
	return true
}

// genAssignments draws assignments over the forest. supportedOnly keeps every root of a kind that has
// an evaluator; otherwise entra_tenant roots (includes and excludes), tier0_scope roots and Via
// assignments are mixed in.
func genAssignments(r *rand.Rand, f *pForest, supportedOnly bool) []Assignment {
	var out []Assignment
	for k := 0; k < 1+r.Intn(4); k++ {
		perms := reportsP
		if r.Intn(5) == 0 {
			perms = []authz.Permission{"x.y"}
		}
		a := Assignment{ID: fmt.Sprintf("a%d", k), Subject: SubjectAccount, Permissions: perms}
		for j := 0; j < 1+r.Intn(3); j++ {
			c := []string{conn, conn2}[r.Intn(2)]
			ous := f.ous(c)
			node := f.nodes[ous[r.Intn(len(ous))]]
			switch p := r.Intn(10); {
			case p < 2:
				a.Roots = append(a.Roots, Root{Kind: NamingContext, Connection: c, GUID: f.nodes[f.head(ous[0])].id})
			case p < 6:
				a.Roots = append(a.Roots, Root{Kind: OUSubtree, Connection: c, GUID: node.id})
			case p < 9 || supportedOnly:
				a.Roots = append(a.Roots, Root{Kind: OUOneLevel, Connection: c, GUID: node.id})
			default:
				a.Roots = append(a.Roots, Root{Kind: EntraTenant, Connection: c, GUID: c})
			}
		}
		for j := 0; j < r.Intn(3); j++ {
			c := []string{conn, conn2}[r.Intn(2)]
			ous := f.ous(c)
			kind := OUSubtree
			guidOf := f.nodes[ous[r.Intn(len(ous))]].id
			if r.Intn(8) == 0 {
				kind = NamingContext
				guidOf = f.nodes[f.head(ous[0])].id
			} else if !supportedOnly && r.Intn(8) == 0 {
				kind, guidOf = EntraTenant, c
			}
			a.Roots = append(a.Roots, Root{Kind: kind, Connection: c, GUID: guidOf, Exclude: true})
		}
		if !supportedOnly {
			// Shapes the schema refuses and the oracle fails closed on: the producer may not read wider.
			c := []string{conn, conn2}[r.Intn(2)]
			switch r.Intn(6) {
			case 0:
				ous := f.ous(c)
				a.Roots = append(a.Roots, Root{Kind: OUOneLevel, Connection: c, GUID: f.nodes[ous[r.Intn(len(ous))]].id, Exclude: true})
			case 1:
				a.Roots = append(a.Roots, Root{Kind: OUOneLevel, Connection: c, GUID: c})
			}
		}
		if !supportedOnly && r.Intn(6) == 0 {
			a.Via = &authz.Derivation{Correlation: &authz.Correlation{State: authz.CorrelationMatched, Takeover: authz.TakeoverAttested}}
		}
		out = append(out, a)
	}
	return out
}

func genTokenScope(r *rand.Rand, f *pForest) *authz.Scope {
	switch r.Intn(4) {
	case 0:
		return nil
	case 1:
		return &authz.Scope{}
	}
	var sc authz.Scope
	pick := func() int { c := []string{conn, conn2}[r.Intn(2)]; o := f.ous(c); return o[r.Intn(len(o))] }
	for j := 0; j < 1+r.Intn(2); j++ {
		sc.Include = append(sc.Include, authz.ScopeRoot{ID: mustID2(f.nodes[pick()].id), OneLevel: r.Intn(4) == 0, Complete: true})
	}
	for j := 0; j < r.Intn(3); j++ {
		sc.Exclude = append(sc.Exclude, authz.ScopeRoot{ID: mustID2(f.nodes[pick()].id), Complete: true})
	}
	return &sc
}

// oracle decides node i with the same view Authorize uses: objectView over the assignments, then
// authz.Evaluator.AuthorizeRead.
func oracle(t *testing.T, as []Assignment, tok *authz.Token, f *pForest, i int) bool {
	t.Helper()
	n := f.nodes[i]
	var anc []string
	for _, j := range f.chain(i)[1:] {
		anc = append(anc, f.nodes[j].id)
	}
	tgt, ev, err := objectView(as, authority.TargetRef{Connection: n.conn, GUID: n.id, Class: "user"},
		authority.Facts{Exists: true, Tier0: n.tier0, Ancestors: anc, AncestorsComplete: true})
	if err != nil {
		t.Fatal(err)
	}
	p := &authz.Principal{ID: acct, Assignments: ev}
	return (authz.Evaluator{Now: func() time.Time { return rsNow }}).AuthorizeRead(p, tok, runReports, tgt).Allowed
}

func forestConns(f *pForest) fakeConns {
	m := fakeConns{}
	for _, n := range f.nodes {
		m[mustID2(n.id)] = mustID2(n.conn)
	}
	return m
}

func propRun(t *testing.T, supportedOnly bool, seeds int) {
	for seed := 1; seed <= seeds; seed++ {
		r := rand.New(rand.NewSource(int64(seed)))
		f := newForest(r)
		as := genAssignments(r, f, supportedOnly)
		var tok *authz.Token
		opts := []rsOpt{withConns(forestConns(f))}
		if r.Intn(2) == 0 {
			tk := authz.Token{Permissions: reportsP, ExpiresAt: rsNow.Add(time.Hour), Scope: genTokenScope(r, f)}
			tok = &tk
			opts = append(opts, withToken(tk))
		}
		s, err := produce(t, as, opts...)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		for i := range f.nodes {
			got, want := f.admits(s, i), oracle(t, as, tok, f, i)
			if supportedOnly && got != want {
				t.Fatalf("seed %d node %d (%+v): scope=%v oracle=%v\nassignments=%+v\ntoken=%+v\nscope=%+v token=%v",
					seed, i, f.nodes[i], got, want, as, tok, s.Terms(), s.Reasons())
			}
			// With kinds the producer cannot render, it may admit less than the oracle, never more.
			if got && !want {
				t.Fatalf("seed %d node %d (%+v): scope admits what the oracle refuses\nassignments=%+v\ntoken=%+v\nscope=%+v",
					seed, i, f.nodes[i], as, tok, s.Terms())
			}
		}
	}
}

// Test_ReadScope_matches_read_oracle is the AC3 property test: over random forests (two connections,
// OUs and leaves, random OU moves, Tier-0 objects), random assignments with several includes and
// excludes, group-style several grants, ou_one_level included, and random tokens (none, empty, narrowing
// with subtree and one-level roots), every object is admitted by the ReadScope's terms exactly when
// authz.Evaluator.AuthorizeRead admits it.
func Test_ReadScope_matches_read_oracle(t *testing.T) {
	propRun(t, true, 1500)
}

// Roots of kinds with no evaluator, and Via assignments, make the producer narrower than the oracle
// (which reads entra_tenant as a connection-wide subtree). It must never be wider, and the oracle
// already ignores Via for reads.
func Test_ReadScope_with_unsupported_kinds_never_exceeds_read_oracle(t *testing.T) {
	propRun(t, false, 1500)
}

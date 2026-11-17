package inventory_test

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/authz/authztest"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/reportsql"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

// T-2088 (spec ad-explorer-read-api X3, EX6): reportsql.CompileTree draws the scope with the one renderer. The
// forest below is written straight into directory_objects (the writer is not what is under test); the oracle
// is the list a person would write down from the picture.
//
//	D  (container, naming context head)
//	└ P  ou                      hidden ancestor of the scope root
//	  └ R  ou                    scope root: subtree(R) minus subtree(X)
//	    ├ a1 ou ── b1 user
//	    ├ a2 ou
//	    ├ x  ou ── x1 user        excluded
//	    ├ u3 user, u4 user
//	    ├ gone user               state = deleted
//	    ├ cloud user              nc_guid NULL
//	    └ fix  user               ancestry_complete = false (mid-repair)

func tg(n int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) }

type tnode struct {
	id, parent     int
	anc            []int
	kind, rdn      string
	state          string
	nc, complete   bool
	connection     inventory.ConnectionID
	noParentColumn bool
}

func (e *env) insertTree(t *testing.T, ns ...tnode) {
	t.Helper()
	for _, n := range ns {
		anc := []string{}
		for _, a := range n.anc {
			anc = append(anc, tg(a))
		}
		var parent, nc any
		if n.parent != 0 {
			parent = tg(n.parent)
		}
		if n.nc {
			nc = tg(1)
		}
		state := n.state
		if state == "" {
			state = "live"
		}
		if err := e.exec(e.a, `INSERT INTO public.directory_objects (tenant_id, connection_id, object_guid, nc_guid, kind, object_class, parent_guid, ancestry, ancestry_complete, rdn, display_name, observed_at, state)
			VALUES (NULLIF(current_setting('app.tenant_id', true), '')::uuid, $1::uuid, $2::uuid, $3::uuid, $4, $4, $5::uuid, $6::uuid[], $7, $8, $8, now(), $9)`,
			string(n.connection), tg(n.id), nc, n.kind, parent, anc, n.complete, n.rdn, state); err != nil {
			t.Fatalf("insert %s: %v", n.rdn, err)
		}
	}
}

func (e *env) treeSource(t *testing.T) reportsql.TreeSource {
	t.Helper()
	src, err := reportsql.NewTreeSource(e.catalog(t), report.Anchor{ID: "t", Table: "directory_objects", Mode: report.RowAnchor,
		Project: []report.Ident{"object_guid"}, Connection: "connection_id", NC: "nc_guid", Object: "object_guid", Parent: "parent_guid",
		Ancestry: "ancestry", Complete: "ancestry_complete"}, "kind", "state", "rdn", "display_name")
	if err != nil {
		t.Fatal(err)
	}
	return src
}

func (e *env) tree(t *testing.T, q reportsql.TreeQuery) reportsql.TreeResult {
	t.Helper()
	cq, err := reportsql.CompileTree(e.treeSource(t), q)
	if err != nil {
		t.Fatal(err)
	}
	var res reportsql.TreeResult
	if err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) (err error) { res, err = reportsql.ExecTree(ctx, tx, cq); return }); err != nil {
		t.Fatal(err)
	}
	return res
}

func treeRDNs(rs []reportsql.TreeNodeRow) []string {
	out := []string{}
	for _, r := range rs {
		out = append(out, r.Rdn)
	}
	return out
}

const (
	nD = 1 + iota
	nP
	nR
	nA1
	nA2
	nX
	nU3
	nU4
	nGone
	nCloud
	nFix
	nB1
	nX1
)

func scopeSub(c inventory.ConnectionID, root int, exclude ...int) authz.ReadScope {
	g := authz.ScopeGrant{Include: []authz.ScopeTerm{{Kind: authz.TermSubtree, Connection: rpID(string(c)), Root: rpID(tg(root))}}}
	for _, x := range exclude {
		g.Exclude = append(g.Exclude, authz.ScopeTerm{Kind: authz.TermSubtree, Connection: rpID(string(c)), Root: rpID(tg(x))})
	}
	return authztest.ReadScope(g)
}

func (e *env) forest(t *testing.T) {
	c := e.adA
	e.insertTree(t,
		tnode{id: nD, kind: "container", rdn: "dc=d", nc: true, complete: true, connection: c},
		tnode{id: nP, parent: nD, anc: []int{nD}, kind: "ou", rdn: "ou=p", nc: true, complete: true, connection: c},
		tnode{id: nR, parent: nP, anc: []int{nP, nD}, kind: "ou", rdn: "ou=r", nc: true, complete: true, connection: c},
		tnode{id: nA1, parent: nR, anc: []int{nR, nP, nD}, kind: "ou", rdn: "ou=a1", nc: true, complete: true, connection: c},
		tnode{id: nA2, parent: nR, anc: []int{nR, nP, nD}, kind: "ou", rdn: "ou=A2", nc: true, complete: true, connection: c},
		tnode{id: nX, parent: nR, anc: []int{nR, nP, nD}, kind: "ou", rdn: "ou=x", nc: true, complete: true, connection: c},
		tnode{id: nU3, parent: nR, anc: []int{nR, nP, nD}, kind: "user", rdn: "cn=u3", nc: true, complete: true, connection: c},
		tnode{id: nU4, parent: nR, anc: []int{nR, nP, nD}, kind: "user", rdn: "cn=u4", nc: true, complete: true, connection: c},
		tnode{id: nGone, parent: nR, anc: []int{nR, nP, nD}, kind: "user", rdn: "cn=gone", state: "deleted", nc: true, complete: true, connection: c},
		tnode{id: nCloud, parent: nR, anc: []int{nR, nP, nD}, kind: "user", rdn: "cn=cloud", nc: false, complete: true, connection: c},
		tnode{id: nFix, parent: nR, anc: []int{nR, nP, nD}, kind: "user", rdn: "cn=fix", nc: true, complete: false, connection: c},
		tnode{id: nB1, parent: nA1, anc: []int{nA1, nR, nP, nD}, kind: "user", rdn: "cn=b1", nc: true, complete: true, connection: c},
		tnode{id: nX1, parent: nX, anc: []int{nX, nR, nP, nD}, kind: "user", rdn: "cn=x1", nc: true, complete: true, connection: c},
	)
}

func Test_CompileTree_over_the_one_scope_renderer(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		e.forest(t)
		c := string(e.adA)
		scope := scopeSub(e.adA, nR, nX)
		kids := func(parent int, containers bool, limit, examine int, after *reportsql.TreeAfter, sc authz.ReadScope) reportsql.TreeResult {
			return e.tree(t, reportsql.TreeQuery{Op: reportsql.TreeChildren, Connection: c, Object: tg(parent), ContainersOnly: containers, Limit: limit, Examine: examine, After: after, Scope: sc})
		}
		t.Run("children: containers first, then by lower(rdn); deleted, cloud, mid-repair and excluded are absent", func(t *testing.T) {
			r := kids(nR, false, 50, 100, nil, scope)
			if want := []string{"ou=a1", "ou=A2", "cn=u3", "cn=u4"}; !slices.Equal(treeRDNs(r.Rows), want) || r.More {
				t.Fatalf("got %v more=%v want %v", treeRDNs(r.Rows), r.More, want)
			}
			if !r.Rows[0].HasChildren || r.Rows[1].HasChildren || r.Rows[2].HasChildren {
				t.Fatalf("hasChildren: %+v", r.Rows)
			}
		})
		t.Run("view=containers", func(t *testing.T) {
			r := kids(nR, true, 50, 100, nil, scope)
			if want := []string{"ou=a1", "ou=A2"}; !slices.Equal(treeRDNs(r.Rows), want) {
				t.Fatalf("got %v", treeRDNs(r.Rows))
			}
		})
		t.Run("keyset pages union to the admitted children, no duplicate, none missing", func(t *testing.T) {
			var all []string
			var after *reportsql.TreeAfter
			for i := 0; i < 10; i++ {
				r := kids(nR, false, 3, 100, after, scope)
				all = append(all, treeRDNs(r.Rows)...)
				if !r.More {
					break
				}
				after = r.Resume
			}
			if want := []string{"ou=a1", "ou=A2", "cn=u3", "cn=u4"}; !slices.Equal(all, want) {
				t.Fatalf("got %v", all)
			}
		})
		t.Run("examination ceiling returns what it found with a cursor from the last examined row", func(t *testing.T) {
			// examine 3: a1, a2 and u3 are read (excluded x sorts after a2 among containers: a1, A2, x), x is hidden.
			r := kids(nR, false, 50, 3, nil, scope)
			if want := []string{"ou=a1", "ou=A2"}; !slices.Equal(treeRDNs(r.Rows), want) || !r.More || r.Resume == nil || r.Resume.Object != tg(nX) {
				t.Fatalf("got %v more=%v resume=%+v", treeRDNs(r.Rows), r.More, r.Resume)
			}
		})
		t.Run("a hidden parent has no children for the caller; the answer is empty, like a missing one", func(t *testing.T) {
			for _, p := range []int{nX, nP, nD, 999} {
				if r := kids(p, false, 50, 100, nil, scope); len(r.Rows) != 0 {
					t.Fatalf("parent %d: %v", p, treeRDNs(r.Rows))
				}
			}
		})
		t.Run("roots start at the scope root, never name the hidden ancestor", func(t *testing.T) {
			r := e.tree(t, reportsql.TreeQuery{Op: reportsql.TreeRoots, Scope: scope})
			if want := []string{"ou=r"}; !slices.Equal(treeRDNs(r.Rows), want) {
				t.Fatalf("got %v", treeRDNs(r.Rows))
			}
			if r.Rows[0].Parent != "" {
				t.Fatalf("a root named its hidden parent %s", r.Rows[0].Parent)
			}
			r = e.tree(t, reportsql.TreeQuery{Op: reportsql.TreeRoots, Scope: authztest.ReadScope(authz.ScopeGrant{Include: []authz.ScopeTerm{{Kind: authz.TermNamingContext, Connection: rpID(c), Root: rpID(tg(1))}}})})
			if want := []string{"dc=d"}; !slices.Equal(treeRDNs(r.Rows), want) {
				t.Fatalf("naming-context scope roots: %v", treeRDNs(r.Rows))
			}
		})
		t.Run("node: path is the contiguous admitted run, a hidden ancestor ends it", func(t *testing.T) {
			r := e.tree(t, reportsql.TreeQuery{Op: reportsql.TreeNode, Connection: c, Object: tg(nB1), Scope: scope})
			if !r.Found || r.Rows[0].Rdn != "cn=b1" || !slices.Equal(treeRDNs(r.Path), []string{"ou=r", "ou=a1"}) {
				t.Fatalf("%+v", r)
			}
			if r.Path[0].Parent != "" || r.Path[1].Parent != tg(nR) || r.Rows[0].Parent != tg(nA1) {
				t.Fatalf("a parent GUID outside the admitted run is named: %+v", r)
			}
			for _, hidden := range []int{nX, nX1, nP, nGone, nCloud, nFix, 999} {
				if r := e.tree(t, reportsql.TreeQuery{Op: reportsql.TreeNode, Connection: c, Object: tg(hidden), Scope: scope}); r.Found || len(r.Rows) != 0 || len(r.Path) != 0 {
					t.Fatalf("node %d answered: %+v", hidden, r)
				}
			}
		})
		t.Run("an empty scope reads nothing and says why", func(t *testing.T) {
			r := kids(nR, false, 50, 100, nil, authztest.ReadScope())
			if len(r.Rows) != 0 || !slices.Contains(r.ScopeReasons, "scope_empty") {
				t.Fatalf("%+v", r)
			}
		})
		t.Run("the scope fragment is the renderer's: the same text Compile draws", func(t *testing.T) {
			cq, err := reportsql.CompileTree(e.treeSource(t), reportsql.TreeQuery{Op: reportsql.TreeNode, Connection: c, Object: tg(nB1), Scope: scope})
			if err != nil {
				t.Fatal(err)
			}
			sql, _ := cq.Statement()
			if !strings.Contains(sql, "COALESCE(((t.\"ancestry_complete\")) AND") && !strings.Contains(sql, "COALESCE((t.\"ancestry_complete\")") {
				t.Fatalf("no scopeSQL shape in %s", sql)
			}
			if strings.Contains(sql, "'"+tg(nR)+"'") {
				t.Fatal("a GUID is inlined, not bound")
			}
		})
		t.Run("bad input is refused before any SQL", func(t *testing.T) {
			src := e.treeSource(t)
			for _, q := range []reportsql.TreeQuery{
				{Op: reportsql.TreeChildren, Connection: c, Object: "x' OR 1=1 --", Limit: 1, Examine: 1},
				{Op: reportsql.TreeChildren, Connection: c, Object: tg(nR), Limit: 0, Examine: 1},
				{Op: reportsql.TreeChildren, Connection: c, Object: tg(nR), Limit: 201, Examine: 1},
				{Op: reportsql.TreeChildren, Connection: c, Object: tg(nR), Limit: 1, Examine: 5001},
				{Op: 0},
			} {
				if _, err := reportsql.CompileTree(src, q); err == nil {
					t.Fatalf("accepted %+v", q)
				}
			}
		})
	})
}

package inventory_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/reportsql"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

// EX6 part (T-2088): the work of a tree statement is bounded by W_e, not by how many siblings the scope
// hides. A scoped caller is admitted to container C, which holds three visible children that sort last and H
// hidden ones (mid-repair, so every scope term refuses them) that sort first, for H in {0, W_e-10, W_e+10,
// 20,000}. W_e is injected small; the bound is the same in W_e.
//
// The index is the one of spec §5, created here because its migration belongs to T-2089; the test pins the
// statement to it, so that migration must create exactly this index or this test fails the build.
const treeIndex = `CREATE INDEX directory_objects_by_tree ON public.directory_objects
	(tenant_id, connection_id, parent_guid, (kind NOT IN ('ou', 'container')), (lower(rdn) COLLATE "C"), object_guid)
	WHERE state = 'live' AND parent_guid IS NOT NULL`

// treeRootsIndex serves roots: the live containers of AD connections in the statement's order, so the scan
// reads containers only (never the users) and LIMIT 501 stops it early once 501 roots are found.
const treeRootsIndex = `CREATE INDEX directory_objects_tree_roots ON public.directory_objects
	(tenant_id, connection_id, (lower(rdn) COLLATE "C"), object_guid)
	WHERE state = 'live' AND nc_guid IS NOT NULL AND kind IN ('ou', 'container')`

func (e *env) plan(t *testing.T, q reportsql.TreeQuery) *planNode {
	t.Helper()
	cq, err := reportsql.CompileTree(e.treeSource(t), q)
	if err != nil {
		t.Fatal(err)
	}
	sql, args := cq.Statement()
	var p *planNode
	if err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) (err error) {
		p, err = explainAnalyze(ctx, tx, sql, args)
		return
	}); err != nil {
		t.Fatal(err)
	}
	return p
}

// treeWork reads the plan: no Seq Scan of directory_objects, every directory_objects scan led by tenant_id
// (the RLS qual or the index condition), and the rows the CTE "base" read.
func treeWork(t *testing.T, p *planNode, label string) (baseRows float64) {
	t.Helper()
	p.walk("", func(n *planNode, cte string) {
		if n.Relation != "directory_objects" {
			return
		}
		if n.Type == "Seq Scan" {
			t.Errorf("%s: Seq Scan on directory_objects in %q", label, cte)
		}
		if n.Type == "Index Scan" || n.Type == "Index Only Scan" {
			if n.IndexCond != "" && n.Index != "directory_objects_by_ancestry" && !containsWord(n.IndexCond, "tenant_id") {
				t.Errorf("%s: %s on %s is not led by tenant_id: %s", label, n.Type, n.Index, n.IndexCond)
			}
		}
		if cte == "base" {
			baseRows += n.Rows * n.Loops
		}
	})
	return baseRows
}

func containsWord(s, w string) bool {
	for i := 0; i+len(w) <= len(s); i++ {
		if s[i:i+len(w)] == w {
			return true
		}
	}
	return false
}

func Test_CompileTree_work_is_bounded(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		const we, limit = 100, 5
		e := setup(t, s)
		for _, ix := range []string{treeIndex, treeRootsIndex} {
			if err := e.d.ExecOwner(context.Background(), ix); err != nil {
				t.Fatal(err)
			}
		}
		e.insertTree(t,
			tnode{id: nD, kind: "container", rdn: "dc=d", nc: true, complete: true, connection: e.adA},
			tnode{id: nP, parent: nD, anc: []int{nD}, kind: "container", rdn: "cn=c", nc: true, complete: true, connection: e.adA},
		)
		c := string(e.adA)
		ins := func(from, to int, prefix string, complete bool) {
			if err := e.exec(e.a, `INSERT INTO public.directory_objects (tenant_id, connection_id, object_guid, nc_guid, kind, object_class, parent_guid, ancestry, ancestry_complete, rdn, display_name, observed_at, state)
				SELECT NULLIF(current_setting('app.tenant_id', true), '')::uuid, $1::uuid, ('10000000-0000-4000-8000-' || lpad(g::text, 12, '0'))::uuid, $2::uuid,
				  'user', 'user', $3::uuid, ARRAY[$3::uuid, $4::uuid], $5, $6 || lpad(g::text, 8, '0'), '', now(), 'live'
				FROM generate_series($7::int, $8::int) g`, c, tg(1), tg(nP), tg(nD), complete, prefix, from, to); err != nil {
				t.Fatal(err)
			}
		}
		// filler: a directory_objects of realistic size under another container, and containers to root.
		if err := e.exec(e.a, `INSERT INTO public.directory_objects (tenant_id, connection_id, object_guid, nc_guid, kind, object_class, parent_guid, ancestry, ancestry_complete, rdn, display_name, observed_at, state)
			SELECT NULLIF(current_setting('app.tenant_id', true), '')::uuid, $1::uuid, ('20000000-0000-4000-8000-' || lpad(g::text, 12, '0'))::uuid, $2::uuid,
			  CASE WHEN g % 10 = 0 THEN 'ou' ELSE 'user' END, 'x', $3::uuid, ARRAY[$3::uuid], true, 'cn=f' || g, '', now(), 'live'
			FROM generate_series(1, 20000) g`, c, tg(1), tg(nD)); err != nil {
			t.Fatal(err)
		}
		ins(900001, 900003, "z", true)
		scope := scopeSub(e.adA, nP)
		hidden := 0
		for _, h := range []int{0, we - 10, we + 10, 20000} {
			t.Run(fmt.Sprintf("H=%d", h), func(t *testing.T) {
				if h > hidden {
					ins(1000+hidden, 1000+h-1, "a", false)
					hidden = h
				}
				if err := e.d.ExecOwner(context.Background(), `ANALYZE public.directory_objects`); err != nil {
					t.Fatal(err)
				}
				q := reportsql.TreeQuery{Op: reportsql.TreeChildren, Connection: c, Object: tg(nP), Limit: limit, Examine: we, Scope: scope}
				p := e.plan(t, q)
				base := treeWork(t, p, "children")
				t.Logf("children: %v child rows read before the scope cut (W_e=%d), execution %.2f ms", base, we, p.Time)
				if base > we {
					t.Errorf("children read %v child rows before the scope cut, W_e = %d", base, we)
				}
				r := e.tree(t, q)
				switch {
				case h <= we-10:
					if len(r.Rows) != 3 || r.More {
						t.Errorf("all three visible children expected: %v more=%v", rdns(r.Rows), r.More)
					}
				default:
					// the ceiling stops the read among the hidden rows: nothing visible yet, a cursor to go on
					if len(r.Rows) != 0 || !r.More || r.Resume == nil {
						t.Errorf("ceiling: %v more=%v resume=%v", rdns(r.Rows), r.More, r.Resume)
					}
				}
				treeWork(t, e.plan(t, reportsql.TreeQuery{Op: reportsql.TreeRoots, Scope: scope}), "roots")
				treeWork(t, e.plan(t, reportsql.TreeQuery{Op: reportsql.TreeNode, Connection: c, Object: tg(900001), Scope: scope}), "node")
			})
		}
	})
}

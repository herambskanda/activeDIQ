package inventory_test

import (
	"fmt"
	"strings"
	"testing"
)

// hitsJoinViolations is the plan shape of the search statement's reads of the three search relations
// (ADR-0011 rules 13 and 16, T-1345), whatever the ceiling: no Seq Scan on directory_objects, the key table or the
// posting table; directory_objects is reached only through an Index Scan or Index Only Scan whose Index Cond holds
// tenant_id (a read bounded by the tenant, not filtered after it); and no Hash Join or Merge Join has
// directory_objects below it, because a join the planner may pick by estimate reads every tenant's rows.
func hitsJoinViolations(plan *planNode) []string {
	var out []string
	plan.walk("", func(n *planNode, cte string) {
		switch n.Relation {
		case "directory_objects", "inventory_search_keys", "inventory_search_trigrams":
			if strings.Contains(n.Type, "Seq Scan") {
				out = append(out, fmt.Sprintf("%s on %s (%s)", n.Type, n.Relation, cte))
			}
		}
		if n.Relation == "directory_objects" || strings.HasPrefix(n.Index, "directory_objects") {
			if n.Type != "Index Scan" && n.Type != "Index Only Scan" && !strings.Contains(n.Type, "Seq Scan") {
				out = append(out, fmt.Sprintf("directory_objects is read by a %s (%s), want an Index Scan", n.Type, cte))
			}
			if (n.Type == "Index Scan" || n.Type == "Index Only Scan") && !strings.Contains(n.IndexCond, "tenant_id") {
				out = append(out, fmt.Sprintf("directory_objects %s Index Cond %q lacks tenant_id (%s)", n.Type, n.IndexCond, cte))
			}
		}
		if n.Type == "Hash Join" || n.Type == "Merge Join" {
			found := false
			for i := range n.Children {
				n.Children[i].walk("", func(c *planNode, _ string) {
					if c.Relation == "directory_objects" || strings.HasPrefix(c.Index, "directory_objects") {
						found = true
					}
				})
			}
			if found {
				out = append(out, fmt.Sprintf("%s onto directory_objects (%s)", n.Type, cte))
			}
		}
	})
	return out
}

// The checker has to fail on the shapes it forbids: these are the plans PostgreSQL 18 chose at the default W
// before the hits join probed per candidate, and variants of it.
func Test_search_plan_shape_checker_rejects_seq_scan_and_hash_join(t *testing.T) {
	probe := planNode{Type: "Index Scan", Relation: "directory_objects", Index: "directory_objects_pkey", IndexCond: "((tenant_id = x) AND (connection_id = c.connection_id))"}
	hash := planNode{Type: "Hash Join", Children: []planNode{{Type: "CTE Scan"}, {Type: "Hash", Children: []planNode{{Type: "Seq Scan", Relation: "directory_objects"}}}}}
	cases := []struct {
		name string
		plan planNode
		want string // "" means no violation
	}{
		{"nested loop of index probes", planNode{Type: "Nested Loop", Children: []planNode{{Type: "CTE Scan"}, probe}}, ""},
		{"index only scan with tenant", planNode{Type: "Index Only Scan", Relation: "directory_objects", IndexCond: "(tenant_id = x)"}, ""},
		{"hash join onto a seq scan", hash, "Seq Scan on directory_objects"},
		{"hash join onto an index scan", planNode{Type: "Hash Join", Children: []planNode{{Type: "CTE Scan"}, {Type: "Hash", Children: []planNode{probe}}}}, "Hash Join onto directory_objects"},
		{"merge join onto an index scan", planNode{Type: "Merge Join", Children: []planNode{{Type: "CTE Scan"}, probe}}, "Merge Join onto directory_objects"},
		{"index scan without tenant_id", planNode{Type: "Index Scan", Relation: "directory_objects", IndexCond: "(object_guid = c.object_guid)"}, "lacks tenant_id"},
		{"bitmap scan", planNode{Type: "Bitmap Heap Scan", Relation: "directory_objects"}, "want an Index Scan"},
		{"seq scan on the posting table", planNode{Type: "Seq Scan", Relation: "inventory_search_trigrams"}, "Seq Scan on inventory_search_trigrams"},
		{"seq scan on the key table", planNode{Type: "Seq Scan", Relation: "inventory_search_keys"}, "Seq Scan on inventory_search_keys"},
	}
	for _, c := range cases {
		got := strings.Join(hitsJoinViolations(&c.plan), "; ")
		if c.want == "" && got != "" || c.want != "" && !strings.Contains(got, c.want) {
			t.Errorf("%s: violations %q, want %q", c.name, got, c.want)
		}
	}
}

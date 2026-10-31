package inventory

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"sort"

	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tablekind"
)

// Both closure tables derive from the DM-17 links; neither is append-only (the closure is recomputed).
var _ = tablekind.Declare(tablekind.Table{Name: "public.inventory_group_members", Entity: "DM-17", Kind: tablekind.Directory})
var _ = tablekind.Declare(tablekind.Table{Name: "public.inventory_group_closure_dirty", Entity: "DM-17", Kind: tablekind.Directory})

// The effective-membership closure (reports spec §6.6, FR-15) is materialised in
// inventory_group_members (migration 0067) by RefreshClosure, which Populate calls at the end of every
// batch. It is derived only from the stored DM-17 links and the live group rows, never from a live
// LDAP walk. See the migration for what a row means.

const (
	// maxClosureDepth is the deepest member row the closure holds. Nesting beyond it is not followed:
	// the groups at the cap are flagged cut and the group_members dataset shows the finding. A refresh
	// never fails on depth: whoever can build a deep chain of groups must not be able to freeze the
	// inventory of the whole domain.
	maxClosureDepth = 128
	// closureChunk bounds the roots one INSERT carries, so a parameter stays small on a big domain.
	closureChunk = 200
	// closureChunkRows bounds the member rows one INSERT is estimated to produce, so no single statement
	// nears the store's statement timeout (30 s) at the declared budget. A root above it goes alone.
	closureChunkRows = 25_000

	// The closure row budget (breadth, as maxClosureDepth is the budget of depth). Without it, whoever can
	// write the member attribute of K groups (a group delegate, a managedBy owner, anyone who can create a
	// group) adds one big group to each and the closure grows to K x N rows; every later change to the big
	// group then rewrites all of them inside the sync transaction, under the connection's lock (security
	// review of T-0961: 50 one-value writes made 306,050 rows and 13-15 s per batch).
	//
	// A root's cost is estimated before anything is written: the number of member and primary-group links
	// of every group it reaches, an upper bound of the rows it would hold (a member reachable several
	// ways has one row). A root whose estimate exceeds defaultRootRows, or what is left of
	// defaultConnRows after the roots that are not being recomputed, is not expanded: it gets one
	// over_budget marker row, its counts read Unknown and group_members says so. The refresh succeeds.
	// Roots are admitted smallest estimate first (then lowest GUID), so a container never displaces the
	// group it contains, and the outcome does not depend on the order rows arrived. Because only
	// recomputed roots are re-decided, the rows held by the other roots stay within defaultConnRows, and a
	// refresh deletes and inserts at most that many rows.
	//
	// defaultRootRows holds a 200,000-user Domain Users (the largest group a customer domain has);
	// defaultConnRows holds it and BUILTIN\Users, which contains it, with room for the rest.
	defaultRootRows = 250_000
	defaultConnRows = 500_000
)

// closureBudget is the row budget in force; tests lower it through SetClosureBudget (export_test.go).
var closureBudget = budget{root: defaultRootRows, conn: defaultConnRows}

type budget struct{ root, conn int }

// RefreshClosure recomputes the closure rows of every group marked dirty and of every live group that
// contains one (directly or through nesting), then clears the marks. It runs in the caller's tenant
// transaction under the connection's writer lock. With nothing dirty it reads one row and returns.
func (Writer) RefreshClosure(ctx context.Context, tx store.Tx, connection ConnectionID) (int, error) {
	if _, ok := canon(string(connection)); !ok || string(connection) != lower(string(connection)) {
		return 0, ErrInvalid
	}
	if err := requireTenant(ctx, tx); err != nil {
		return 0, err
	}
	if err := lockConnection(ctx, tx, connection); err != nil {
		return 0, err
	}
	dirty, err := scanGUIDs(tx.Query(ctx, `SELECT group_guid::text FROM public.inventory_group_closure_dirty
		WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND connection_id = $1::uuid`, string(connection)))
	if err != nil {
		return 0, fmt.Errorf("inventory: closure: dirty groups: %w", err)
	}
	if len(dirty) == 0 {
		return 0, nil
	}
	// The dirty groups, every group left unexpanded by an earlier refresh (the budget may have room now),
	// and every live group above them: their rows are stale or to be decided again.
	affected, err := scanGUIDs(tx.Query(ctx, `WITH RECURSIVE up(g) AS (
			SELECT x FROM unnest($2::uuid[]) AS x
		UNION
			SELECT o.group_guid FROM public.inventory_group_members o
			WHERE o.tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND o.connection_id = $1::uuid AND o.edge_kind = 'over_budget'
		UNION
			SELECT l.source_guid FROM public.links l JOIN up ON l.target_guid = up.g
			JOIN public.directory_objects s ON s.tenant_id = l.tenant_id AND s.connection_id = l.connection_id AND s.object_guid = l.source_guid
			WHERE l.tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND l.connection_id = $1::uuid
			AND l.link_attr = 'member' AND l.state = 'active' AND s.kind = 'group' AND s.state = 'live')
		SELECT g::text FROM up`, string(connection), dirty))
	if err != nil {
		return 0, fmt.Errorf("inventory: closure: affected groups: %w", err)
	}
	// The live nesting edges below the affected live groups: all a breadth-first walk needs.
	roots, err := scanGUIDs(tx.Query(ctx, `SELECT object_guid::text FROM public.directory_objects
		WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND connection_id = $1::uuid
		AND object_guid = ANY($2::uuid[]) AND kind = 'group' AND state = 'live'`, string(connection), affected))
	if err != nil {
		return 0, fmt.Errorf("inventory: closure: live roots: %w", err)
	}
	edges, err := nestingEdges(ctx, tx, connection, roots)
	if err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM public.inventory_group_members
		WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND connection_id = $1::uuid AND group_guid = ANY($2::uuid[])`,
		string(connection), affected); err != nil {
		return 0, fmt.Errorf("inventory: closure: clear: %w", err)
	}
	admitted, over, counts, err := admit(ctx, tx, connection, roots, affected, edges)
	if err != nil {
		return 0, err
	}
	roots = admitted
	var chunk []reachRow
	var cuts []reachRow
	rows := 0
	flush := func() error {
		if len(chunk) == 0 {
			return nil
		}
		b, err := json.Marshal(chunk)
		if err != nil {
			return fmt.Errorf("inventory: closure: %w", err)
		}
		tag, err := tx.Exec(ctx, insertClosureSQL, string(connection), string(b))
		if err != nil {
			return writeErr("closure insert", err)
		}
		rows += int(tag.RowsAffected())
		if len(cuts) > 0 {
			cb, err := json.Marshal(cuts)
			if err != nil {
				return fmt.Errorf("inventory: closure: %w", err)
			}
			if _, err := tx.Exec(ctx, markCutSQL, string(connection), string(cb)); err != nil {
				return writeErr("closure cut", err)
			}
		}
		chunk, cuts = chunk[:0], cuts[:0]
		return nil
	}
	pending := 0
	for i, r := range roots {
		reach, cut := reachFrom(r, edges)
		chunk = append(chunk, reach...)
		cuts = append(cuts, cut...)
		for _, g := range reach {
			pending += counts[g.Grp]
		}
		if (i+1)%closureChunk == 0 || len(chunk) >= 20000 || pending >= closureChunkRows {
			pending = 0
			if err := flush(); err != nil {
				return 0, err
			}
		}
	}
	if err := flush(); err != nil {
		return 0, err
	}
	if len(over) > 0 {
		tag, err := tx.Exec(ctx, markOverBudgetSQL, string(connection), over)
		if err != nil {
			return 0, writeErr("closure over budget", err)
		}
		rows += int(tag.RowsAffected())
	}
	if _, err := tx.Exec(ctx, `DELETE FROM public.inventory_group_closure_dirty
		WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND connection_id = $1::uuid AND group_guid = ANY($2::uuid[])`,
		string(connection), dirty); err != nil {
		return 0, fmt.Errorf("inventory: closure: clear marks: %w", err)
	}
	return rows, nil
}

// insertClosureSQL turns the groups each root reaches (root itself at depth 0) into member rows: every
// active member or primary-group link of a reached group is a member of the root. A member reachable
// several ways keeps its shortest path (then the lowest group GUID, then a member value over a
// primary-group edge). A link back to the root is the cycle finding.
const insertClosureSQL = `INSERT INTO public.inventory_group_members (tenant_id, connection_id, group_guid, member_guid, edge_kind, depth, via)
	SELECT DISTINCT ON (r.root, l.target_guid)
		NULLIF(current_setting('app.tenant_id', true), '')::uuid, $1::uuid, r.root, l.target_guid,
		CASE WHEN l.target_guid = r.root THEN 'cycle'
		     WHEN r.depth > 0 THEN 'nested'
		     WHEN l.link_attr = 'primary_group' THEN 'primary_group'
		     ELSE 'direct' END,
		r.depth + 1,
		CASE WHEN r.depth > 0 THEN r.via || r.grp ELSE '{}'::uuid[] END
	FROM jsonb_to_recordset($2::jsonb) AS r(root uuid, grp uuid, depth int, via uuid[])
	JOIN public.links l ON l.tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND l.connection_id = $1::uuid
		AND l.source_guid = r.grp AND l.link_attr IN ('member', 'primary_group') AND l.state = 'active'
	ORDER BY r.root, l.target_guid, r.depth, r.grp, (l.link_attr = 'primary_group')`

// markOverBudgetSQL gives each group left unexpanded its one marker row (group = member).
const markOverBudgetSQL = `INSERT INTO public.inventory_group_members (tenant_id, connection_id, group_guid, member_guid, edge_kind, depth, via)
	SELECT NULLIF(current_setting('app.tenant_id', true), '')::uuid, $1::uuid, g, g, 'over_budget', 1, '{}'::uuid[]
	FROM unnest($2::uuid[]) AS g`

// admit splits the roots being recomputed into those that fit the closure budget and those that do not
// (see defaultRootRows). Nothing is written. The estimate walks the group edges only, never the members.
func admit(ctx context.Context, tx store.Tx, connection ConnectionID, roots, affected []string, edges map[string][]string) (admitted, over []string, counts map[string]int, err error) {
	if len(roots) == 0 {
		return nil, nil, nil, nil
	}
	universe := map[string]bool{}
	for p, cs := range edges {
		universe[p] = true
		for _, c := range cs {
			universe[c] = true
		}
	}
	for _, r := range roots {
		universe[r] = true
	}
	ids := make([]string, 0, len(universe))
	for g := range universe {
		ids = append(ids, g)
	}
	counts = map[string]int{}
	rows, err := tx.Query(ctx, `SELECT source_guid::text, count(*) FROM public.links
		WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND connection_id = $1::uuid
		AND source_guid = ANY($2::uuid[]) AND link_attr IN ('member', 'primary_group') AND state = 'active' GROUP BY source_guid`, string(connection), ids)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("inventory: closure: budget counts: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var g string
		var n int
		if err := rows.Scan(&g, &n); err != nil {
			return nil, nil, nil, fmt.Errorf("inventory: closure: budget counts: %w", err)
		}
		counts[g] = n
	}
	if err := rows.Err(); err != nil {
		return nil, nil, nil, fmt.Errorf("inventory: closure: budget counts: %w", err)
	}
	rows.Close()
	var held int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM public.inventory_group_members
		WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND connection_id = $1::uuid AND NOT group_guid = ANY($2::uuid[])`,
		string(connection), affected).Scan(&held); err != nil {
		return nil, nil, nil, fmt.Errorf("inventory: closure: budget held rows: %w", err)
	}
	admitted, over = splitByBudget(roots, edges, counts, closureBudget, held)
	return admitted, over, counts, nil
}

// splitByBudget is admit without the database: each root's estimate is the sum of counts over the groups it reaches.
func splitByBudget(roots []string, edges map[string][]string, counts map[string]int, b budget, held int) (admitted, over []string) {
	type cand struct {
		root string
		est  int
	}
	cands := make([]cand, 0, len(roots))
	for _, r := range roots {
		reach, _ := reachFrom(r, edges)
		est := 0
		for _, g := range reach {
			est += counts[g.Grp]
		}
		cands = append(cands, cand{r, est})
	}
	sort.Slice(cands, func(i, j int) bool {
		if cands[i].est != cands[j].est {
			return cands[i].est < cands[j].est
		}
		return cands[i].root < cands[j].root
	})
	remaining := max(b.conn-held, 0)
	for _, c := range cands {
		if c.est > b.root || c.est > remaining {
			over = append(over, c.root)
			continue
		}
		remaining -= c.est
		admitted = append(admitted, c.root)
	}
	return admitted, over
}

// markCutSQL flags the member rows of groups the walk did not descend into (see maxClosureDepth), when
// such a group has members at all: an empty group at the cap hides nothing.
const markCutSQL = `UPDATE public.inventory_group_members m SET cut = true
	FROM jsonb_to_recordset($2::jsonb) AS c(root uuid, grp uuid)
	WHERE m.tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND m.connection_id = $1::uuid
	AND m.group_guid = c.root AND m.member_guid = c.grp AND m.edge_kind = 'nested' AND m.depth = 128
	AND EXISTS (SELECT 1 FROM public.links l WHERE l.tenant_id = m.tenant_id AND l.connection_id = m.connection_id
		AND l.source_guid = c.grp AND l.link_attr IN ('member', 'primary_group') AND l.state = 'active')`

type reachRow struct {
	Root  string   `json:"root"`
	Grp   string   `json:"grp"`
	Depth int      `json:"depth"`
	Via   []string `json:"via"`
}

// nestingEdges returns, for every live group at or below the roots, its live group members:
// parent -> children, children sorted so that a walk is deterministic.
func nestingEdges(ctx context.Context, tx store.Tx, connection ConnectionID, roots []string) (map[string][]string, error) {
	out := map[string][]string{}
	if len(roots) == 0 {
		return out, nil
	}
	rows, err := tx.Query(ctx, `WITH RECURSIVE down(g) AS (
			SELECT x FROM unnest($2::uuid[]) AS x
		UNION
			SELECT l.target_guid FROM public.links l JOIN down ON l.source_guid = down.g
			JOIN public.directory_objects t ON t.tenant_id = l.tenant_id AND t.connection_id = l.connection_id AND t.object_guid = l.target_guid
			WHERE l.tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND l.connection_id = $1::uuid
			AND l.link_attr = 'member' AND l.state = 'active' AND t.kind = 'group' AND t.state = 'live')
		SELECT l.source_guid::text, l.target_guid::text FROM public.links l JOIN down ON l.source_guid = down.g
		JOIN public.directory_objects t ON t.tenant_id = l.tenant_id AND t.connection_id = l.connection_id AND t.object_guid = l.target_guid
		WHERE l.tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND l.connection_id = $1::uuid
		AND l.link_attr = 'member' AND l.state = 'active' AND t.kind = 'group' AND t.state = 'live'`, string(connection), roots)
	if err != nil {
		return nil, fmt.Errorf("inventory: closure: nesting edges: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var s, t string
		if err := rows.Scan(&s, &t); err != nil {
			return nil, fmt.Errorf("inventory: closure: nesting edges: %w", err)
		}
		out[s] = append(out[s], t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("inventory: closure: nesting edges: %w", err)
	}
	for _, c := range out {
		sort.Strings(c)
	}
	return out, nil
}

// reachFrom walks the nesting edges breadth first from root and returns every group it reaches,
// root first at depth 0, each with its shortest chain of intermediate groups (nearest the root first).
// A group at the depth cap is not descended into; it is returned in the second result (Root, Grp) so its
// member row is flagged. A group is visited once, so cycles end. Level by level and in GUID order, the parent of a group is the
// lowest-GUID group of the previous level that holds it, which makes the chain deterministic.
func reachFrom(root string, edges map[string][]string) (reached, cut []reachRow) {
	type node struct {
		depth int
		via   []string
	}
	seen := map[string]node{root: {}}
	out := []reachRow{{Root: root, Grp: root, Depth: 0, Via: []string{}}}
	cutSeen := map[string]bool{}
	frontier := []string{root}
	for depth := 1; len(frontier) > 0; depth++ {
		var next []string
		for _, g := range frontier {
			for _, c := range edges[g] {
				if _, ok := seen[c]; ok {
					continue
				}
				if depth >= maxClosureDepth {
					if !cutSeen[c] {
						cutSeen[c] = true
						cut = append(cut, reachRow{Root: root, Grp: c, Depth: depth})
					}
					continue
				}
				n := node{depth: depth}
				if depth > 1 {
					n.via = append(append(make([]string, 0, depth), seen[g].via...), g)
				} else {
					n.via = []string{}
				}
				seen[c] = n
				next = append(next, c)
				out = append(out, reachRow{Root: root, Grp: c, Depth: depth, Via: n.via})
			}
		}
		sort.Strings(next)
		frontier = next
	}
	return out, cut
}

// guidRows is the part of pgx.Rows scanGUIDs reads. The SQL stays a constant at the call site
// (sqlconst), so the helper takes the rows, not the statement: scanGUIDs(tx.Query(ctx, `...`, args...)).
type guidRows interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
	Close()
}

func scanGUIDs(rows guidRows, err error) ([]string, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

package inventory

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"sort"

	"github.com/skenzeriq/activediq/internal/platform/store"
)

// The effective-membership closure (reports spec §6.6, FR-15) is materialised in
// inventory_group_members (migration 0063) by RefreshClosure, which Populate calls at the end of every
// batch. It is derived only from the stored DM-17 links and the live group rows, never from a live
// LDAP walk. See the migration for what a row means.

// ErrTooDeep: group nesting is deeper than the closure can hold (128 levels). A silent cut would hide
// members, so the refresh fails and the cycle rolls back.
var ErrTooDeep = errors.New("inventory: group nesting is deeper than 128 levels")

const (
	maxClosureDepth = 128
	// closureChunk bounds the roots one INSERT carries, so a parameter stays small on a big domain.
	closureChunk = 200
)

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
	dirty, err := queryGUIDs(ctx, tx, `SELECT group_guid::text FROM public.inventory_group_closure_dirty
		WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND connection_id = $1::uuid`, string(connection))
	if err != nil {
		return 0, fmt.Errorf("inventory: closure: dirty groups: %w", err)
	}
	if len(dirty) == 0 {
		return 0, nil
	}
	// The dirty groups and every live group above them: their rows are stale.
	affected, err := queryGUIDs(ctx, tx, `WITH RECURSIVE up(g) AS (
			SELECT x FROM unnest($2::uuid[]) AS x
		UNION
			SELECT l.source_guid FROM public.links l JOIN up ON l.target_guid = up.g
			JOIN public.directory_objects s ON s.tenant_id = l.tenant_id AND s.connection_id = l.connection_id AND s.object_guid = l.source_guid
			WHERE l.tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND l.connection_id = $1::uuid
			AND l.link_attr = 'member' AND l.state = 'active' AND s.kind = 'group' AND s.state = 'live')
		SELECT g::text FROM up`, string(connection), dirty)
	if err != nil {
		return 0, fmt.Errorf("inventory: closure: affected groups: %w", err)
	}
	// The live nesting edges below the affected live groups: all a breadth-first walk needs.
	roots, err := queryGUIDs(ctx, tx, `SELECT object_guid::text FROM public.directory_objects
		WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND connection_id = $1::uuid
		AND object_guid = ANY($2::uuid[]) AND kind = 'group' AND state = 'live'`, string(connection), affected)
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
	var chunk []reachRow
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
		chunk = chunk[:0]
		return nil
	}
	for i, r := range roots {
		reach, err := reachFrom(r, edges)
		if err != nil {
			return 0, err
		}
		chunk = append(chunk, reach...)
		if (i+1)%closureChunk == 0 || len(chunk) >= 20000 {
			if err := flush(); err != nil {
				return 0, err
			}
		}
	}
	if err := flush(); err != nil {
		return 0, err
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
// A group is visited once, so cycles end. Level by level and in GUID order, the parent of a group is the
// lowest-GUID group of the previous level that holds it, which makes the chain deterministic.
func reachFrom(root string, edges map[string][]string) ([]reachRow, error) {
	type node struct {
		depth int
		via   []string
	}
	seen := map[string]node{root: {}}
	out := []reachRow{{Root: root, Grp: root, Depth: 0, Via: []string{}}}
	frontier := []string{root}
	for depth := 1; len(frontier) > 0; depth++ {
		var next []string
		for _, g := range frontier {
			for _, c := range edges[g] {
				if _, ok := seen[c]; ok {
					continue
				}
				if depth >= maxClosureDepth {
					return nil, ErrTooDeep
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
	return out, nil
}

func queryGUIDs(ctx context.Context, tx store.Tx, sql string, args ...any) ([]string, error) {
	rows, err := tx.Query(ctx, sql, args...)
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

package inventory

import (
	"context"

	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/platform/searchkey"
	"github.com/skenzeriq/activediq/internal/platform/store"
)

// dnPage is the number of descendants one step of rewriteDescendantDNs reads and writes.
const dnPage = 1000

// descendantsDNSQL reads one page of the rows below $2 after $3, in object order: their dn, kind, state
// and how many hops above them $2 sits (ancestry is nearest parent first, so 1 is the parent).
const descendantsDNSQL = `SELECT object_guid::text, dn, kind, state, array_position(ancestry, $2::uuid)
	FROM public.directory_objects
	WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND connection_id = $1::uuid
	AND ancestry @> ARRAY[$2::uuid] AND object_guid <> $2::uuid AND dn <> ''
	AND ($3::uuid IS NULL OR object_guid > $3::uuid)
	ORDER BY object_guid LIMIT $4`

// rewriteDescendantDNs re-derives the dn of every row below moved from moved's new dn (DM-16.I5:
// DirSync does not report the children of a moved parent). A descendant's dn is its own RDNs, one
// per hop up to moved, then moved's dn, so the new dn keeps the first k RDNs (k = its distance to
// moved) and takes moved's new dn after them. This is a typed DN operation (dn.Rebase), never a
// text replace, so a comma or "+" inside an RDN value cannot shift the cut. The swap is by position,
// so a descendant that already carries the new dn (observed earlier in the same batch) comes out
// unchanged. The row's dn search key follows in the same transaction (ADR-0011 rule 5); the other keys
// do not depend on the dn.
//
// A dn that cannot be rebased (it does not parse, or it has fewer RDNs than its chain says) becomes
// empty, which is "unknown", never a stale one; its dn key is removed with it. An empty movedDN (a
// row without a dn, such as an Entra object) leaves the descendants' dn alone.
func rewriteDescendantDNs(ctx context.Context, tx store.Tx, connection ConnectionID, moved GUID, movedDN string) error {
	if movedDN == "" {
		return nil
	}
	target, terr := dn.Parse(movedDN, dn.Lenient)
	after := ""
	for {
		rs, err := tx.Query(ctx, descendantsDNSQL, string(connection), string(moved), nilIfEmptyStr(after), dnPage)
		if err != nil {
			return writeErr("read descendants dn", err)
		}
		var guids, oldDN, newDN, kinds []string
		var states []string
		for rs.Next() {
			var g, d, k, st string
			var hops int
			if err := rs.Scan(&g, &d, &k, &st, &hops); err != nil {
				rs.Close()
				return writeErr("scan descendants dn", err)
			}
			guids, oldDN, kinds, states = append(guids, g), append(oldDN, d), append(kinds, k), append(states, st)
			newDN = append(newDN, rebased(d, hops, target, terr))
		}
		rs.Close()
		if err := rs.Err(); err != nil {
			return writeErr("read descendants dn", err)
		}
		if len(guids) == 0 {
			return nil
		}
		after = guids[len(guids)-1]

		var keyObjs, keyVals []string
		var changed []string
		var changedDN []string
		for i := range guids {
			if newDN[i] == oldDN[i] {
				continue
			}
			changed, changedDN = append(changed, guids[i]), append(changedDN, newDN[i])
			src := keySource{object: GUID(guids[i]), kind: Kind(kinds[i]), state: ObjectState(states[i]), dn: newDN[i]}
			if !src.searchable() {
				continue
			}
			keyObjs = append(keyObjs, guids[i])
			keyVals = append(keyVals, dnKey(newDN[i]))
		}
		if len(changed) == 0 {
			if len(guids) < dnPage {
				return nil
			}
			continue
		}
		if _, err := tx.Exec(ctx, `UPDATE public.directory_objects d SET dn = v.dn
			FROM unnest($2::uuid[], $3::text[]) AS v(object_guid, dn)
			WHERE d.tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND d.connection_id = $1::uuid
			AND d.object_guid = v.object_guid`, string(connection), changed, changedDN); err != nil {
			return writeErr("rewrite descendants dn", err)
		}
		// Every changed row loses a dn key that is not its new one; the searchable ones get the new one. One
		// statement, and the delete spares a key the insert wants, as writeSearchKeysSQL does, so a new
		// dn that normalises to the old key is not deleted and then lost to the conflict.
		if _, err := tx.Exec(ctx, `WITH want AS (
				SELECT w.object_guid, w.key FROM unnest($4::uuid[], $5::text[]) AS w(object_guid, key) WHERE w.key <> ''),
			del AS (
				DELETE FROM public.inventory_search_keys k
				WHERE k.tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND k.connection_id = $1::uuid
				AND k.key_kind = $2::smallint AND k.object_guid = ANY($3::uuid[])
				AND NOT EXISTS (SELECT 1 FROM want w WHERE w.object_guid = k.object_guid AND w.key = k.key)
				RETURNING 1)
			INSERT INTO public.inventory_search_keys (tenant_id, connection_id, object_guid, key_kind, key, norm_version)
			SELECT NULLIF(current_setting('app.tenant_id', true), '')::uuid, $1::uuid, w.object_guid, $2::smallint, w.key, $6::smallint FROM want w
			ON CONFLICT (tenant_id, connection_id, object_guid, key_kind, key) DO UPDATE SET norm_version = EXCLUDED.norm_version`,
			string(connection), int16(searchkey.KindDN), changed, keyObjs, keyVals, int16(searchkey.Version)); err != nil {
			return writeErr("rewrite descendants dn keys", err)
		}
		if len(guids) < dnPage {
			return nil
		}
	}
}

func nilIfEmptyStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// dnKey is the dn search key searchKeys would build for text, "" when it builds none.
func dnKey(text string) string {
	for _, r := range searchKeys(keySource{object: "00000000-0000-0000-0000-000000000000", kind: KindUser, state: ObjLive, dn: text}) {
		if r.kind == searchkey.KindDN {
			return r.key
		}
	}
	return ""
}

// rebased is d with everything above its first keep RDNs replaced by target; "" when it cannot be.
func rebased(d string, keep int, target dn.DN, terr error) string {
	if terr != nil {
		return ""
	}
	cur, err := dn.Parse(d, dn.Lenient)
	if err != nil || keep >= cur.Len() {
		return ""
	}
	out, err := dn.Rebase(cur, keep, target)
	if err != nil {
		return ""
	}
	return out.String()
}

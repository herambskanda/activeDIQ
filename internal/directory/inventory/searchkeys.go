package inventory

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/attr/sid"
	"github.com/skenzeriq/activediq/internal/platform/searchkey"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tablekind"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

var _ = tablekind.Declare(tablekind.Table{Name: "public.inventory_search_keys", Entity: "DM-16", Kind: tablekind.Directory})

// The search index (ADR-0011 rules 5, 6, 9; migration 0069). The sync writer writes an object's keys in
// the same transaction as its directory_objects row (Populate), so a reader sees both or neither, and a
// rolled-back cycle leaves them unchanged.
//
// Keys come from an allow-list of typed columns, plus two attributes of the generic bag read by name
// (mail of a contact, dNSHostName of a computer). Nothing is derived from "the attribute bag as a whole":
// a secret attribute, a confidential one, or any attribute not named here cannot yield a key.

// searchKeyRow is one key of one object.
type searchKeyRow struct {
	object GUID
	kind   searchkey.Kind
	key    string
}

// keySource is what the keys of one object are built from. Populate fills it from the Observation, the
// backfill from the stored row; both go through searchKeys so that they cannot differ.
type keySource struct {
	object          GUID
	kind            Kind
	state           ObjectState
	displayName     string
	rdn             string
	sam             string
	upn             string
	dn              string
	sid             []byte
	consistencyGUID []byte
	// mail and dnsHost are the string values of the attributes "mail" and "dNSHostName", "" when absent
	// or not a string.
	mail, dnsHost string
}

func sourceOf(o *Observation) keySource {
	s := keySource{object: o.Object, kind: o.Kind, state: o.State, displayName: o.DisplayName, rdn: o.RDN, sam: o.SAMAccountName,
		upn: o.UPN, dn: o.DN, sid: o.SID, consistencyGUID: o.ConsistencyGUID}
	if v, ok := o.Attributes["mail"].(string); ok {
		s.mail = v
	}
	if v, ok := o.Attributes["dNSHostName"].(string); ok {
		s.dnsHost = v
	}
	return s
}

// searchable says which objects the index holds: the kinds universal search answers (users, groups,
// computers, contacts) that are not purged.
func (s keySource) searchable() bool {
	switch s.kind {
	case KindUser, KindInetOrgPerson, KindGroup, KindComputer, KindGMSA, KindContact:
	default:
		return false
	}
	return s.state != ObjPurged
}

// rdnValue is the value of an RDN given as "CN=Priya Raman" or "CN=Raman\, Priya": the part after the
// first "=", with backslash escapes resolved.
func rdnValue(rdn string) string {
	i := strings.IndexByte(rdn, '=')
	if i < 0 {
		return rdn
	}
	v := rdn[i+1:]
	var b strings.Builder
	for j := 0; j < len(v); j++ {
		c := v[j]
		if c != '\\' || j+1 >= len(v) {
			b.WriteByte(c)
			continue
		}
		j++
		if j+1 < len(v) && isHex(v[j]) && isHex(v[j+1]) {
			b.WriteByte(unhex(v[j])<<4 | unhex(v[j+1]))
			j++
			continue
		}
		b.WriteByte(v[j])
	}
	if !utf8.ValidString(b.String()) {
		return ""
	}
	return b.String()
}

func isHex(c byte) bool { return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' }
func unhex(c byte) byte {
	switch {
	case c >= 'a':
		return c - 'a' + 10
	case c >= 'A':
		return c - 'A' + 10
	}
	return c - '0'
}

// searchKeys builds the keys of one object, deduplicated and in a stable order. A value that cannot be
// normalised or that is longer than a query can be is skipped, never an error: an object is stored
// whatever its text looks like.
func searchKeys(s keySource) []searchKeyRow {
	if !s.searchable() {
		return nil
	}
	var out []searchKeyRow
	seen := map[searchkey.Kind]map[string]bool{}
	add := func(k searchkey.Kind, key string) {
		if key == "" || utf8.RuneCountInString(key) > searchkey.MaxRunes || !utf8.ValidString(key) || strings.IndexByte(key, 0) >= 0 {
			return
		}
		if seen[k] == nil {
			seen[k] = map[string]bool{}
		}
		if !seen[k][key] {
			seen[k][key] = true
			out = append(out, searchKeyRow{s.object, k, key})
		}
	}
	ident := func(k searchkey.Kind, v string) {
		if v != "" && utf8.ValidString(v) && !strings.ContainsRune(v, 0) {
			add(k, searchkey.NormIdent(v))
		}
	}
	name := func(v string) {
		if v == "" || !utf8.ValidString(v) || strings.ContainsRune(v, 0) {
			return
		}
		n := searchkey.NormName(v)
		add(searchkey.KindName, n)
		for _, w := range searchkey.Words(n) {
			add(searchkey.KindNameWord, w)
		}
	}
	isComputer := s.kind == KindComputer || s.kind == KindGMSA

	name(s.displayName)
	rdn := rdnValue(s.rdn)
	if isComputer {
		rdn = strings.TrimSuffix(rdn, "$")
	}
	name(rdn)

	ident(searchkey.KindSAM, s.sam)
	if isComputer && strings.HasSuffix(s.sam, "$") {
		ident(searchkey.KindSAM, strings.TrimSuffix(s.sam, "$"))
	}
	ident(searchkey.KindUPN, s.upn)
	if s.kind == KindContact {
		ident(searchkey.KindMail, s.mail)
	}
	if isComputer {
		ident(searchkey.KindDNSHost, s.dnsHost)
	}
	if len(s.sid) > 0 {
		if v, err := sid.FromBytes(s.sid); err == nil {
			ident(searchkey.KindSID, v.String())
		}
	}
	add(searchkey.KindGUID, strings.ToLower(string(s.object)))
	if len(s.consistencyGUID) > 0 {
		if g, err := guid.FromBytes(s.consistencyGUID); err == nil {
			add(searchkey.KindConsistencyGUID, g.String())
			ident(searchkey.KindConsistencyGUID, base64.StdEncoding.EncodeToString(s.consistencyGUID))
		}
	}
	if s.dn != "" && utf8.ValidString(s.dn) && !strings.ContainsRune(s.dn, 0) {
		add(searchkey.KindDN, searchkey.NormDN(s.dn))
	}
	return out
}

// keyDelta is what a write of search keys changed.
type keyDelta struct{ inserted, updated, deleted int }

// writeSearchKeys makes the keys of the given objects exactly rows: keys not in rows are deleted, new ones
// inserted, and a key whose norm_version is older than searchkey.Version is rewritten. An object in
// objects with no row has no keys afterwards. Nothing is written for a key that is already current, so
// running it again changes nothing. It runs in the caller's tenant transaction.
func writeSearchKeys(ctx context.Context, tx store.Tx, connection ConnectionID, objects []GUID, rows []searchKeyRow) (keyDelta, error) {
	var d keyDelta
	if len(objects) == 0 {
		return d, nil
	}
	objs := make([]string, len(objects))
	for i, o := range objects {
		objs[i] = string(o)
	}
	rg := make([]string, len(rows))
	rk := make([]int16, len(rows))
	rt := make([]string, len(rows))
	for i, r := range rows {
		rg[i], rk[i], rt[i] = string(r.object), int16(r.kind), r.key
	}
	err := tx.QueryRow(ctx, writeSearchKeysSQL, string(connection), objs, rg, rk, rt, int16(searchkey.Version)).Scan(&d.inserted, &d.updated, &d.deleted)
	if err != nil {
		return d, writeErr("write search keys", err)
	}
	return d, nil
}

// writeSearchKeysSQL: $1 connection, $2 the objects whose key set is replaced, $3-$5 the wanted keys
// (object, kind, key), $6 norm_version. The delete and the insert see one snapshot, so a key both wanted
// and present is untouched, and the upsert rewrites only a row of another version.
const writeSearchKeysSQL = `WITH want AS (
		SELECT w.object_guid, w.key_kind, w.key FROM unnest($3::uuid[], $4::smallint[], $5::text[]) AS w(object_guid, key_kind, key)),
	del AS (
		DELETE FROM public.inventory_search_keys k
		WHERE k.tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND k.connection_id = $1::uuid
		AND k.object_guid = ANY($2::uuid[])
		AND NOT EXISTS (SELECT 1 FROM want w WHERE w.object_guid = k.object_guid AND w.key_kind = k.key_kind AND w.key = k.key)
		RETURNING 1),
	ins AS (
		INSERT INTO public.inventory_search_keys AS k (tenant_id, connection_id, object_guid, key_kind, key, norm_version)
		SELECT NULLIF(current_setting('app.tenant_id', true), '')::uuid, $1::uuid, w.object_guid, w.key_kind, w.key, $6::smallint FROM want w
		ON CONFLICT (tenant_id, connection_id, object_guid, key_kind, key) DO UPDATE SET norm_version = EXCLUDED.norm_version
			WHERE k.norm_version IS DISTINCT FROM EXCLUDED.norm_version
		RETURNING (xmax = 0) AS inserted)
	SELECT (SELECT count(*) FROM ins WHERE inserted), (SELECT count(*) FROM ins WHERE NOT inserted), (SELECT count(*) FROM del)`

// BackfillProgress is reported after every page of a backfill.
type BackfillProgress struct {
	// Objects is the number of objects looked at so far; Indexed the number of those that have keys.
	Objects, Indexed int
	// Inserted, Updated and Deleted count the key rows the backfill changed so far. A run over an index
	// that is already current reports zero for all three.
	Inserted, Updated, Deleted int
}

// backfillPage is the number of objects one backfill transaction reads and writes.
const backfillPage = 500

// Backfill brings the search keys of every object of the tenant up to date: an object with no keys gets
// them, a key built with an older searchkey.Version is rewritten, a key of an object that is no longer
// searchable is removed. Each object is indexed once (it walks the objects in key order, a page per
// transaction), a run over a current index changes nothing, and progress is reported after every page.
// It never reads the key table: the keys are derived from the objects, so there is no state to lose and
// it can be stopped and started again at any time.
func (r *Reader) Backfill(ctx context.Context, tid tenant.ID, progress func(BackfillProgress)) (BackfillProgress, error) {
	var total BackfillProgress
	var afterConn, afterObj string
	for {
		var done bool
		err := r.with(ctx, tid, func(ctx context.Context, tx store.Tx) error {
			var err error
			var page BackfillProgress
			page, afterConn, afterObj, done, err = backfillPageOf(ctx, tx, afterConn, afterObj)
			total.Objects += page.Objects
			total.Indexed += page.Indexed
			total.Inserted += page.Inserted
			total.Updated += page.Updated
			total.Deleted += page.Deleted
			return err
		})
		if err != nil {
			return total, err
		}
		if progress != nil {
			progress(total)
		}
		if done {
			return total, nil
		}
	}
}

func backfillPageOf(ctx context.Context, tx store.Tx, afterConn, afterObj string) (page BackfillProgress, lastConn, lastObj string, done bool, err error) {
	if err := requireTenant(ctx, tx); err != nil {
		return page, "", "", false, err
	}
	rs, err := tx.Query(ctx, backfillObjectsSQL, afterConn, afterObj, backfillPage)
	if err != nil {
		return page, "", "", false, fmt.Errorf("inventory: backfill read: %w", err)
	}
	type obj struct {
		conn string
		src  keySource
	}
	var objs []obj
	for rs.Next() {
		var o obj
		var obj_, kind, state string
		if err := rs.Scan(&o.conn, &obj_, &kind, &state, &o.src.displayName, &o.src.rdn, &o.src.sam, &o.src.upn, &o.src.dn,
			&o.src.sid, &o.src.consistencyGUID, &o.src.mail, &o.src.dnsHost); err != nil {
			rs.Close()
			return page, "", "", false, fmt.Errorf("inventory: backfill scan: %w", err)
		}
		o.src.object, o.src.kind, o.src.state = GUID(obj_), Kind(kind), ObjectState(state)
		objs = append(objs, o)
	}
	rs.Close()
	if err := rs.Err(); err != nil {
		return page, "", "", false, fmt.Errorf("inventory: backfill read: %w", err)
	}
	if len(objs) == 0 {
		return page, afterConn, afterObj, true, nil
	}
	// One write per connection of the page: the statement names one connection.
	byConn := map[string][]obj{}
	var order []string
	for _, o := range objs {
		if _, ok := byConn[o.conn]; !ok {
			order = append(order, o.conn)
		}
		byConn[o.conn] = append(byConn[o.conn], o)
	}
	for _, c := range order {
		var guids []GUID
		var rows []searchKeyRow
		for _, o := range byConn[c] {
			guids = append(guids, o.src.object)
			ks := searchKeys(o.src)
			rows = append(rows, ks...)
			if len(ks) > 0 {
				page.Indexed++
			}
		}
		d, err := writeSearchKeys(ctx, tx, ConnectionID(c), guids, rows)
		if err != nil {
			return page, "", "", false, err
		}
		page.Inserted += d.inserted
		page.Updated += d.updated
		page.Deleted += d.deleted
	}
	page.Objects = len(objs)
	last := objs[len(objs)-1]
	return page, last.conn, string(last.src.object), len(objs) < backfillPage, nil
}

// backfillObjectsSQL reads one page of objects after ($1, $2) in (connection, object) order. The two
// attributes are taken only when they are JSON strings.
const backfillObjectsSQL = `SELECT connection_id::text, object_guid::text, kind, state, COALESCE(display_name, ''), COALESCE(rdn, ''),
		COALESCE(sam_account_name, ''), COALESCE(upn, ''), COALESCE(dn, ''), sid, consistency_guid,
		CASE WHEN jsonb_typeof(attributes -> 'mail') = 'string' THEN attributes ->> 'mail' ELSE '' END,
		CASE WHEN jsonb_typeof(attributes -> 'dNSHostName') = 'string' THEN attributes ->> 'dNSHostName' ELSE '' END
	FROM public.directory_objects
	WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
	AND ($1::text = '' OR (connection_id, object_guid) > ($1::text::uuid, $2::text::uuid))
	ORDER BY connection_id, object_guid LIMIT $3`

package inventory

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/store"
)

// The reconcile (DM-19.I3, connector contract §6.5.3). A full read only upserts, and the change feed does not
// promise deletions, so an object gone from the directory would stay live in inventory forever. The caller
// lists every managed naming context by objectGUID alone and hands the listings here; a live row of those
// naming contexts that no listing holds is marked deleted, in one transaction with its edges and the closure.

// DefaultMassDeleteShare is the largest share of a connection's live objects one reconcile may mark deleted
// (20 %). A listing that would remove more is refused as a whole: an empty or truncated listing, a wrong
// scope or a DC that was reached but not authoritative looks exactly like this, and a customer's inventory
// must not be emptied by it. Only the operator may decide that a real mass deletion happened.
const DefaultMassDeleteShare = 0.20

// reconcileChunk is how many GUIDs one write statement carries.
const reconcileChunk = 1000

// ErrMassDelete is the class of *MassDeleteError.
var ErrMassDelete = errors.New("inventory: mass delete refused")

// MassDeleteError says how many live objects the reconcile would have removed. Nothing was written.
type MassDeleteError struct {
	// Gone is the number of live objects no listing held; Considered the live objects the reconcile looked at;
	// Share is the limit in force (a fraction of Considered).
	Gone, Considered int
	Share            float64
}

func (e *MassDeleteError) Error() string {
	return fmt.Sprintf("inventory: mass delete refused: %d of %d live objects would be removed (limit %.0f %%)", e.Gone, e.Considered, e.Share*100)
}

// Is makes errors.Is(err, ErrMassDelete) true.
func (e *MassDeleteError) Is(target error) bool { return target == ErrMassDelete }

// GUIDSet is a set of object GUIDs in the byte order of their canonical text, 16 bytes each (the listing of a
// 200,000-object domain is 3 MB of keys, not 200,000 strings).
type GUIDSet map[[16]byte]struct{}

// Add puts a GUID into the set.
func (s GUIDSet) Add(g [16]byte) { s[g] = struct{}{} }

// Listing is the complete list of the objects one naming context holds: every object of its subtree, the head
// included. It must be complete; the caller never builds one from a search that did not finish.
type Listing struct {
	NC      GUID
	Objects GUIDSet
}

// Reconciliation is one reconcile of one AD connection.
type Reconciliation struct {
	Connection ConnectionID
	// AsOf is when the listings began. A row observed at or after it is newer than the listings and is left
	// alone, so an object created, moved or changed while the listings ran is never removed on their account.
	AsOf time.Time
	// Now is the time the hybrid gate is judged at.
	Now time.Time
	// Listings are the managed domain naming contexts, each complete. The diff is forest-wide: an object is
	// gone only when no listing holds it, so one that moved between domains is a move (DM-16.I1).
	Listings []Listing
	// MaxDeleteShare is the mass-delete limit as a fraction of the live objects, in (0, 1]; 0 is
	// DefaultMassDeleteShare.
	MaxDeleteShare float64
	// PurgeAfter turns a deleted or recycled object that is still absent into purged once it has been
	// unobserved this long (the caller's tombstone lifetime, plus the deleted-object lifetime when the
	// Recycle Bin is on, DM-09). 0 never purges: the reconcile cannot see tombstones, so it cannot tell a
	// purged object from a tombstone on its own.
	PurgeAfter time.Duration
}

// Reconciled is what a reconcile did.
type Reconciled struct {
	// Considered is the number of live objects of the listed naming contexts older than AsOf.
	Considered int
	// Gone is how many of them no listing held and are now deleted. Purged is how many deleted or recycled
	// objects became purged.
	Gone, Purged int
	// Relocated counts live objects stored under one naming context that another listing holds: a
	// cross-domain move the reconcile saw but does not carry out. They are untouched; the next read of the
	// destination domain, or the feed, moves the row.
	Relocated int
	// EdgesRemoved counts the member and primary-group edges removed because an end of them is gone.
	EdgesRemoved int
	// Ingested is the closure refresh and gate run that followed, zero when nothing changed.
	Ingested Ingested
}

// Reconcile marks the live objects of the listed naming contexts that no listing holds as deleted, removes
// the edges that end at them, marks their groups for a closure recompute, runs the closure refresh and the
// hybrid gate, and promotes long-absent tombstones to purged, all in the caller's tenant transaction under the
// connection's writer lock. A reconcile that would remove more than the mass-delete share writes nothing and
// returns *MassDeleteError.
//
// Rows outside the listed naming contexts, naming context heads, and rows observed at or after AsOf are never
// touched. A deleted object is not removed from the search index (it is still found, as deleted); a purged one is.
func (g Ingester) Reconcile(ctx context.Context, tx store.Tx, in Reconciliation) (Reconciled, error) {
	var out Reconciled
	if g.Classifier == nil {
		return out, ErrNoClassifier
	}
	share, err := in.validate()
	if err != nil {
		return out, err
	}
	if err := requireTenant(ctx, tx); err != nil {
		return out, err
	}
	if err := lockConnection(ctx, tx, in.Connection); err != nil {
		return out, err
	}
	var kind string
	if err := tx.QueryRow(ctx, `SELECT kind FROM public.connections
		WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND id = $1::uuid`, string(in.Connection)).Scan(&kind); err != nil {
		if store.IsNoRows(err) {
			return out, ErrUnknownConnection
		}
		return out, fmt.Errorf("inventory: connection kind: %w", err)
	}
	if kind != connKindADForest {
		return out, ErrInvalid
	}
	var future bool
	if err := tx.QueryRow(ctx, `SELECT $1::timestamptz > now() + $2::interval`, in.AsOf.UTC(), fmt.Sprintf("%d seconds", int(clockSkewAllowance.Seconds()))).Scan(&future); err != nil {
		return out, writeErr("reconcile as-of", err)
	}
	if future {
		return out, fmt.Errorf("%w: reconcile as-of is in the future", ErrInvalid)
	}

	gone, purge, err := in.diff(ctx, tx, &out)
	if err != nil {
		return out, err
	}
	if float64(len(gone)) > share*float64(out.Considered) {
		return Reconciled{}, &MassDeleteError{Gone: len(gone), Considered: out.Considered, Share: share}
	}

	for _, ch := range chunks(gone, reconcileChunk) {
		tag, err := tx.Exec(ctx, `UPDATE public.directory_objects SET state = 'deleted', observed_at = $3
			WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND connection_id = $1::uuid
			AND object_guid = ANY($2::uuid[]) AND state = 'live' AND observed_at < $3`, string(in.Connection), ch, in.AsOf.UTC())
		if err != nil {
			return out, writeErr("mark deleted", err)
		}
		out.Gone += int(tag.RowsAffected())
	}
	for _, ch := range chunks(purge, reconcileChunk) {
		tag, err := tx.Exec(ctx, `UPDATE public.directory_objects SET state = 'purged', observed_at = $3
			WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND connection_id = $1::uuid
			AND object_guid = ANY($2::uuid[]) AND state IN ('deleted', 'recycled') AND observed_at < $3`, string(in.Connection), ch, in.AsOf.UTC())
		if err != nil {
			return out, writeErr("mark purged", err)
		}
		out.Purged += int(tag.RowsAffected())
		objs := make([]GUID, len(ch))
		for i, s := range ch {
			objs[i] = GUID(s)
		}
		// A purged object leaves the search index; writeSearchKeys with no wanted keys deletes them.
		if _, err := writeSearchKeys(ctx, tx, in.Connection, objs, nil); err != nil {
			return out, err
		}
	}
	// Edges end at deleted and purged objects alike (a tombstone read by the feed keeps the edges of a group
	// that had members), and every group touched is a closure root to recompute.
	for _, ch := range chunks(append(append([]string(nil), gone...), purge...), reconcileChunk) {
		var n int
		if err := tx.QueryRow(ctx, removeEdgesSQL, string(in.Connection), ch, in.AsOf.UTC()).Scan(&n); err != nil {
			return out, writeErr("remove edges of gone objects", err)
		}
		out.EdgesRemoved += n
	}
	if out.Gone == 0 && out.Purged == 0 {
		return out, nil
	}
	// The closure the datasets read and the hybrid gate (a correlation whose AD side is gone breaks) follow
	// in this transaction: the ingester's own refresh, over a cycle with no observation.
	out.Ingested, err = g.Ingest(ctx, tx, Cycle{Connection: in.Connection, Observed: in.AsOf, Now: in.Now})
	return out, err
}

// removeEdgesSQL: $1 connection, $2 the gone objects, $3 the as-of. Every active edge with a gone object at
// either end is removed (a gone group's own members, the groups it was a member of, a gone user's
// memberships, a primary-group edge), and each group that lost an edge, and each gone group, is marked dirty.
const removeEdgesSQL = `WITH edge AS (
		UPDATE public.links SET state = 'removed', observed_at = GREATEST(observed_at, $3)
		WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND connection_id = $1::uuid AND state = 'active'
		AND (source_guid = ANY($2::uuid[]) OR target_guid = ANY($2::uuid[]))
		RETURNING tenant_id, connection_id, source_guid),
	dirty AS (
		INSERT INTO public.inventory_group_closure_dirty (tenant_id, connection_id, group_guid)
		SELECT DISTINCT tenant_id, connection_id, source_guid FROM edge
		UNION
		SELECT tenant_id, connection_id, object_guid FROM public.directory_objects
		WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND connection_id = $1::uuid
		AND object_guid = ANY($2::uuid[]) AND kind = 'group'
		ON CONFLICT DO NOTHING
		RETURNING 1)
	SELECT (SELECT count(*) FROM edge)`

func (in Reconciliation) validate() (share float64, err error) {
	if _, ok := canon(string(in.Connection)); !ok || string(in.Connection) != lower(string(in.Connection)) || in.AsOf.IsZero() || in.Now.IsZero() {
		return 0, ErrInvalid
	}
	if len(in.Listings) == 0 || in.PurgeAfter < 0 {
		return 0, ErrInvalid
	}
	share = in.MaxDeleteShare
	switch {
	case share == 0:
		share = DefaultMassDeleteShare
	case share < 0 || share > 1:
		return 0, ErrInvalid
	}
	seen := map[GUID]bool{}
	for _, l := range in.Listings {
		if !validGUID(l.NC) || seen[l.NC] || l.Objects == nil {
			return 0, ErrInvalid
		}
		seen[l.NC] = true
	}
	return share, nil
}

// diff reads the stored rows of the listed naming contexts and sorts them against the listings: the live
// ones no listing holds (gone), the tombstones long unobserved and still absent (purge), and counts the live
// ones a listing of another naming context holds (Relocated). It reads each row once, in a stream, and
// keeps only the GUIDs it will write.
func (in Reconciliation) diff(ctx context.Context, tx store.Tx, out *Reconciled) (gone, purge []string, err error) {
	ncs := make([]string, len(in.Listings))
	for i, l := range in.Listings {
		ncs[i] = string(l.NC)
	}
	var purgeBefore any // NULL: never purge
	if in.PurgeAfter > 0 {
		purgeBefore = in.AsOf.UTC().Add(-in.PurgeAfter)
	}
	rows, err := tx.Query(ctx, `SELECT object_guid::text, nc_guid::text, state, ($4::timestamptz IS NOT NULL AND observed_at <= $4::timestamptz)
		FROM public.directory_objects
		WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND connection_id = $1::uuid
		AND nc_guid = ANY($2::uuid[]) AND object_guid <> nc_guid AND state IN ('live', 'deleted', 'recycled') AND observed_at < $3`,
		string(in.Connection), ncs, in.AsOf.UTC(), purgeBefore)
	if err != nil {
		return nil, nil, fmt.Errorf("inventory: reconcile: stored objects: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var obj, nc, state string
		var old bool
		if err := rows.Scan(&obj, &nc, &state, &old); err != nil {
			return nil, nil, fmt.Errorf("inventory: reconcile: stored objects: %w", err)
		}
		k, ok := guidKey(obj)
		if !ok {
			return nil, nil, ErrCorrupt
		}
		held := ""
		for _, l := range in.Listings {
			if _, ok := l.Objects[k]; ok {
				held = string(l.NC)
				if held == nc {
					break // listed where it is stored: nothing more to learn
				}
			}
		}
		switch {
		case state == string(ObjLive):
			out.Considered++
			switch {
			case held == "":
				gone = append(gone, obj)
			case held != nc:
				out.Relocated++
			}
		case held == "" && old:
			purge = append(purge, obj)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("inventory: reconcile: stored objects: %w", err)
	}
	return gone, purge, nil
}

// guidKey is the 16 bytes of a canonical text GUID.
func guidKey(s string) (k [16]byte, ok bool) {
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return k, false
	}
	b, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	if err != nil || len(b) != 16 {
		return k, false
	}
	copy(k[:], b)
	return k, true
}

// chunks splits s into slices of at most n.
func chunks(s []string, n int) [][]string {
	var out [][]string
	for len(s) > 0 {
		m := min(n, len(s))
		out = append(out, s[:m])
		s = s[m:]
	}
	return out
}

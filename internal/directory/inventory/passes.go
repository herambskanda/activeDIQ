package inventory

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// DefaultStalenessThreshold is how old the last successful pass of a naming context may be before a
// report calls it stale (spec Q6, reports.md §6.4). [PROPOSED] 60 minutes: six times the 10-minute
// sync cadence, so one missed cycle is not an alarm and a dead feed is.
const DefaultStalenessThreshold = 60 * time.Minute

// MaxFreshnessConnections bounds the connections of one Freshness call.
const MaxFreshnessConnections = 1000

// PassState is what the sync last told inventory about a naming context's change feed.
type PassState string

// The states MarkNC records. ok is not among them: only RecordPass, which carries a pass time, sets it.
const (
	PassResyncRequired PassState = "resync_required" // the cookie is unusable (DM-19.I3, I4)
	PassPaused         PassState = "paused"
)

// RecordPass records that a sync pass of the naming context completed, as of asOf (the start of the
// read, Cycle.Observed). It is the D6 watermark: written whether or not the pass changed anything, so a
// quiet domain stays fresh, and it clears resync_required and paused. It runs in the caller's tenant
// transaction, the one that stored the pass's inventory rows (DM-19.I1).
//
// A pass older than the one already recorded is ErrStale and records nothing: a watermark never moves
// back. A pass in the future is ErrInvalid.
func (Writer) RecordPass(ctx context.Context, tx store.Tx, connection ConnectionID, nc GUID, asOf time.Time) error {
	if err := validPassRef(connection, nc); err != nil {
		return err
	}
	if asOf.IsZero() {
		return ErrInvalid
	}
	if err := requireTenant(ctx, tx); err != nil {
		return err
	}
	var future bool
	if err := tx.QueryRow(ctx, `SELECT $1::timestamptz > now() + $2::interval`, asOf.UTC(), fmt.Sprintf("%d seconds", int(clockSkewAllowance.Seconds()))).Scan(&future); err != nil {
		return writeErr("pass as-of", err)
	}
	if future {
		return fmt.Errorf("%w: pass as-of is in the future", ErrInvalid)
	}
	tag, err := tx.Exec(ctx, `INSERT INTO public.nc_sync_passes AS p (tenant_id, connection_id, nc_guid, last_pass_at, state)
		VALUES (NULLIF(current_setting('app.tenant_id', true), '')::uuid, $1::uuid, $2::uuid, $3, 'ok')
		ON CONFLICT (tenant_id, connection_id, nc_guid) DO UPDATE
		SET last_pass_at = EXCLUDED.last_pass_at, state = 'ok',
		    state_changed_at = CASE WHEN p.state = 'ok' THEN p.state_changed_at ELSE now() END
		WHERE p.last_pass_at IS NULL OR p.last_pass_at <= EXCLUDED.last_pass_at`,
		string(connection), string(nc), asOf.UTC())
	if err != nil {
		return writeErr("record pass", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrStale
	}
	return nil
}

// MarkNC records that the naming context's feed is resync_required or paused. The last pass time is
// kept: it is still the age of the data. A naming context that has never completed a pass keeps no
// pass time and reads as never synced.
func (Writer) MarkNC(ctx context.Context, tx store.Tx, connection ConnectionID, nc GUID, state PassState) error {
	if err := validPassRef(connection, nc); err != nil {
		return err
	}
	if state != PassResyncRequired && state != PassPaused {
		return ErrInvalid
	}
	if err := requireTenant(ctx, tx); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO public.nc_sync_passes AS p (tenant_id, connection_id, nc_guid, state)
		VALUES (NULLIF(current_setting('app.tenant_id', true), '')::uuid, $1::uuid, $2::uuid, $3)
		ON CONFLICT (tenant_id, connection_id, nc_guid) DO UPDATE
		SET state = EXCLUDED.state,
		    state_changed_at = CASE WHEN p.state = EXCLUDED.state THEN p.state_changed_at ELSE now() END`,
		string(connection), string(nc), string(state)); err != nil {
		return writeErr("mark naming context", err)
	}
	return nil
}

func validPassRef(connection ConnectionID, nc GUID) error {
	c, ok := canon(string(connection))
	n, ok2 := canon(string(nc))
	if !ok || !ok2 || c != string(connection) || n != string(nc) {
		return ErrInvalid
	}
	return nil
}

// FreshnessQuery names the connections a result covers and the time it is judged at.
type FreshnessQuery struct {
	// Connections are the connections the scope reaches. At least one.
	Connections []ConnectionID
	// Now is the judging time; the zero time is invalid (the function is pure in it).
	Now time.Time
	// Threshold is the staleness threshold; zero means DefaultStalenessThreshold.
	Threshold time.Duration
}

// FreshnessResult is the D6 answer: the watermark of every covered naming context and the label
// computed from them.
type FreshnessResult struct {
	// Watermarks has one entry per naming context, ordered by connection then NC. A
	// connection that has no naming context row yet has one entry with a zero NC and state never synced.
	Watermarks []report.NCWatermark
	// Label is report.Label over Watermarks: AsOf is the oldest last pass among the naming contexts that
	// have one; Stale names each stale NC with its age and cause; NotSynced lists the skipped connections.
	Label     report.Freshness
	Threshold time.Duration
	// Names is the display name of every covered connection, so a stale label can name the directory
	// behind it. It holds one entry per distinct connection asked for.
	Names map[ConnectionID]string
}

// Freshness returns the watermarks of the covered connections' naming contexts and their label. The
// watermark is the last successful sync pass (RecordPass), not the last change, so a directory with no
// changes for a day but a recent pass is not stale. A naming context in resync_required or paused, or
// whose connection is suspended, is stale with its age; the others are still reported. A connection that
// never completed a first sync is listed as skipped and is not part of the oldest watermark.
//
// Every statement runs in one tenant transaction, so the answer is a consistent snapshot. A connection
// the tenant does not have is ErrUnknownConnection: it is never silently dropped from a freshness claim.
func (r *Reader) Freshness(ctx context.Context, tid tenant.ID, q FreshnessQuery) (FreshnessResult, error) {
	var out FreshnessResult
	if q.Now.IsZero() || q.Threshold < 0 || len(q.Connections) == 0 {
		return out, ErrInvalid
	}
	if len(q.Connections) > MaxFreshnessConnections {
		return out, ErrTooMany
	}
	threshold := q.Threshold
	if threshold == 0 {
		threshold = DefaultStalenessThreshold
	}
	seen := map[ConnectionID]bool{}
	ids := make([]string, 0, len(q.Connections))
	for _, c := range q.Connections {
		if s, ok := canon(string(c)); !ok || s != string(c) {
			return out, ErrInvalid
		}
		if !seen[c] {
			seen[c] = true
			ids = append(ids, string(c))
		}
	}
	sort.Strings(ids)

	var ws []report.NCWatermark
	names := make(map[ConnectionID]string, len(ids))
	err := r.with(ctx, tid, func(ctx context.Context, tx store.Tx) error {
		rows, err := tx.Query(ctx, `SELECT c.id::text, c.state, c.display_name, COALESCE(p.nc_guid::text, ''), p.last_pass_at, COALESCE(p.state, '')
			FROM public.connections c
			LEFT JOIN public.nc_sync_passes p ON p.tenant_id = c.tenant_id AND p.connection_id = c.id
			WHERE c.tenant_id = $1::uuid AND c.id = ANY($2::uuid[])
			ORDER BY c.id, p.nc_guid`, tid.String(), ids)
		if err != nil {
			return fmt.Errorf("inventory: watermarks: %w", err)
		}
		defer rows.Close()
		found := map[string]bool{}
		for rows.Next() {
			var conn, connState, name, nc, state string
			var pass *time.Time
			if err := rows.Scan(&conn, &connState, &name, &nc, &pass, &state); err != nil {
				return fmt.Errorf("inventory: watermarks: %w", err)
			}
			found[conn] = true
			names[ConnectionID(conn)] = name
			w, err := watermark(conn, connState, nc, pass, state)
			if err != nil {
				return err
			}
			ws = append(ws, w)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("inventory: watermarks: %w", err)
		}
		for _, id := range ids {
			if !found[id] {
				return ErrUnknownConnection
			}
		}
		return nil
	})
	if err != nil {
		return FreshnessResult{}, err
	}
	out.Watermarks = ws
	out.Threshold = threshold
	out.Names = names
	out.Label = report.Label(ws, threshold, q.Now)
	return out, nil
}

// watermark maps one stored row to the report type. Anything outside the declared domain is ErrCorrupt.
func watermark(conn, connState, nc string, pass *time.Time, state string) (report.NCWatermark, error) {
	c, err := authz.ParseObjectID(conn)
	if err != nil {
		return report.NCWatermark{}, ErrCorrupt
	}
	w := report.NCWatermark{Connection: c}
	if nc == "" { // no naming context row: the connection has not completed a first sync
		w.State = report.NCNeverSynced
		return w, nil
	}
	if w.NC, err = authz.ParseObjectID(nc); err != nil {
		return report.NCWatermark{}, ErrCorrupt
	}
	if pass == nil {
		w.State = report.NCNeverSynced
		return w, nil
	}
	w.LastPassAt = pass.UTC()
	switch {
	case connState == "suspended" || state == string(PassPaused):
		w.State = report.NCPaused
	case state == string(PassResyncRequired):
		w.State = report.NCResyncRequired
	case state == "ok":
		w.State = report.NCOK
	default:
		return report.NCWatermark{}, ErrCorrupt
	}
	return w, nil
}

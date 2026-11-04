package inventory

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/attr/filetime"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tablekind"
)

var _ = tablekind.Declare(tablekind.Table{Name: "public.inventory_domain_policies", Entity: "DM-16", Kind: tablekind.Directory})
var _ = tablekind.Declare(tablekind.Table{Name: "public.inventory_psos", Entity: "DM-16", Kind: tablekind.Directory})
var _ = tablekind.Declare(tablekind.Table{Name: "public.inventory_pso_applies", Entity: "DM-16", Kind: tablekind.Directory})

// PolicyWriter stores the D4 policy inputs of the derived states (reports spec §6.4): the domain
// password and lockout policy per naming context, the Password Settings Objects and the
// msDS-PSOAppliesTo edges. Like Writer it runs in the caller's tenant transaction and decides nothing
// about who may call it. A nil interval is "not read", which the report shows as Unknown (input
// missing); the writer never fills one in.
//
// Intervals arrive decoded by the one codec (filetime.DecodeInterval), so a value the codec refuses
// (a positive interval, a maxPwdAge of 0) has no representation here and stays "not read".
type PolicyWriter struct{}

// DomainPolicy is the policy of one naming context.
type DomainPolicy struct {
	MaxPwdAge, LockoutDuration *filetime.Interval
	// LogonSyncIntervalDays is msDS-LogonTimeSyncInterval (nil: not read; the attribute's default
	// applies in the directory but is not assumed here).
	LogonSyncIntervalDays *int
	// PSOsReadAt is when the domain's PSO set was last read in full (zero: never). Without it no
	// user of the domain can be said to have no PSO.
	PSOsReadAt time.Time
}

// PSO is one Password Settings Object's values.
type PSO struct {
	// Precedence is msDS-PasswordSettingsPrecedence (nil: not read; a PSO without it cannot win).
	Precedence                 *int64
	MaxPwdAge, LockoutDuration *filetime.Interval
}

// intervalSecs stores an interval in whole seconds, rounded up so a sub-second span is not "forever":
// 0 is Forever (never expires, or locked until an admin unlocks). nil is not read.
func intervalSecs(i *filetime.Interval) (any, error) {
	if i == nil {
		return nil, nil
	}
	if i.Forever {
		return int64(0), nil
	}
	if i.Ticks <= 0 {
		return nil, fmt.Errorf("%w: interval without a positive length", ErrInvalid)
	}
	const perSecond = 10_000_000
	return (i.Ticks + perSecond - 1) / perSecond, nil
}

func (PolicyWriter) check(ctx context.Context, tx store.Tx, c ConnectionID, ids ...GUID) error {
	if _, ok := canon(string(c)); !ok || string(c) != lower(string(c)) {
		return ErrInvalid
	}
	for _, g := range ids {
		if !validGUID(g) {
			return ErrInvalid
		}
	}
	return requireTenant(ctx, tx)
}

// SetDomainPolicy records the policy of naming context nc as read at observed. An older observation
// than the stored one is ignored.
func (w PolicyWriter) SetDomainPolicy(ctx context.Context, tx store.Tx, connection ConnectionID, nc GUID, p DomainPolicy, observed time.Time) error {
	if err := w.check(ctx, tx, connection, nc); err != nil {
		return err
	}
	if observed.IsZero() || (p.LogonSyncIntervalDays != nil && (*p.LogonSyncIntervalDays < 0 || *p.LogonSyncIntervalDays > 3650)) {
		return ErrInvalid
	}
	age, err := intervalSecs(p.MaxPwdAge)
	if err != nil {
		return err
	}
	dur, err := intervalSecs(p.LockoutDuration)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO public.inventory_domain_policies AS d (tenant_id, connection_id, nc_guid, max_pwd_age_secs, lockout_duration_secs,
			logon_sync_interval_days, psos_read_at, observed_at)
		VALUES (NULLIF(current_setting('app.tenant_id', true), '')::uuid, $1::uuid, $2::uuid, $3::bigint, $4::bigint, $5::int, $6::timestamptz, $7)
		ON CONFLICT (tenant_id, connection_id, nc_guid) DO UPDATE SET max_pwd_age_secs = EXCLUDED.max_pwd_age_secs,
			lockout_duration_secs = EXCLUDED.lockout_duration_secs, logon_sync_interval_days = EXCLUDED.logon_sync_interval_days,
			psos_read_at = EXCLUDED.psos_read_at, observed_at = EXCLUDED.observed_at
		WHERE d.observed_at <= EXCLUDED.observed_at`,
		string(connection), string(nc), age, dur, p.LogonSyncIntervalDays, nullTime(p.PSOsReadAt), observed.UTC())
	if err != nil {
		return writeErr("set domain policy", err)
	}
	return nil
}

// SetPSO records a PSO of naming context nc. The PSO is also a directory object (DM-16), written by
// Populate; its name comes from that row, never from here.
func (w PolicyWriter) SetPSO(ctx context.Context, tx store.Tx, connection ConnectionID, pso, nc GUID, p PSO, observed time.Time) error {
	if err := w.check(ctx, tx, connection, pso, nc); err != nil {
		return err
	}
	if observed.IsZero() || (p.Precedence != nil && *p.Precedence < 1) {
		return ErrInvalid
	}
	age, err := intervalSecs(p.MaxPwdAge)
	if err != nil {
		return err
	}
	dur, err := intervalSecs(p.LockoutDuration)
	if err != nil {
		return err
	}
	// A new PSO row starts its counter at the edges already stored for it (edges may arrive before the values;
	// there are at most psoAppliesPerPSO of them).
	_, err = tx.Exec(ctx, `INSERT INTO public.inventory_psos AS d (tenant_id, connection_id, pso_guid, nc_guid, precedence, max_pwd_age_secs, lockout_duration_secs, observed_at, applies_count)
		VALUES (NULLIF(current_setting('app.tenant_id', true), '')::uuid, $1::uuid, $2::uuid, $3::uuid, $4::bigint, $5::bigint, $6::bigint, $7,
			(SELECT count(*) FROM public.inventory_pso_applies a WHERE a.tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
				AND a.connection_id = $1::uuid AND a.pso_guid = $2::uuid AND a.state = 'active'))
		ON CONFLICT (tenant_id, connection_id, pso_guid) DO UPDATE SET nc_guid = EXCLUDED.nc_guid, precedence = EXCLUDED.precedence,
			max_pwd_age_secs = EXCLUDED.max_pwd_age_secs, lockout_duration_secs = EXCLUDED.lockout_duration_secs, observed_at = EXCLUDED.observed_at
		WHERE d.observed_at <= EXCLUDED.observed_at`,
		string(connection), string(pso), string(nc), p.Precedence, age, dur, observed.UTC())
	if err != nil {
		return writeErr("set pso", err)
	}
	return nil
}

// SetPSOApplies records msDS-PSOAppliesTo pso → target (a user or a group) as active.
func (w PolicyWriter) SetPSOApplies(ctx context.Context, tx store.Tx, connection ConnectionID, pso, target GUID, observed time.Time) error {
	return w.applies(ctx, tx, connection, pso, target, "active", observed)
}

// RemovePSOApplies marks the edge removed (edges are never deleted).
func (w PolicyWriter) RemovePSOApplies(ctx context.Context, tx store.Tx, connection ConnectionID, pso, target GUID, observed time.Time) error {
	return w.applies(ctx, tx, connection, pso, target, "removed", observed)
}

// Row budget of inventory_pso_applies (TM-D32). A PSO is normally written by a Domain Admin, but a delegate
// with write on one PSO chooses how many msDS-PSOAppliesTo values it holds. The caps are constants, not
// settings the directory can reach: past either, further active edges are not stored and the PSO is marked
// applies_over_budget, which the users dataset reads as Unknown for the PSO's naming context. The cycle
// commits.
const (
	psoAppliesPerPSO  = 10_000
	psoAppliesPerConn = 100_000
)

var psoApplies = struct{ perPSO, perConn int }{psoAppliesPerPSO, psoAppliesPerConn}

// ErrPSONotStored: an msDS-PSOAppliesTo edge past the budget arrived for a PSO whose values were not stored
// yet, so there is no row to carry the over-budget marker. Call SetPSO before the PSO's edges.
var ErrPSONotStored = errors.New("inventory: PSO values must be stored before an edge past the applies budget")

func (w PolicyWriter) applies(ctx context.Context, tx store.Tx, connection ConnectionID, pso, target GUID, state string, observed time.Time) error {
	if err := w.check(ctx, tx, connection, pso, target); err != nil {
		return err
	}
	if observed.IsZero() {
		return ErrInvalid
	}
	var (
		stored  *int
		perConn int
		prev    string
	)
	if err := tx.QueryRow(ctx, `SELECT (SELECT p.applies_count FROM public.inventory_psos p WHERE p.tenant_id = t.id AND p.connection_id = $1::uuid AND p.pso_guid = $2::uuid),
			(SELECT COALESCE(sum(p.applies_count), 0) FROM public.inventory_psos p WHERE p.tenant_id = t.id AND p.connection_id = $1::uuid),
			COALESCE((SELECT a.state FROM public.inventory_pso_applies a WHERE a.tenant_id = t.id AND a.connection_id = $1::uuid
				AND a.pso_guid = $2::uuid AND a.target_guid = $3::uuid), '')
		FROM (SELECT NULLIF(current_setting('app.tenant_id', true), '')::uuid AS id) t`,
		string(connection), string(pso), string(target)).Scan(&stored, &perConn, &prev); err != nil {
		return writeErr("read pso applies budget", err)
	}
	newActive := state == "active" && prev != "active"
	if newActive {
		var count int
		if stored != nil {
			count = *stored
		} else if err := tx.QueryRow(ctx, `SELECT count(*) FROM (SELECT 1 FROM public.inventory_pso_applies a
			WHERE a.tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND a.connection_id = $1::uuid
			AND a.pso_guid = $2::uuid AND a.state = 'active' LIMIT $3) s`, string(connection), string(pso), psoApplies.perPSO).Scan(&count); err != nil {
			return writeErr("count pso applies", err)
		}
		if count >= psoApplies.perPSO || perConn >= psoApplies.perConn {
			if stored == nil {
				return ErrPSONotStored
			}
			return markAppliesOver(ctx, tx, connection, pso, true)
		}
	}
	err := tx.QueryRow(ctx, `INSERT INTO public.inventory_pso_applies AS d (tenant_id, connection_id, pso_guid, target_guid, state, observed_at)
		VALUES (NULLIF(current_setting('app.tenant_id', true), '')::uuid, $1::uuid, $2::uuid, $3::uuid, $5, $4)
		ON CONFLICT (tenant_id, connection_id, pso_guid, target_guid) DO UPDATE SET state = EXCLUDED.state, observed_at = EXCLUDED.observed_at
		WHERE d.observed_at <= EXCLUDED.observed_at RETURNING 1`,
		string(connection), string(pso), string(target), observed.UTC(), state).Scan(new(int))
	if store.IsNoRows(err) {
		return nil // an older observation than the stored one: nothing changed
	}
	if err != nil {
		return writeErr("set pso applies", err)
	}
	delta := 0
	if newActive {
		delta = 1
	} else if state == "removed" && prev == "active" {
		delta = -1
	}
	if delta != 0 {
		if _, err := tx.Exec(ctx, `UPDATE public.inventory_psos SET applies_count = applies_count + $3
			WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND connection_id = $1::uuid AND pso_guid = $2::uuid`,
			string(connection), string(pso), delta); err != nil {
			return writeErr("count pso applies", err)
		}
	}
	return nil
}

// SetPSOAppliesRead tells the writer how many msDS-PSOAppliesTo values the directory holds for pso right now.
// The over-budget marker is set from that number alone (more than the per-PSO cap), so it clears when the
// directory is brought back under the cap and does not depend on what earlier cycles stored. A PSO that is
// not stored is ignored (its values are Unknown already).
func (w PolicyWriter) SetPSOAppliesRead(ctx context.Context, tx store.Tx, connection ConnectionID, pso GUID, values int) error {
	if err := w.check(ctx, tx, connection, pso); err != nil {
		return err
	}
	if values < 0 {
		return ErrInvalid
	}
	return markAppliesOver(ctx, tx, connection, pso, values > psoApplies.perPSO)
}

func markAppliesOver(ctx context.Context, tx store.Tx, connection ConnectionID, pso GUID, over bool) error {
	if _, err := tx.Exec(ctx, `UPDATE public.inventory_psos SET applies_over_budget = $3
		WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND connection_id = $1::uuid AND pso_guid = $2::uuid
		AND applies_over_budget <> $3`, string(connection), string(pso), over); err != nil {
		return writeErr("mark pso applies over budget", err)
	}
	return nil
}

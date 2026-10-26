package authn

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/audit/chain"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// MinSessionRetention is the shortest time an ended session row is kept: the audit trail refers to the
// handle, and an investigation after a weekend should still find the row.
const MinSessionRetention = 24 * time.Hour

// DefaultSessionRetention is the retention a Purger uses when none is set.
const DefaultSessionRetention = 90 * 24 * time.Hour

// ErrRetention is returned for a retention shorter than MinSessionRetention.
var ErrRetention = errors.New("authn: session retention is too short")

// Purger deletes ended sessions older than the retention. The runtime role has no DELETE on
// authn_sessions, so a Purger runs on the maintenance path with a store opened by store.OpenMaintenance
// as the owner role. It never touches an active session.
type Purger struct {
	owner     *store.DB
	sink      audit.Sink
	retention time.Duration
	clock     func() time.Time
}

// NewPurger returns a Purger. sink must be bound to owner (audit.NewChainer(owner)) so the purge's own
// event is chained in the purge's transaction. A zero retention means DefaultSessionRetention. clock is
// nil in production (the database clock); tests set it.
func NewPurger(owner *store.DB, sink audit.Sink, retention time.Duration, clock func() time.Time) (*Purger, error) {
	if owner == nil || sink == nil {
		return nil, errors.New("authn: Purger needs an owner-role store and an audit sink")
	}
	if retention == 0 {
		retention = DefaultSessionRetention
	}
	if retention < MinSessionRetention {
		return nil, ErrRetention
	}
	return &Purger{owner: owner, sink: sink, retention: retention, clock: clock}, nil
}

// Purge deletes the tenant's sessions that ended more than the retention ago, and records
// authn.sessions.purged (count and cutoff, nothing about the sessions) in the same transaction. It
// returns how many rows it deleted.
func (p *Purger) Purge(ctx context.Context, t tenant.ID, by authority.Chain) (int, error) {
	if t.IsZero() || by.Validate() != nil {
		return 0, ErrInvalid
	}
	var n int
	err := p.owner.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		var now time.Time
		if p.clock != nil {
			now = p.clock().UTC()
		} else if err := tx.QueryRow(ctx, sqlClock).Scan(&now); err != nil {
			return err
		}
		cutoff := now.Add(-p.retention)
		tag, err := tx.Exec(ctx, `DELETE FROM public.authn_sessions WHERE tenant_id = $1 AND state <> 'active' AND ended_at < $2`, t.String(), cutoff)
		if err != nil {
			return err
		}
		n = int(tag.RowsAffected())
		if n == 0 {
			return nil
		}
		return p.sink.Append(ctx, tx, audit.Event{
			ID: "authn.sessions.purged." + strconv.FormatInt(cutoff.UnixNano(), 10), Kind: KindSessionsPurged, At: now, Actor: by,
			Target:    authority.TargetRef{GUID: t.String(), Class: "tenant"},
			Component: "authn", Outcome: audit.Success,
			Details: []chain.Detail{{Key: "cutoff", Value: cutoff.Format(time.RFC3339Nano)}, {Key: "sessions", Value: strconv.Itoa(n)}},
		})
	})
	if err != nil {
		return 0, fmt.Errorf("authn: purge sessions: %w", err)
	}
	return n, nil
}

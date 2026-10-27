package client

import (
	"context"
	"errors"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// Errors of the live refresher. None carries an object identifier or a directory message.
var (
	// ErrRefreshConnection: the connection is not a live connection of the tenant.
	ErrRefreshConnection = errors.New("client: live refresh: connection not found for this tenant")
	// ErrRefreshGone: the live read found no such object, so no fact about it is advanced.
	ErrRefreshGone = errors.New("client: live refresh: the object no longer exists")
)

// FactsStore stores the verdict of a live read on the object's correlations. inventory.Facts
// implements it.
type FactsStore interface {
	RecordLiveFacts(ctx context.Context, tid tenant.ID, ref inventory.Ref, tier0 bool, readAt time.Time) error
}

var _ FactsStore = (*inventory.Facts)(nil)

// InventoryRefresher is the LiveRefresher over the connector's reads and the inventory.
type InventoryRefresher struct {
	conns ConnectionSource
	reads Reads
	store FactsStore
	now   func() time.Time
}

var _ LiveRefresher = (*InventoryRefresher)(nil)

// NewInventoryRefresher returns the refresher. now is the clock; nil means time.Now.
func NewInventoryRefresher(conns ConnectionSource, reads Reads, st FactsStore, now func() time.Time) (*InventoryRefresher, error) {
	if conns == nil || reads == nil || st == nil {
		return nil, errors.New("client: live refresher needs a connection source, reads and a facts store")
	}
	if now == nil {
		now = time.Now
	}
	return &InventoryRefresher{conns: conns, reads: reads, store: st, now: now}, nil
}

// RefreshCorrelations implements LiveRefresher (DM-20.I5). It reads ref's tier0 verdict live, stores
// it on ref's correlations and returns the read time: the time taken before the read was issued, so
// the stored as-of can only understate freshness. The connection is resolved under tid first, so a
// ref of another tenant is refused before any directory is contacted. On any failure, including an
// object that is gone, nothing is stored and the error is returned.
func (r *InventoryRefresher) RefreshCorrelations(ctx context.Context, tid tenant.ID, ref inventory.Ref) (time.Time, error) {
	if tid.IsZero() || !ref.Valid() {
		return time.Time{}, ErrInvalidOp
	}
	conn, err := r.conns.Get(ctx, tid, connection.ID(ref.Connection))
	if err != nil || string(conn.ID) != string(ref.Connection) || conn.RetiredAt != nil {
		return time.Time{}, ErrRefreshConnection
	}
	at := r.now().UTC()
	got, err := r.reads.Object(authority.WithTenant(ctx, tid.String()), nil,
		authority.TargetRef{Connection: string(ref.Connection), GUID: string(ref.Object)}, string(ref.Object), true)
	if err != nil {
		return time.Time{}, err
	}
	if !got.Exists {
		return time.Time{}, ErrRefreshGone
	}
	if err := r.store.RecordLiveFacts(ctx, tid, ref, got.Tier0, at); err != nil {
		return time.Time{}, err
	}
	return at, nil
}

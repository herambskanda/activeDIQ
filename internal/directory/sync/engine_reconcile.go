package sync

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// Reconciler is the inventory's reconcile write side (inventory.Ingester).
type Reconciler interface {
	Reconcile(ctx context.Context, tx store.Tx, in inventory.Reconciliation) (inventory.Reconciled, error)
}

// ReconcileOptions tune one Reconcile. The zero value is the safe default.
type ReconcileOptions struct {
	// MaxDeleteShare is the largest fraction of the live objects one reconcile may mark deleted; 0 is
	// inventory.DefaultMassDeleteShare (20 %).
	MaxDeleteShare float64
	// PurgeAfter promotes a deleted or recycled object that is still absent to purged once it has been
	// unobserved this long; 0 never purges (see inventory.Reconciliation.PurgeAfter).
	PurgeAfter time.Duration
}

// ListedNC is how many objects the listing of one naming context held.
type ListedNC struct {
	NC      inventory.GUID
	Objects int
}

// ReconcileReport is the outcome of Reconcile.
type ReconcileReport struct {
	Connection inventory.ConnectionID
	// Listed is one entry per listing that finished, in the order of the managed domains.
	Listed []ListedNC
	// Completed says every managed naming context was listed to its end and the diff was committed. A
	// reconcile that returned an error is not complete, and wrote nothing.
	Completed bool
	inventory.Reconciled
}

// Reconcile infers the deletions a full read cannot see and the change feed does not promise (contract
// §6.5.3, DM-19.I3): it lists every managed domain naming context by objectGUID alone, pages each through the
// connector's ScopedSearch and keeps the GUIDs, then diffs the union against inventory in one transaction. A
// live object that no listing holds becomes deleted, its member and primary-group edges are removed and the
// closure follows, all in that transaction (inventory.Ingester.Reconcile). The diff is forest-wide, so an
// object that moved between two managed domains is a move (DM-16.I1), never a delete and a create.
//
// It runs after a FullCycle whose every domain completed, or as the fallback of a change feed for the
// deletions that feed cannot see. Safety, in order of what stops it:
//
//   - A listing that ends without its completion marker, or fails, stops the whole reconcile before any
//     write: an incomplete listing never deletes, and the pass is not complete (*DomainError, phase "list").
//   - A diff that would delete more than the mass-delete share (opts.MaxDeleteShare, default 20 %) of the live
//     objects, an empty listing included, deletes nothing and returns inventory.ErrMassDelete. The next cycle
//     is not blocked; it simply meets the same refusal until the directory and inventory agree again or the
//     operator removes what is really gone.
//   - A connection that is not active, a paused partition or a lease behind the stored fencing token stops it
//     before the connector is called, and again before the write.
//
// The listings take memory of 16 bytes per object of the forest, and are held until the write.
func (e *Engine) Reconcile(ctx context.Context, tid tenant.ID, id connection.ID, lease LeaseFunc, opts ReconcileOptions) (ReconcileReport, error) {
	rep := ReconcileReport{Connection: inventory.ConnectionID(id)}
	if err := e.ready(); err != nil {
		return rep, err
	}
	if e.Reconciler == nil || lease == nil || tid.IsZero() {
		return rep, fmt.Errorf("%w: reconciler, lease or tenant", ErrNotConfigured)
	}
	conn, err := e.Conns.Get(ctx, tid, id)
	if err != nil {
		return rep, fmt.Errorf("%w: connection: %w", ErrSource, err)
	}
	ref, err := e.refuse(conn, id)
	if err != nil {
		return rep, err
	}
	managed, err := e.Domains.ManagedDomains(ctx, tid, id)
	if err != nil {
		return rep, fmt.Errorf("%w: managed domains: %w", ErrSource, err)
	}
	domains, err := checkDomains(managed)
	if err != nil {
		return rep, err
	}
	claims, err := e.claimAll(ctx, tid, id, domains, lease)
	if err != nil {
		return rep, err
	}
	cc, pageSize, err := e.connect(ctx, id, ref, domains)
	if err != nil {
		return rep, err
	}

	asOf := e.utc()
	rj := make([]*readJob, len(claims))
	in := inventory.Reconciliation{Connection: rep.Connection, AsOf: asOf, MaxDeleteShare: opts.MaxDeleteShare, PurgeAfter: opts.PurgeAfter}
	for i, c := range claims {
		rj[i] = &readJob{e: e, tid: tid, conn: id, ref: ref, cc: cc, key: c.key, lease: c.lease, nc: c.d.NC, pageSize: pageSize, rep: &DomainReport{NC: c.d.NC}}
		if err := rj[i].stillAllowed(ctx); err != nil {
			return e.reconcileDone(rep, err)
		}
		set, err := rj[i].list(ctx)
		if err != nil {
			return e.reconcileDone(rep, rj[i].wrap(err, "list"))
		}
		in.Listings = append(in.Listings, inventory.Listing{NC: c.d.NC, Objects: set})
		rep.Listed = append(rep.Listed, ListedNC{NC: c.d.NC, Objects: len(set)})
	}
	// The listings can take minutes: the connection may have been suspended or the lease taken over since.
	for _, j := range rj {
		if err := j.stillAllowed(ctx); err != nil {
			return e.reconcileDone(rep, err)
		}
	}
	in.Now = e.utc()
	err = e.Tenants.WithTenant(ctx, tid, func(ctx context.Context, tx store.Tx) error {
		// The compare-and-set of every partition's cursor fences a deposed holder in the transaction that deletes.
		for _, c := range claims {
			cur, err := e.Cursors.Claim(ctx, tx, c.key, c.lease)
			if err != nil {
				return err
			}
			if cur.State == StatePaused {
				return ErrPaused
			}
		}
		var err error
		rep.Reconciled, err = e.Reconciler.Reconcile(ctx, tx, in)
		return err
	})
	if err != nil {
		rep.Reconciled = inventory.Reconciled{}
		return e.reconcileDone(rep, err)
	}
	rep.Completed = true
	return e.reconcileDone(rep, nil)
}

// reconcileDone logs the outcome as counts and a fixed class, never an error text, and passes err through.
func (e *Engine) reconcileDone(rep ReconcileReport, err error) (ReconcileReport, error) {
	lvl := slog.LevelInfo
	if err != nil {
		lvl = slog.LevelWarn
	}
	attrs := []any{"completed", rep.Completed, "listed_ncs", len(rep.Listed), "considered", rep.Considered, "gone", rep.Gone,
		"purged", rep.Purged, "relocated", rep.Relocated, "edges_removed", rep.EdgesRemoved}
	if err != nil {
		phase, class := errClass(err)
		attrs = append(attrs, "error_phase", phase, "error_class", class)
	}
	e.log().Log(context.Background(), lvl, "sync: reconcile", attrs...)
	return rep, err
}

// list streams the domain asking for the objectGUID alone and returns the set of GUIDs. A stream that ends
// without its completion marker is ErrIncomplete, and an entry without a usable GUID is ErrProtocol: either
// would make a live object look gone, so the listing is refused whole.
func (r *readJob) list(ctx context.Context) (inventory.GUIDSet, error) {
	set := inventory.GUIDSet{}
	_, err := r.stream(ctx, searchSpec{attrs: []string{"objectGUID"}, pageSize: r.pageSize}, func(en *connectorv1.DirectoryEntry) error {
		v := en.GetObjectGuid().GetValue()
		if len(v) != 16 {
			return ErrProtocol
		}
		var k [16]byte
		copy(k[:], v)
		if k == ([16]byte{}) {
			return ErrProtocol
		}
		set.Add(k)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return set, nil
}

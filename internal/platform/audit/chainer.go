package audit

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit/chain"
	"github.com/skenzeriq/activediq/internal/platform/store"
)

// Errors of the chain.
var (
	// ErrNoHead is returned at commit for a tenant that was never initialised: it cannot append.
	ErrNoHead = errors.New("audit: the tenant has no chain head (InitTenant has not run): refusing to append")
	// ErrIsolation is returned when the transaction is not READ COMMITTED, which the head lock relies on.
	ErrIsolation = errors.New("audit: the chain needs a READ COMMITTED transaction")
	// ErrNoTenantTx is returned when an event is chained in a transaction with no tenant.
	ErrNoTenantTx = errors.New("audit: events are chained inside a tenant transaction only")
	// ErrStaleHead is returned when the head moved under the append (it cannot while its row lock is held).
	ErrStaleHead = errors.New("audit: the chain head changed during the append")
)

// headLockTimeout bounds the wait for the head row lock, the last lock a transaction takes.
const headLockTimeout = "5000" // milliseconds

// pending is what Append buffers in the transaction's slot until the commit hook chains it.
type pending struct{ events []Event }

// Chainer implements Sink with the per-tenant hash chain (ADR-0005 rule 11). Append buffers; the commit
// hook it installs on the store chains, so the chain's order is commit order and has no gaps.
type Chainer struct {
	slot *store.Slot[pending]
}

// NewChainer installs the chain's commit hook on db. Call it once, when the process opens the store.
func NewChainer(db *store.DB) *Chainer {
	c := &Chainer{slot: store.NewSlot[pending]()}
	db.SetBeforeCommit(c.beforeCommit)
	return c
}

var _ Sink = (*Chainer)(nil)

// Append requests ev inside tx. It commits or rolls back with the transaction. It refuses an invalid
// event, a transaction of a store without the chain hook, and a transaction that has started committing.
func (c *Chainer) Append(_ context.Context, tx store.Tx, ev Event) error {
	if err := ev.Validate(); err != nil {
		return err
	}
	if _, err := toEnvelope(ev); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidEvent, err)
	}
	return c.slot.Update(tx, func(p *pending) error {
		p.events = append(p.events, ev)
		return nil
	})
}

func toEnvelope(ev Event) (chain.Envelope, error) {
	e := chain.Envelope{
		EventID:     ev.ID,
		Kind:        string(ev.Kind),
		KindVersion: 1,
		Requester:   chain.Principal{ID: string(ev.Actor.Requester.ID), Kind: string(ev.Actor.Requester.Kind)},
		Component:   ev.Component,
		Connection:  ev.Target.Connection,
		TargetGUID:  ev.Target.GUID,
		TargetClass: ev.Target.Class,
		Parent:      ev.Target.Parent, // the RDN of a create is personal and stays out of the chain
		Outcome:     string(ev.Outcome),
		Reason:      ev.Reason,
		PlanHash:    ev.PlanHash,
	}
	for _, p := range ev.Actor.Via {
		e.Via = append(e.Via, chain.Principal{ID: string(p.ID), Kind: string(p.Kind)})
	}
	if ev.Key.Operation != "" {
		if ev.Key.Item < 0 || ev.Key.Step < 0 {
			return e, errors.New("negative item or step")
		}
		e.Operation, e.Item, e.Step, e.HasStep = string(ev.Key.Operation), uint64(ev.Key.Item), uint64(ev.Key.Step), true
	}
	// Attribute values are personal data: they go to the personal side store, not into the chain. The
	// chain records which attributes changed and how many values moved.
	for _, ch := range ev.Changes {
		e.Changes = append(e.Changes, chain.Change{Attribute: ch.Attribute, Secret: ch.Secret,
			BeforeCount: uint64(len(ch.Before)), AfterCount: uint64(len(ch.After))})
	}
	e.Details = append([]chain.Detail(nil), ev.Details...)
	if !sort.SliceIsSorted(e.Details, func(i, j int) bool { return e.Details[i].Key < e.Details[j].Key }) {
		return e, errors.New("details not in key order")
	}
	if _, err := e.Marshal(); err != nil { // catches invalid UTF-8 and duplicate keys early, at the call site
		return e, err
	}
	return e, nil
}

// beforeCommit chains the transaction's buffered events (ADR-0005 rule 11, steps 1 to 4).
func (c *Chainer) beforeCommit(ctx context.Context, tx store.Tx, tenantID string) error {
	p, ok := c.slot.Take(tx)
	if !ok || len(p.events) == 0 {
		return nil
	}
	if tenantID == "" {
		return ErrNoTenantTx
	}
	tenant, err := chain.ParseUUID(tenantID)
	if err != nil {
		return ErrNoTenantTx
	}
	var iso string
	if err := tx.QueryRow(ctx, `SELECT current_setting('transaction_isolation')`).Scan(&iso); err != nil {
		return fmt.Errorf("audit: read isolation: %w", err)
	}
	if iso != "read committed" {
		return ErrIsolation
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('lock_timeout', $1, true)`, headLockTimeout); err != nil {
		return fmt.Errorf("audit: set lock timeout: %w", err)
	}
	var seq uint64
	var hashB []byte
	var at time.Time
	err = tx.QueryRow(ctx, `SELECT seq, hash, at FROM audit_head WHERE tenant_id = $1::uuid FOR UPDATE`, tenantID).Scan(&seq, &hashB, &at)
	switch {
	case store.IsNoRows(err):
		return ErrNoHead
	case err != nil:
		return fmt.Errorf("audit: lock chain head: %w", err)
	}
	var prev chain.Hash
	copy(prev[:], hashB)
	head := seq

	seen := map[string]bool{}
	for _, ev := range p.events {
		if seen[ev.ID] {
			continue
		}
		seen[ev.ID] = true
		var dup bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM audit_event WHERE tenant_id = $1::uuid AND event_id = $2)`, tenantID, ev.ID).Scan(&dup); err != nil {
			return fmt.Errorf("audit: check event id: %w", err)
		}
		if dup { // a retried append after an ambiguous COMMIT: already recorded
			continue
		}
		if err := tx.QueryRow(ctx, `SELECT greatest(clock_timestamp(), $1::timestamptz)`, at).Scan(&at); err != nil {
			return fmt.Errorf("audit: read clock: %w", err)
		}
		at = at.UTC().Truncate(time.Microsecond)
		env, _ := toEnvelope(ev)
		env.Tenant, env.Seq, env.At = tenant, seq+1, at
		raw, err := env.Marshal()
		if err != nil {
			return fmt.Errorf("audit: encode event: %w", err)
		}
		h := chain.Link(tenant, env.Seq, prev, chain.BodyHash(raw))
		if _, err := tx.Exec(ctx, `INSERT INTO audit_event (tenant_id, seq, at, event_id, kind, envelope, prev_hash, hash)
			VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8)`, tenantID, env.Seq, at, ev.ID, string(ev.Kind), raw, prev[:], h[:]); err != nil {
			return fmt.Errorf("audit: insert event: %w", err)
		}
		prev, seq = h, env.Seq
	}
	if seq == head {
		return nil
	}
	tag, err := tx.Exec(ctx, `UPDATE audit_head SET seq = $2, hash = $3, at = $4 WHERE tenant_id = $1::uuid AND seq = $5`, tenantID, seq, prev[:], at, head)
	if err != nil {
		return fmt.Errorf("audit: advance chain head: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrStaleHead
	}
	return nil
}

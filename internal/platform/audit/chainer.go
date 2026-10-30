package audit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit/chain"
	"github.com/skenzeriq/activediq/internal/platform/personal"
	"github.com/skenzeriq/activediq/internal/platform/store"
	tenantpkg "github.com/skenzeriq/activediq/internal/platform/tenant"
)

// Errors of the chain.
var (
	// ErrNoHead is returned at commit for a tenant that was never initialised: it cannot append.
	ErrNoHead = errors.New("audit: the tenant has no chain head (InitTenant has not run): refusing to append")
	// ErrIsolation is returned when the transaction is not READ COMMITTED, which the head lock relies on.
	ErrIsolation = errors.New("audit: the chain needs a READ COMMITTED transaction")
	// ErrNoTenantTx is returned when an event is chained in a transaction with no tenant.
	ErrNoTenantTx = errors.New("audit: events are chained inside a tenant transaction only")
	// ErrEventIDReused is returned when an event ID is appended again with different content: dropping the
	// second record silently would lose an audit entry.
	ErrEventIDReused = errors.New("audit: event id reused with different content")
	// ErrStaleHead is returned when the head moved under the append (it cannot while its row lock is held).
	ErrStaleHead = errors.New("audit: the chain head changed during the append")
)

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
	// Attribute values are personal data: toEnvelope records which attributes changed and how many values
	// moved; the commit hook (withRefs) stores the values and adds their personal references.
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
func (c *Chainer) beforeCommit(ctx context.Context, tx store.Tx, tid tenantpkg.ID) error {
	p, ok := c.slot.Take(tx)
	if !ok || len(p.events) == 0 {
		return nil
	}
	if tid.IsZero() {
		return ErrNoTenantTx
	}
	tenantID := tid.String()
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

	seen := map[string][]byte{}
	for _, ev := range p.events {
		// The event's identity is its content without the fields the chain assigns (tenant, seq, at).
		env, _ := toEnvelope(ev) // refs are minted per attempt (random value IDs), so identity excludes them
		ident, err := env.Marshal()
		if err != nil {
			return fmt.Errorf("audit: encode event: %w", err)
		}
		if prior, ok := seen[ev.ID]; ok {
			if !bytes.Equal(prior, ident) {
				return fmt.Errorf("%w: %q", ErrEventIDReused, ev.ID)
			}
			continue
		}
		seen[ev.ID] = ident
		var stored []byte
		err = tx.QueryRow(ctx, `SELECT envelope FROM audit_event WHERE tenant_id = $1::uuid AND event_id = $2`, tenantID, ev.ID).Scan(&stored)
		switch {
		case err == nil:
			// A retried append after an ambiguous COMMIT is the same event; anything else under this
			// ID would be silently lost, so it fails the transaction.
			old, perr := chain.ParseEnvelope(stored)
			if perr != nil {
				return fmt.Errorf("audit: stored event %q: %w", ev.ID, perr)
			}
			old.Tenant, old.Seq, old.At = [16]byte{}, 0, time.Time{}
			old.Snapshots = nil
			for i := range old.Changes {
				old.Changes[i].Before, old.Changes[i].After = nil, nil
			}
			oldIdent, merr := old.Marshal()
			if merr != nil {
				return fmt.Errorf("audit: stored event %q: %w", ev.ID, merr)
			}
			if !bytes.Equal(oldIdent, ident) {
				return fmt.Errorf("%w: %q", ErrEventIDReused, ev.ID)
			}
			continue
		case !store.IsNoRows(err):
			return fmt.Errorf("audit: check event id: %w", err)
		}
		if err := tx.QueryRow(ctx, `SELECT greatest(clock_timestamp(), $1::timestamptz)`, at).Scan(&at); err != nil {
			return fmt.Errorf("audit: read clock: %w", err)
		}
		at = at.UTC().Truncate(time.Microsecond)
		if err := withRefs(ctx, tx, tid, ev, &env); err != nil {
			return err
		}
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

// Record kinds under which the Chainer files values in the personal side store.
const (
	kindBefore   = "audit.before"
	kindAfter    = "audit.after"
	kindSnapshot = "audit.snapshot"
)

// withRefs stores ev's personal values in the personal side store, inside the commit transaction, and puts
// a reference for each into env. Secret changes carry no values (AG-9) and a change with no subject is not personal; neither gets refs.
func withRefs(ctx context.Context, tx store.Tx, tid tenantpkg.ID, ev Event, env *chain.Envelope) error {
	ps := personal.New()
	put := func(subject, kind, field, value string) (chain.Ref, error) {
		r, err := ps.Put(ctx, tx, tid, subject, kind, field, value)
		if err != nil {
			return chain.Ref{}, fmt.Errorf("audit: keep personal value of %q: %w", field, err)
		}
		return chain.Ref{Subject: r.Subject, ValueID: r.ValueID, Field: r.Field, Commitment: r.Commitment}, nil
	}
	for i, ch := range ev.Changes {
		if ch.Secret || ch.Subject == "" {
			continue
		}
		for _, v := range ch.Before {
			r, err := put(ch.Subject, kindBefore, ch.Attribute, v)
			if err != nil {
				return err
			}
			env.Changes[i].Before = append(env.Changes[i].Before, r)
		}
		for _, v := range ch.After {
			r, err := put(ch.Subject, kindAfter, ch.Attribute, v)
			if err != nil {
				return err
			}
			env.Changes[i].After = append(env.Changes[i].After, r)
		}
	}
	for _, s := range ev.Snapshots {
		r, err := put(s.Subject, kindSnapshot, s.Field, s.Value)
		if err != nil {
			return err
		}
		env.Snapshots = append(env.Snapshots, r)
	}
	return nil
}

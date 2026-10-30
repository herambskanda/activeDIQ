package connection

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// Store is the SQL of DM-10. Every method takes the transaction of a store.DB.WithTenant call, so a
// caller composes several writes (a verification result and a state change) in one transaction.
// Row-level security does the tenant scoping; each method also refuses to run with no tenant context,
// instead of quietly returning nothing.
type Store struct{}

const columns = `id, kind, display_name, directory_identity, credential_id, state,
	last_verification_id, verified_at, retired_at, last_stamp_at, COALESCE(transport_security, ''), created_at, updated_at`

type scanner interface{ Scan(dest ...any) error }

func scan(r scanner) (Connection, error) {
	var c Connection
	var kind, ident, state, tr string
	var lastVer *string
	if err := r.Scan(&c.ID, &kind, &c.DisplayName, &ident, &c.CredentialID, &state,
		&lastVer, &c.VerifiedAt, &c.RetiredAt, &c.LastStampAt, &tr, &c.CreatedAt, &c.UpdatedAt); err != nil {
		return Connection{}, err
	}
	c.Kind, c.DirectoryIdentity, c.State, c.Transport = Kind(kind), DirectoryIdentity(ident), State(state), Transport(tr)
	if lastVer != nil {
		c.LastVerificationID = *lastVer
	}
	return c, nil
}

func requireTenant(ctx context.Context, tx store.Tx) error {
	var ok bool
	if err := tx.QueryRow(ctx, `SELECT NULLIF(current_setting('app.tenant_id', true), '') IS NOT NULL`).Scan(&ok); err != nil {
		return fmt.Errorf("connection: tenant context: %w", err)
	}
	if !ok {
		return ErrNoTenant
	}
	return nil
}

// Create inserts a draft (L1). The tenant is the transaction's.
func (Store) Create(ctx context.Context, tx store.Tx, n New) (Connection, error) {
	if err := n.validate(); err != nil {
		return Connection{}, err
	}
	if err := requireTenant(ctx, tx); err != nil {
		return Connection{}, err
	}
	row := tx.QueryRow(ctx, `INSERT INTO public.connections (tenant_id, kind, display_name, credential_id, transport_security)
		VALUES (NULLIF(current_setting('app.tenant_id', true), '')::uuid, $1, $2, $3::uuid, NULLIF($4, ''))
		RETURNING `+columns, string(n.Kind), n.DisplayName, string(n.CredentialID), string(n.Transport))
	c, err := scan(row)
	if err != nil {
		return Connection{}, fmt.Errorf("connection: create: %w", err)
	}
	return c, nil
}

// Get returns one connection of the tenant, or ErrNotFound.
func (Store) Get(ctx context.Context, tx store.Tx, id ID) (Connection, error) {
	if err := requireTenant(ctx, tx); err != nil {
		return Connection{}, err
	}
	if _, err := ParseID(string(id)); err != nil {
		return Connection{}, err
	}
	c, err := scan(tx.QueryRow(ctx, `SELECT `+columns+` FROM public.connections WHERE id = $1::uuid`, string(id)))
	if store.IsNoRows(err) {
		return Connection{}, ErrNotFound
	}
	if err != nil {
		return Connection{}, fmt.Errorf("connection: get: %w", err)
	}
	return c, nil
}

// maxList bounds List: a tenant has a handful of connections, and an unbounded read is a defect.
const maxList = 1000

// List returns the tenant's connections, oldest first. Discarded connections are hidden unless
// includeDiscarded (spec L9: gone from the list; the row stays so audit references resolve).
func (Store) List(ctx context.Context, tx store.Tx, includeDiscarded bool) ([]Connection, error) {
	if err := requireTenant(ctx, tx); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT `+columns+` FROM public.connections
		WHERE $1 OR state <> 'discarded' ORDER BY created_at, id LIMIT $2`, includeDiscarded, maxList)
	if err != nil {
		return nil, fmt.Errorf("connection: list: %w", err)
	}
	defer rows.Close()
	var out []Connection
	for rows.Next() {
		c, err := scan(rows)
		if err != nil {
			return nil, fmt.Errorf("connection: list: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("connection: list: %w", err)
	}
	return out, nil
}

// ListStranded returns the connections that have been verifying since before the cutoff, oldest
// first. A verifying connection has a run in flight only for the length of one connector call, so one
// that has been in the state longer than any run can last has lost its run (a crash between the
// claim and the record). Bounded like List.
func (Store) ListStranded(ctx context.Context, tx store.Tx, before time.Time) ([]Connection, error) {
	if err := requireTenant(ctx, tx); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT `+columns+` FROM public.connections
		WHERE state = 'verifying' AND updated_at < $1 ORDER BY updated_at, id LIMIT $2`, before, maxList)
	if err != nil {
		return nil, fmt.Errorf("connection: list stranded: %w", err)
	}
	defer rows.Close()
	var out []Connection
	for rows.Next() {
		c, err := scan(rows)
		if err != nil {
			return nil, fmt.Errorf("connection: list stranded: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("connection: list stranded: %w", err)
	}
	return out, nil
}

// lock reads the row FOR UPDATE with the next ordering stamp (I13): greatest(clock_timestamp(),
// last_stamp_at + 1µs), never now(), so stamps of one connection strictly increase in commit order.
func lock(ctx context.Context, tx store.Tx, id ID) (c Connection, stamp time.Time, err error) {
	if err := requireTenant(ctx, tx); err != nil {
		return Connection{}, time.Time{}, err
	}
	if _, err := ParseID(string(id)); err != nil {
		return Connection{}, time.Time{}, err
	}
	row := tx.QueryRow(ctx, `SELECT `+columns+`, greatest(clock_timestamp(), COALESCE(last_stamp_at + interval '1 microsecond', clock_timestamp()))
		FROM public.connections WHERE id = $1::uuid FOR UPDATE`, string(id))
	var kind, ident, state, tr string
	var lastVer *string
	if err := row.Scan(&c.ID, &kind, &c.DisplayName, &ident, &c.CredentialID, &state,
		&lastVer, &c.VerifiedAt, &c.RetiredAt, &c.LastStampAt, &tr, &c.CreatedAt, &c.UpdatedAt, &stamp); err != nil {
		if store.IsNoRows(err) {
			return Connection{}, time.Time{}, ErrNotFound
		}
		return Connection{}, time.Time{}, fmt.Errorf("connection: lock: %w", err)
	}
	c.Kind, c.DirectoryIdentity, c.State, c.Transport = Kind(kind), DirectoryIdentity(ident), State(state), Transport(tr)
	if lastVer != nil {
		c.LastVerificationID = *lastVer
	}
	return c, stamp, nil
}

// Transition moves a connection from → to. The pair must be a declared edge (checked before any SQL),
// and the stored state must still be from (compare-and-set under a row lock), else the state is
// unchanged and an error says why. Entering decommissioning or discarded sets retired_at (I13).
//
// Transition is the mechanical step only. The gates that decide whether to call it (the activation
// gate, I9; a qualifying resume run, I10) belong to the callers.
func (Store) Transition(ctx context.Context, tx store.Tx, id ID, from, to State) (Connection, error) {
	if !CanTransition(from, to) {
		return Connection{}, fmt.Errorf("%w: %s → %s", ErrIllegalTransition, from, to)
	}
	cur, stamp, err := lock(ctx, tx, id)
	if err != nil {
		return Connection{}, err
	}
	if cur.State != from {
		return Connection{}, fmt.Errorf("%w: expected %s, is %s", ErrStateConflict, from, cur.State)
	}
	if to == StateActive && cur.DirectoryIdentity == "" {
		// The database CHECK would refuse this too; this gives the caller a typed reason.
		return Connection{}, fmt.Errorf("%w: a connection with no verified identity cannot become active", ErrIllegalTransition)
	}
	var retired *time.Time
	var stampArg *time.Time
	if to.retires() {
		retired, stampArg = &stamp, &stamp
	}
	row := tx.QueryRow(ctx, `UPDATE public.connections SET state = $2, retired_at = COALESCE($3, retired_at),
		last_stamp_at = COALESCE($4, last_stamp_at), updated_at = now()
		WHERE id = $1::uuid AND state = $5 RETURNING `+columns, string(id), string(to), retired, stampArg, string(from))
	c, err := scan(row)
	if store.IsNoRows(err) {
		return Connection{}, ErrStateConflict
	}
	if err != nil {
		return Connection{}, fmt.Errorf("connection: transition: %w", err)
	}
	return c, nil
}

// SetDirectoryIdentity records the identity found by a verification's V5 check. It is allowed only
// while the connection is verifying and only if no identity is set yet; setting the same value again
// is a no-op, a different one is ErrIdentityFixed (I1). If another live connection of the tenant and
// kind holds the identity the unique index refuses it with ErrDuplicateIdentity (I2), which is what
// makes the check race-free.
func (Store) SetDirectoryIdentity(ctx context.Context, tx store.Tx, id ID, identity DirectoryIdentity) (Connection, error) {
	ident, err := ParseDirectoryIdentity(string(identity))
	if err != nil {
		return Connection{}, err
	}
	cur, _, err := lock(ctx, tx, id)
	if err != nil {
		return Connection{}, err
	}
	switch {
	case cur.DirectoryIdentity == ident:
		return cur, nil
	case cur.DirectoryIdentity != "":
		return Connection{}, ErrIdentityFixed
	case cur.State != StateVerifying:
		return Connection{}, fmt.Errorf("%w (state %s)", ErrIdentityState, cur.State)
	}
	// A failed statement aborts the transaction, so the duplicate surfaces as an error the caller
	// rolls back on; the verification run records it in its own fresh transaction.
	c, err := scan(tx.QueryRow(ctx, `UPDATE public.connections SET directory_identity = $2, updated_at = now()
		WHERE id = $1::uuid AND directory_identity = '' RETURNING `+columns, string(id), string(ident)))
	if err != nil {
		if store.SQLState(err) == "23505" {
			return Connection{}, ErrDuplicateIdentity
		}
		return Connection{}, fmt.Errorf("connection: set identity: %w", err)
	}
	return c, nil
}

// Registry is the connection registry handed to modules through directory.Services: the Store bound
// to a database, one tenant per call. Each method opens its own tenant transaction; a caller that
// needs several writes atomic uses Store inside its own WithTenant.
type Registry struct {
	db *store.DB
	s  Store
}

// NewRegistry binds the registry to a database.
func NewRegistry(db *store.DB) *Registry { return &Registry{db: db} }

func (r *Registry) with(ctx context.Context, tid tenant.ID, fn func(ctx context.Context, tx store.Tx) error) error {
	if r == nil || r.db == nil {
		return errors.New("connection: registry not configured")
	}
	if tid.IsZero() {
		return ErrNoTenant
	}
	return r.db.WithTenant(ctx, tid, fn)
}

// Create adds a draft connection to the tenant (L1).
func (r *Registry) Create(ctx context.Context, tid tenant.ID, n New) (c Connection, err error) {
	err = r.with(ctx, tid, func(ctx context.Context, tx store.Tx) (e error) { c, e = r.s.Create(ctx, tx, n); return })
	return c, err
}

// Get returns one connection of the tenant.
func (r *Registry) Get(ctx context.Context, tid tenant.ID, id ID) (c Connection, err error) {
	err = r.with(ctx, tid, func(ctx context.Context, tx store.Tx) (e error) { c, e = r.s.Get(ctx, tx, id); return })
	return c, err
}

// Bindings returns the connection's bindings that are not removed, in routing order, for the tenant.
func (r *Registry) Bindings(ctx context.Context, tid tenant.ID, id ID) (bs []Binding, err error) {
	err = r.with(ctx, tid, func(ctx context.Context, tx store.Tx) (e error) { bs, e = r.s.Bindings(ctx, tx, id); return })
	return bs, err
}

// List returns the tenant's connections.
func (r *Registry) List(ctx context.Context, tid tenant.ID, includeDiscarded bool) (cs []Connection, err error) {
	err = r.with(ctx, tid, func(ctx context.Context, tx store.Tx) (e error) { cs, e = r.s.List(ctx, tx, includeDiscarded); return })
	return cs, err
}

// Transition moves a connection along a declared edge.
func (r *Registry) Transition(ctx context.Context, tid tenant.ID, id ID, from, to State) (c Connection, err error) {
	err = r.with(ctx, tid, func(ctx context.Context, tx store.Tx) (e error) { c, e = r.s.Transition(ctx, tx, id, from, to); return })
	return c, err
}

// SetDirectoryIdentity records the V5 identity of a verifying connection.
func (r *Registry) SetDirectoryIdentity(ctx context.Context, tid tenant.ID, id ID, identity DirectoryIdentity) (c Connection, err error) {
	err = r.with(ctx, tid, func(ctx context.Context, tx store.Tx) (e error) {
		c, e = r.s.SetDirectoryIdentity(ctx, tx, id, identity)
		return
	})
	return c, err
}

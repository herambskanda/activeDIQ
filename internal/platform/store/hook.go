package store

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5"
)

// The two neutral mechanisms a package above store can use to do work at commit without store knowing
// its types (ADR-0005 rule 11): a per-transaction Slot, and one BeforeCommit hook per DB. store imports
// no audit code and no SQL here names an audit table; platform/audit builds the chain on these.

// Errors of the slot and hook mechanisms.
var (
	// ErrNoHook is returned by Slot.Update on a transaction whose DB was opened with no BeforeCommit
	// hook: whatever was buffered would never be handled, so it fails closed.
	ErrNoHook = errors.New("store: this store has no BeforeCommit hook: nothing would handle the buffered work")
	// ErrSlotSealed is returned by Slot.Update once the commit hook has started.
	ErrSlotSealed = errors.New("store: the transaction is committing: nothing more can be buffered")
	// ErrNotStoreTx is returned by the slot functions for a Tx that did not come from this package.
	ErrNotStoreTx = errors.New("store: not a store transaction")
	// ErrUndrained is returned (and the transaction rolled back) when the hook returned without taking
	// everything buffered in the slots.
	ErrUndrained = errors.New("store: the commit hook left buffered work unhandled")
	// ErrTxControl is returned for COMMIT, ROLLBACK, SAVEPOINT and friends inside a transaction body,
	// which could commit around the hook.
	ErrTxControl = errors.New("store: transaction-control SQL is not allowed inside a store transaction")
)

// BeforeCommitFunc runs after the body of a transaction and before COMMIT, in the same transaction,
// when at least one slot holds something. tenantID is the transaction's tenant ("" for a platform
// transaction). It must take (Slot.Take) everything it handles.
type BeforeCommitFunc func(ctx context.Context, tx Tx, tenantID string) error

type hookHolder struct {
	mu sync.Mutex
	f  BeforeCommitFunc
}

func (h *hookHolder) get() BeforeCommitFunc {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.f
}

// SetBeforeCommit installs the one commit hook. It is set once when the process opens the store;
// a second call, or a nil function, panics: a swapped hook would unchain the audit trail.
func (d *DB) SetBeforeCommit(f BeforeCommitFunc) {
	if f == nil {
		panic("store: SetBeforeCommit(nil)")
	}
	d.hook.mu.Lock()
	defer d.hook.mu.Unlock()
	if d.hook.f != nil {
		panic("store: the BeforeCommit hook is already set")
	}
	d.hook.f = f
}

// txState is shared by the body's Tx and the hook's Tx of one transaction.
type txState struct {
	hooked bool
	sealed bool
	slots  map[any]any
}

// Slot holds one value of type T per transaction, keyed by the Slot itself: only a package that holds
// the *Slot can reach its value.
type Slot[T any] struct{ _ byte }

// NewSlot makes a slot. Declare it once, in the package that owns the work.
func NewSlot[T any]() *Slot[T] { return new(Slot[T]) }

func stateOf(tx Tx) (*txState, error) {
	t, ok := tx.(storeTx)
	if !ok || t.st == nil {
		return nil, ErrNotStoreTx
	}
	return t.st, nil
}

// Update runs fn on the transaction's value (the zero T the first time).
func (s *Slot[T]) Update(tx Tx, fn func(*T) error) error {
	st, err := stateOf(tx)
	if err != nil {
		return err
	}
	if !st.hooked {
		return ErrNoHook
	}
	if st.sealed {
		return ErrSlotSealed
	}
	v, _ := st.slots[s].(*T)
	fresh := v == nil
	if fresh {
		v = new(T)
	}
	if err := fn(v); err != nil {
		return err
	}
	if fresh {
		if st.slots == nil {
			st.slots = map[any]any{}
		}
		st.slots[s] = v
	}
	return nil
}

// Take removes and returns the transaction's value; ok is false when nothing was buffered.
func (s *Slot[T]) Take(tx Tx) (v *T, ok bool) {
	st, err := stateOf(tx)
	if err != nil {
		return nil, false
	}
	v, ok = st.slots[s].(*T)
	delete(st.slots, s)
	return v, ok
}

// HasHook reports whether tx belongs to a store with a BeforeCommit hook.
func HasHook(tx Tx) bool {
	st, err := stateOf(tx)
	return err == nil && st.hooked
}

// isTxControl reports whether sql contains a statement that starts or ends a transaction or a
// savepoint. It looks at the first word of every ';'-separated statement.
func isTxControl(sql string) bool {
	for _, stmt := range strings.Split(sql, ";") {
		f := strings.Fields(stmt)
		if len(f) == 0 {
			continue
		}
		switch strings.ToUpper(f[0]) {
		case "COMMIT", "ROLLBACK", "SAVEPOINT", "RELEASE", "BEGIN", "START", "END", "ABORT":
			return true
		case "PREPARE":
			if len(f) > 1 && strings.EqualFold(f[1], "TRANSACTION") {
				return true
			}
		}
	}
	return false
}

type errRow struct{ err error }

func (r errRow) Scan(...any) error { return r.err }

var _ pgx.Row = errRow{}

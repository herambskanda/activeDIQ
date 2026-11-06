package storetest

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// FakeTx is a store.Tx that touches no database, for unit tests of code that only needs to hand a
// transaction to collaborators (a fake audit sink, a fake store). Tests keep their own state in
// Records and Writes; the fake owner of the transaction decides when they commit or are dropped.
// Query and QueryRow fail: anything that really reads or writes SQL needs the PostgreSQL harness.
type FakeTx struct {
	Records  []any    // what a fake collaborator appended in this transaction (audit events)
	Writes   []string // what a fake store wrote in this transaction
	ReadOnly bool     // a SET TRANSACTION READ ONLY was executed

	// Observe, when set, sees every statement before the fake answers it; a non-nil error is returned
	// to the caller instead (a fake store that refuses writes in a READ ONLY transaction, say). With
	// Observe set, QueryRow returns a row whose Scan fails instead of nil.
	Observe func(sql string) error
}

// Exec records a SET TRANSACTION READ ONLY and accepts everything else.
func (t *FakeTx) Exec(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
	if t.Observe != nil {
		if err := t.Observe(sql); err != nil {
			return pgconn.CommandTag{}, err
		}
	}
	if strings.HasPrefix(sql, "SET TRANSACTION READ ONLY") {
		t.ReadOnly = true
	}
	return pgconn.CommandTag{}, nil
}

// Query always fails (after Observe, when set).
func (t *FakeTx) Query(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
	if t.Observe != nil {
		if err := t.Observe(sql); err != nil {
			return nil, err
		}
	}
	return nil, errors.New("storetest.FakeTx: no rows")
}

// QueryRow returns nil, or with Observe set a row whose Scan fails; callers of the fake must not read rows.
func (t *FakeTx) QueryRow(_ context.Context, sql string, _ ...any) pgx.Row {
	if t.Observe == nil {
		return nil
	}
	if err := t.Observe(sql); err != nil {
		return failedRow{err}
	}
	return failedRow{errors.New("storetest.FakeTx: no rows")}
}

type failedRow struct{ err error }

func (r failedRow) Scan(...any) error { return r.err }

// ReadOnlyError is the error PostgreSQL returns (SQLSTATE 25006) for a write in a READ ONLY
// transaction, for fakes that refuse one the same way.
func ReadOnlyError(stmt string) error {
	return &pgconn.PgError{Severity: "ERROR", Code: "25006", Message: "cannot execute " + stmt + " in a read-only transaction"}
}

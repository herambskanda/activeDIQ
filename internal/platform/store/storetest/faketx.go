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
}

// Exec records a SET TRANSACTION READ ONLY and accepts everything else.
func (t *FakeTx) Exec(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
	if strings.HasPrefix(sql, "SET TRANSACTION READ ONLY") {
		t.ReadOnly = true
	}
	return pgconn.CommandTag{}, nil
}

// Query always fails.
func (*FakeTx) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("storetest.FakeTx: no rows")
}

// QueryRow returns nil; callers of the fake must not read rows.
func (*FakeTx) QueryRow(context.Context, string, ...any) pgx.Row { return nil }

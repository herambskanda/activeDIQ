package storetest

import (
	"context"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Querier is the statement surface of a store.Tx. It is declared here, not imported, because the
// store package's own tests import storetest; any store.Tx satisfies it.
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// StatementLog records the SQL text of every statement run through the RecordingTx values that share it.
// Tests use it to prove how much work a code path does (for example one search statement and one batched
// read per request, however many rows the scope hides).
type StatementLog struct {
	mu   sync.Mutex
	list []string
}

// Count is the number of recorded statements containing sub.
func (l *StatementLog) Count(sub string) (n int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, s := range l.list {
		if strings.Contains(s, sub) {
			n++
		}
	}
	return n
}

// Statements is a copy of the recorded statement texts, in order.
func (l *StatementLog) Statements() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.list...)
}

func (l *StatementLog) add(sql string) {
	l.mu.Lock()
	l.list = append(l.list, sql)
	l.mu.Unlock()
}

// RecordingTx wraps a transaction and records each statement's SQL text into Log before running it.
// It satisfies store.Tx.
type RecordingTx struct {
	Querier
	Log *StatementLog
}

// Record wraps tx so its statements are recorded in log.
func Record(tx Querier, log *StatementLog) RecordingTx { return RecordingTx{Querier: tx, Log: log} }

// Exec records and runs the statement.
func (r RecordingTx) Exec(ctx context.Context, sql string, a ...any) (pgconn.CommandTag, error) {
	r.Log.add(sql)
	return r.Querier.Exec(ctx, sql, a...)
}

// Query records and runs the statement.
func (r RecordingTx) Query(ctx context.Context, sql string, a ...any) (pgx.Rows, error) {
	r.Log.add(sql)
	return r.Querier.Query(ctx, sql, a...)
}

// QueryRow records and runs the statement.
func (r RecordingTx) QueryRow(ctx context.Context, sql string, a ...any) pgx.Row {
	r.Log.add(sql)
	return r.Querier.QueryRow(ctx, sql, a...)
}

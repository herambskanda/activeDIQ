package reportsql

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store"
)

// MaxBatch caps the rows one FETCH returns.
const MaxBatch = 10000

const cursorName = "reportsql_cur"

// Exec runs q through a cursor inside tx and hands the rows to fn in batches of at most batch, so a
// 500k-row run holds one batch in memory (contract §5). It returns the number of rows delivered. A
// batch is read completely before fn is called, so fn may use tx. The cursor lives in tx's
// transaction: the caller owns the transaction and its statement timeout.
//
// A statement timeout surfaces as ErrQueryTimeout (SQL-22), not as a driver error that carries SQL.
func Exec(ctx context.Context, tx store.Tx, q Query, batch int, fn func(ctx context.Context, rows []report.Row) error) (int64, error) {
	if q.sql == "" || len(q.out) == 0 {
		return 0, ErrInvalidQuery // not compiled, or a count query (it has no rows)
	}
	if batch <= 0 || batch > MaxBatch {
		batch = MaxBatch
	}
	declare := CompiledSQL("DECLARE " + cursorName + " NO SCROLL CURSOR FOR " + string(q.sql))
	if _, err := tx.Exec(ctx, string(declare), q.args...); err != nil {
		return 0, wrapErr(ctx, err)
	}
	fetch := CompiledSQL("FETCH FORWARD " + strconv.Itoa(batch) + " FROM " + cursorName)
	var total int64
	for {
		rows, err := fetchBatch(ctx, tx, fetch, q)
		if err != nil {
			return total, err
		}
		if len(rows) == 0 {
			break
		}
		total += int64(len(rows))
		if err := fn(ctx, rows); err != nil {
			return total, err
		}
		if len(rows) < batch {
			break
		}
	}
	if _, err := tx.Exec(ctx, "CLOSE "+cursorName); err != nil {
		return total, wrapErr(ctx, err)
	}
	return total, nil
}

// Count runs a CompileCount query.
func Count(ctx context.Context, tx store.Tx, q Query) (int64, error) {
	if q.sql == "" || q.out != nil {
		return 0, ErrInvalidQuery
	}
	var n int64
	if err := tx.QueryRow(ctx, string(q.sql), q.args...).Scan(&n); err != nil {
		return 0, wrapErr(ctx, err)
	}
	return n, nil
}

// wrapErr maps the statement timeout (57014) to ErrQueryTimeout when the caller's context is still
// live; a cancelled context stays the context's error. Other errors pass through unchanged.
func wrapErr(ctx context.Context, err error) error {
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "57014" && ctx.Err() == nil {
		return ErrQueryTimeout
	}
	return err
}

func fetchBatch(ctx context.Context, tx store.Tx, fetch CompiledSQL, q Query) ([]report.Row, error) {
	// QueryExecModeExec: an unnamed statement, described afresh. The statement cache keys a description
	// by SQL text, and FETCH's columns depend on whichever query the cursor holds, so a cached
	// description of an earlier run's cursor would misdescribe this one. It is still the extended
	// protocol (the server binds), unlike simple protocol, which store.Open refuses (SQL-20).
	rs, err := tx.Query(ctx, string(fetch), pgx.QueryExecModeExec)
	if err != nil {
		return nil, wrapErr(ctx, err)
	}
	defer rs.Close()
	var out []report.Row
	for rs.Next() {
		row, err := scanRow(rs, q)
		if err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	if err := rs.Err(); err != nil {
		return nil, wrapErr(ctx, err)
	}
	return out, nil
}

// dest is one scan target and how to turn it into a cell.
type dest struct {
	ptr  any
	cell func() (report.Cell, error)
}

func newDest(c *column) dest {
	col := c.src
	switch col.Type {
	case report.TypeInt:
		var v *int64
		return dest{&v, func() (report.Cell, error) {
			if v == nil {
				return report.Absent(), nil
			}
			return report.IntCell(*v), nil
		}}
	case report.TypeBool:
		var v *bool
		return dest{&v, func() (report.Cell, error) {
			if v == nil {
				return report.Absent(), nil
			}
			return report.BoolCell(*v), nil
		}}
	case report.TypeTime:
		var v *time.Time
		return dest{&v, func() (report.Cell, error) {
			if v == nil {
				return report.Absent(), nil
			}
			return report.TimeCell(*v), nil
		}}
	case report.TypeGUID:
		var v *string
		return dest{&v, func() (report.Cell, error) {
			if v == nil {
				return report.Absent(), nil
			}
			g, err := authz.ParseObjectID(*v)
			if err != nil {
				return report.Cell{}, fmt.Errorf("reportsql: column %s produced a bad GUID", col.ID)
			}
			return report.GUIDCell(g), nil
		}}
	case report.TypeTextList:
		var v []string
		return dest{&v, func() (report.Cell, error) {
			if v == nil {
				return report.Absent(), nil
			}
			return report.ListCell(v...), nil
		}}
	case report.TypeEnum:
		var v *string
		return dest{&v, func() (report.Cell, error) {
			if v == nil {
				return report.Absent(), nil
			}
			if *v == report.UnknownInputMissing {
				return report.Unknown(), nil
			}
			if !col.HasEnum(*v) {
				return report.Cell{}, fmt.Errorf("%w: column %s", ErrBadEnumValue, col.ID)
			}
			return report.EnumCell(*v), nil
		}}
	}
	var v *string
	return dest{&v, func() (report.Cell, error) {
		if v == nil {
			return report.Absent(), nil
		}
		return report.TextCell(*v), nil
	}}
}

func scanRow(rs pgx.Rows, q Query) (report.Row, error) {
	var key string
	dests := make([]dest, len(q.out))
	ptrs := make([]any, 0, 1+len(q.out)+q.nHidden)
	ptrs = append(ptrs, &key)
	for i, o := range q.out {
		dests[i] = newDest(o.col)
		ptrs = append(ptrs, dests[i].ptr)
	}
	hidden := make([]bool, q.nHidden)
	for i := range hidden {
		ptrs = append(ptrs, &hidden[i])
	}
	if err := rs.Scan(ptrs...); err != nil {
		return report.Row{}, err
	}
	cells := make([]report.Cell, len(q.out))
	for i := range dests {
		c, err := dests[i].cell()
		if err != nil {
			return report.Row{}, err
		}
		cells[i] = c
	}
	for i := 0; i < q.nReq; i++ {
		if u := q.out[i].unknown; u >= 0 && cells[u].IsUnknown() {
			cells[i] = report.Unknown()
		}
	}
	row := report.Row{Key: key, Cells: cells[:q.nReq], Hidden: hidden}
	if q.nHidden == 0 {
		row.Hidden = nil
	}
	return row, nil
}

// ExecAll runs a compiled query that is known to be small and reads every row in one statement, without
// a cursor. It is for a bounded lookup by key (search metadata, T-1097); a report run uses Exec. max is
// the most rows it accepts: a longer answer is ErrTooManyRows and nothing is returned, so an unbounded
// query cannot be buffered by mistake. The statement timeout of tx bounds it.
func ExecAll(ctx context.Context, tx store.Tx, q Query, max int) ([]report.Row, error) {
	if q.sql == "" || len(q.out) == 0 || q.search != nil || max < 1 {
		return nil, ErrInvalidQuery
	}
	rs, err := tx.Query(ctx, string(q.sql), append([]any{pgx.QueryExecModeExec}, q.args...)...)
	if err != nil {
		return nil, wrapErr(ctx, err)
	}
	defer rs.Close()
	var out []report.Row
	for rs.Next() {
		if len(out) == max {
			return nil, ErrTooManyRows
		}
		row, err := scanRow(rs, q)
		if err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	if err := rs.Err(); err != nil {
		return nil, wrapErr(ctx, err)
	}
	return out, nil
}

package run

import (
	"context"
	"encoding/base64"
	jsonv2 "encoding/json/v2"
	"errors"
	"slices"

	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// Page errors.
var (
	ErrBadCursor = errors.New("run: bad cursor")    // 400
	ErrBadSort   = errors.New("run: bad sort")      // 400
	ErrBadLimit  = errors.New("run: bad page size") // 400
)

// PageQuery is one page request over a stored result.
type PageQuery struct {
	SortBy string // a stored, sortable column ID; empty orders by run order
	Desc   bool
	Limit  int // 0: DefaultPageSize
	Cursor string
}

// rowSet is the part of a pgx result set the page reader uses.
type rowSet interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
	Close()
}

// StoredRow is one stored row.
type StoredRow struct {
	Key     string
	Ordinal int64
	Cells   []report.Cell
}

// Page is one page of a stored result with the run it belongs to.
type Page struct {
	Run     Run
	Columns []report.Column // the stored columns in order
	Rows    []StoredRow
	Next    string // "" on the last page
}

type cursor struct {
	V    int    `json:"v"`
	Run  string `json:"r"`
	Sort string `json:"s"`
	Desc bool   `json:"d"`
	Off  int64  `json:"o"`
}

func (c cursor) encode() string {
	b, _ := jsonv2.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeCursor(s string) (cursor, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	var c cursor
	if err != nil || jsonv2.Unmarshal(b, &c) != nil || c.V != 1 || c.Off < 0 {
		return cursor{}, ErrBadCursor
	}
	return c, nil
}

// The two sort variants are static text: the column is a bound parameter, the direction is chosen
// between two constants, and the join keeps a page from reading a run that is not succeeded and live.
const pageByOrdinal = `SELECT w.row_key, w.ordinal, w.cells::text FROM public.report_run_rows w
JOIN public.report_runs r ON r.tenant_id = w.tenant_id AND r.id = w.run_id
WHERE w.run_id = $1::uuid AND r.state = 'succeeded' AND r.expires_at > now()
ORDER BY w.ordinal LIMIT $2 OFFSET $3`

const pageSortAsc = `SELECT w.row_key, w.ordinal, w.cells::text FROM public.report_run_rows w
JOIN public.report_runs r ON r.tenant_id = w.tenant_id AND r.id = w.run_id
WHERE w.run_id = $1::uuid AND r.state = 'succeeded' AND r.expires_at > now()
ORDER BY (w.sort_keys ->> $4) COLLATE "C" ASC NULLS LAST, w.ordinal LIMIT $2 OFFSET $3`

const pageSortDesc = `SELECT w.row_key, w.ordinal, w.cells::text FROM public.report_run_rows w
JOIN public.report_runs r ON r.tenant_id = w.tenant_id AND r.id = w.run_id
WHERE w.run_id = $1::uuid AND r.state = 'succeeded' AND r.expires_at > now()
ORDER BY (w.sort_keys ->> $4) COLLATE "C" DESC NULLS LAST, w.ordinal LIMIT $2 OFFSET $3`

// Page reads one page of a run's stored rows, after the full read gate (§6.6, checks 2 to 5). The total
// is the run's row_count: it is never counted from the rows (ADR-0010 rule 3).
func (s *Service) Page(ctx context.Context, tid tenant.ID, chain authority.Chain, id ID, pq PageQuery) (Page, error) {
	limit := pq.Limit
	if limit == 0 {
		limit = DefaultPageSize
	}
	if limit < 1 || limit > MaxPageSize {
		return Page{}, ErrBadLimit
	}
	var off int64
	if pq.Cursor != "" {
		c, err := decodeCursor(pq.Cursor)
		if err != nil || c.Run != id.String() || c.Sort != pq.SortBy || c.Desc != pq.Desc {
			return Page{}, ErrBadCursor // a cursor belongs to one run and one sort
		}
		off = c.Off
	}
	var out Page
	err := s.Read(ctx, tid, OpPage, id, chain, ForPage, func(ctx context.Context, tx store.Tx, r Run) error {
		out.Run = r
		def, ok := s.Catalog.Definition(r.DefinitionID, r.DefinitionVer)
		if !ok {
			return ErrDefinitionUnknown
		}
		for _, c := range r.Columns {
			col, ok := def.Dataset.Column(report.ColumnID(c))
			if !ok {
				return ErrDefinitionUnknown
			}
			out.Columns = append(out.Columns, col)
		}
		var rows rowSet
		var err error
		switch {
		case pq.SortBy == "":
			rows, err = tx.Query(ctx, pageByOrdinal, id.String(), limit+1, off)
		default:
			i := slices.IndexFunc(out.Columns, func(c report.Column) bool { return string(c.ID) == pq.SortBy })
			if i < 0 || !out.Columns[i].Sortable {
				return ErrBadSort
			}
			if pq.Desc {
				rows, err = tx.Query(ctx, pageSortDesc, id.String(), limit+1, off, pq.SortBy)
			} else {
				rows, err = tx.Query(ctx, pageSortAsc, id.String(), limit+1, off, pq.SortBy)
			}
		}
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var sr StoredRow
			var cj string
			if err := rows.Scan(&sr.Key, &sr.Ordinal, &cj); err != nil {
				return err
			}
			if err := jsonv2.Unmarshal([]byte(cj), &sr.Cells); err != nil {
				return err
			}
			out.Rows = append(out.Rows, sr)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if len(out.Rows) > limit {
			out.Rows = out.Rows[:limit]
			out.Next = cursor{V: 1, Run: id.String(), Sort: pq.SortBy, Desc: pq.Desc, Off: off + int64(limit)}.encode()
		}
		if len(out.Rows) == 0 && r.RowCount != nil && off < *r.RowCount {
			return ErrRunExpired // the database clock says the rows are past their expiry
		}
		return nil
	})
	return out, err
}

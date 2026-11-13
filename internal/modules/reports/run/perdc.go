package run

import (
	"context"
	jsonv2 "encoding/json/v2"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit/chain"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/export"
	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store"
)

// This file is the per-DC half of the run job (USR-04, PWD-03; reports.md §6.5, spec §6.5, FR-10):
//
//	stage 1  candidates      store.go's T2 with the run left running (job.go)
//	stage 2  read cap        candidates × DCs in scope > cap fails the run before any DC is read
//	stage 3  reads           batches of report.PerDCBatchSize, outside any transaction; after each batch a short
//	                         transaction locks the run, checks it is still this attempt's, writes the per-DC cells
//	                         and sort keys, deletes the rows PerDCWhere rejects and records the progress
//	stage 4  finalise        one transaction: order, renumber, digest, succeed

// candRef is a stored candidate: the row and the directory object to ask the DCs about.
type candRef struct {
	key  string
	conn authz.ObjectID
	nc   authz.ObjectID
}

type groupKey struct{ conn, nc authz.ObjectID }

// perDCStage carries what stage 1 learned to the later stages.
type perDCStage struct {
	connIdx, ncIdx int // positions of the helper columns in the compiled row
	refs           []candRef
	perGroup       map[groupKey]int64
	order          []groupKey
	candidates     int64
	cap            int

	hidden  map[string]int64
	hiddenN int64
	stored  int64
	sa      ScopeApplied
	fp      [32]byte
	scope   authz.ReadScope
}

// newPerDCStage prepares the SQL query of stage 1: the per-DC part of the filter and the sort keys on per-DC
// columns cannot be SQL, so they are taken out, and the connection and the naming context of every candidate
// ride along as two extra columns that are never stored.
func newPerDCStage(def Definition, q report.Query) (*perDCStage, report.Query, error) {
	sq := q
	sq.PerDCWhere = nil
	sq.Sort = slices.DeleteFunc(slices.Clone(q.Sort), func(k report.SortKey) bool {
		c, ok := def.Dataset.Column(k.Column)
		return !ok || c.IsPerDC()
	})
	sq.Columns = slices.Clone(q.Columns)
	pd := &perDCStage{perGroup: map[groupKey]int64{}}
	for _, h := range []struct {
		id  report.ColumnID
		idx *int
	}{{"connection_id", &pd.connIdx}, {"domain", &pd.ncIdx}} {
		if _, ok := def.Dataset.Column(h.id); !ok {
			return nil, report.Query{}, &runFailure{reason: FailInternal}
		}
		i := slices.Index(sq.Columns, h.id)
		if i < 0 {
			sq.Columns = append(sq.Columns, h.id)
			i = len(sq.Columns) - 1
		}
		*h.idx = i
	}
	return pd, sq, nil
}

// candidate notes one stored row. Refs are kept only up to the read cap: a run past it is refused and never
// reads, so there is nothing to remember beyond it.
func (pd *perDCStage) candidate(row report.Row, _ int) error {
	if pd.connIdx >= len(row.Cells) || pd.ncIdx >= len(row.Cells) {
		return &runFailure{reason: FailInternal}
	}
	conn, nc := row.Cells[pd.connIdx].GUID(), row.Cells[pd.ncIdx].GUID()
	if conn.IsZero() || nc.IsZero() {
		return &runFailure{reason: FailInternal}
	}
	g := groupKey{conn, nc}
	if _, ok := pd.perGroup[g]; !ok {
		pd.order = append(pd.order, g)
	}
	pd.perGroup[g]++
	pd.candidates++
	if len(pd.refs) <= pd.cap {
		pd.refs = append(pd.refs, candRef{key: row.Key, conn: conn, nc: nc})
	}
	return nil
}

func (s *Service) perDCCap() int {
	if s.PerDCReadCap > 0 {
		return s.PerDCReadCap
	}
	return report.DefaultPerDCReadCap
}

// readSQL is the static SQL of stage 3 and 4. No identifier or value is ever concatenated.
const (
	lockedCells = `SELECT row_key, cells::text FROM public.report_run_rows WHERE run_id = $1::uuid AND row_key = ANY($2::text[]) FOR UPDATE`
	updateCells = `UPDATE public.report_run_rows w SET cells = u.cells::jsonb, sort_keys = w.sort_keys || u.sort_keys::jsonb
FROM unnest($2::text[], $3::text[], $4::text[]) AS u(row_key, cells, sort_keys)
WHERE w.run_id = $1::uuid AND w.row_key = u.row_key`
	deleteSome   = `DELETE FROM public.report_run_rows WHERE run_id = $1::uuid AND row_key = ANY($2::text[])`
	setProgress  = `UPDATE public.report_runs SET per_dc = $3::jsonb WHERE id = $1::uuid AND state = 'running' AND attempt = $2`
	allKeys      = `SELECT row_key, ordinal, sort_keys::text FROM public.report_run_rows WHERE run_id = $1::uuid ORDER BY ordinal`
	setOrdinals  = `UPDATE public.report_run_rows w SET ordinal = u.ordinal FROM unnest($2::text[], $3::bigint[]) AS u(row_key, ordinal) WHERE w.run_id = $1::uuid AND w.row_key = u.row_key`
	cellsByOrder = `SELECT ordinal, cells::text FROM public.report_run_rows WHERE run_id = $1::uuid AND ordinal > $2 ORDER BY ordinal LIMIT $3`
	succeedPerDC = `UPDATE public.report_runs SET state = 'succeeded', row_count = $3, objects_checked = $4, hidden_counts = $5::jsonb,
  digest = $6, as_of = $7, freshness = $8::jsonb, scope_applied = $9::jsonb, per_dc = $10::jsonb, finished_at = $11, expires_at = $12
WHERE id = $1::uuid AND state = 'running' AND attempt = $2`
)

// perDCPlan is what stage 3 needs of the definition: which columns are per-DC, which attributes to ask.
type perDCPlan struct {
	cols     []report.Column // per-DC columns to compute: the shown ones, then any the filter names
	idx      []int           // position in the stored row of each of cols, -1 when not shown
	attrs    []report.PerDCAttr
	scope    report.PerDCScope
	where    report.Expr
	sortKeys []report.SortKey
}

func newPerDCPlan(def Definition, q report.Query, r Run) (perDCPlan, error) {
	p := perDCPlan{scope: def.Def.PerDC.Scope, where: q.PerDCWhere, sortKeys: q.Sort}
	var p0 struct {
		IncludeReadOnlyDcs *bool `json:"includeReadOnlyDcs"`
	}
	if len(r.Params) > 0 && jsonv2.Unmarshal(r.Params, &p0) == nil && p0.IncludeReadOnlyDcs != nil && !*p0.IncludeReadOnlyDcs {
		p.scope = report.ScopeWritable
	}
	add := func(id report.ColumnID, shown int) error {
		c, ok := def.Dataset.Column(id)
		if !ok || !c.IsPerDC() {
			return &runFailure{reason: FailInternal}
		}
		if slices.ContainsFunc(p.cols, func(x report.Column) bool { return x.ID == id }) {
			return nil
		}
		p.cols, p.idx = append(p.cols, c), append(p.idx, shown)
		src := c.Source.(report.PerDC)
		if src.Part == report.PartCoverage {
			return nil
		}
		for _, a := range []report.PerDCAttr{src.Attr, src.Of} {
			if a.Valid() && !slices.Contains(p.attrs, a) {
				p.attrs = append(p.attrs, a)
			}
		}
		return nil
	}
	for i, id := range q.Columns {
		if c, _ := def.Dataset.Column(id); c.IsPerDC() {
			if err := add(id, i); err != nil {
				return p, err
			}
		}
	}
	for _, id := range report.ExprColumns(q.PerDCWhere) {
		if err := add(id, -1); err != nil {
			return p, err
		}
	}
	if len(p.attrs) == 0 {
		p.attrs = []report.PerDCAttr{report.PerDCLastLogon} // a coverage-only report still asks which DCs answer
	}
	return p, nil
}

// readDCs is stages 2 to 4. The candidates are committed and the run is running.
func (s *Service) readDCs(ctx context.Context, jt jobs.TenantTx, r Run, attempt int, def Definition, q report.Query,
	cols []report.Column, colIDs []string, pd *perDCStage, fr FreshnessRecord) error {
	plan, err := newPerDCPlan(def, q, r)
	if err != nil {
		return err
	}
	// Stage 2: the estimate, before any DC is asked (AC-41).
	var reads, maxDCs uint64
	for _, g := range pd.order {
		n, err := s.PerDCDCs.DCsInScope(ctx, g.conn, g.nc, plan.scope)
		if err != nil || n < 0 {
			if cerr := ctx.Err(); cerr != nil {
				return cerr
			}
			return &runFailure{reason: FailConnectionUnavailable}
		}
		reads += report.PerDCReads(uint64(pd.perGroup[g]), uint64(n))
		maxDCs = max(maxDCs, uint64(n))
	}
	if limit := s.perDCCap(); reads > uint64(limit) {
		return &runFailure{reason: FailPerDCReadCapExceeded, detail: map[string]int64{
			"candidates": pd.candidates, "dcs": int64(maxDCs), "reads": clampInt64(reads), "cap": int64(limit)}}
	}

	// Stage 3.
	readAt := s.now()
	var tally report.PerDCTally
	var done int64
	progress := PerDCRecord{Stage: "reading_dcs", Total: pd.candidates, Scope: scopeName(plan.scope)}
	byGroup := map[groupKey][]candRef{}
	for _, c := range pd.refs {
		g := groupKey{c.conn, c.nc}
		byGroup[g] = append(byGroup[g], c)
	}
	if err := jt.Run(ctx, func(ctx context.Context, t store.Tx) error { return s.setProgress(ctx, t, r.ID, attempt, progress) }); err != nil {
		return err
	}
	for _, g := range pd.order {
		refs := byGroup[g]
		for len(refs) > 0 {
			n := min(len(refs), report.PerDCBatchSize)
			batch := refs[:n]
			refs = refs[n:]
			ids := make([]authz.ObjectID, n)
			for i, c := range batch {
				ids[i] = objectOf(c.key)
			}
			objs, sum, err := s.PerDC.Read(ctx, g.conn, g.nc, ids, plan.attrs, plan.scope)
			if err != nil {
				if cerr := ctx.Err(); cerr != nil {
					return cerr
				}
				return &runFailure{reason: FailConnectionUnavailable}
			}
			if len(objs) != n {
				return &runFailure{reason: FailInternal}
			}
			tally.Merge(sum)
			for _, o := range objs {
				tally.Add(o)
			}
			done += int64(n)
			progress.Read = done
			if err := jt.Run(ctx, func(ctx context.Context, t store.Tx) error {
				return s.storeBatch(ctx, t, r, attempt, plan, batch, objs, readAt, progress)
			}); err != nil {
				return err
			}
		}
	}

	// Stage 4.
	rec := PerDCRecord{Total: pd.candidates, Read: done, DCsInScope: tally.InScope, DCsAnswered: tally.Answered,
		Complete: tally.Complete() || tally.Objects == 0, Scope: scopeName(plan.scope), ReadAt: &readAt}
	for _, u := range tally.Sorted() {
		rec.Unreachable = append(rec.Unreachable, UnreachableDC{DC: u.DC, Error: u.Err})
	}
	return jt.Run(ctx, func(ctx context.Context, t store.Tx) error {
		return s.finalisePerDC(ctx, t, r, attempt, plan, pd, colIDs, fr, rec, readAt)
	})
}

func scopeName(sc report.PerDCScope) string {
	if sc == report.ScopeWritable {
		return "writable"
	}
	return "all"
}

func clampInt64(u uint64) int64 {
	if u > 1<<62 {
		return 1 << 62
	}
	return int64(u)
}

// objectOf parses a stored row key (the object GUID's canonical text). A key that is not one cannot have
// been stored by stage 1, so it is the zero ID, which the reader refuses.
func objectOf(key string) authz.ObjectID {
	o, err := authz.ParseObjectID(key)
	if err != nil {
		return authz.ObjectID{}
	}
	return o
}

func (s *Service) setProgress(ctx context.Context, t store.Tx, id ID, attempt int, p PerDCRecord) error {
	b, err := jsonv2.Marshal(p)
	if err != nil {
		return err
	}
	tag, err := t.Exec(ctx, setProgress, id.String(), attempt, string(b))
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return errStopped // cancelled, failed, or another attempt's
	}
	return nil
}

// lockRunning takes the run row and says the run is still this attempt's.
func lockRunning(ctx context.Context, t store.Tx, id ID, attempt int) error {
	cur, err := load(ctx, t, id, true)
	if err != nil {
		return err
	}
	if cur.State != StateRunning || cur.Attempt != attempt {
		return errStopped
	}
	return nil
}

// storeBatch writes one batch's per-DC cells, deletes the rows PerDCWhere rejects, and records progress, in
// one short transaction (§6.5 stage 3).
func (s *Service) storeBatch(ctx context.Context, t store.Tx, r Run, attempt int, plan perDCPlan, batch []candRef,
	objs []report.PerDCObject, readAt time.Time, progress PerDCRecord) error {
	if err := lockRunning(ctx, t, r.ID, attempt); err != nil {
		return err
	}
	keys := make([]string, len(batch))
	for i, c := range batch {
		keys[i] = c.key
	}
	rows, err := t.Query(ctx, lockedCells, r.ID.String(), keys)
	if err != nil {
		return err
	}
	stored := map[string][]report.Cell{}
	for rows.Next() {
		var k, cj string
		if err := rows.Scan(&k, &cj); err != nil {
			rows.Close()
			return err
		}
		var cells []report.Cell
		if err := jsonv2.Unmarshal([]byte(cj), &cells); err != nil {
			rows.Close()
			return err
		}
		stored[k] = cells
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	var upKeys, upCells, upSorts, drop []string
	for i, c := range batch {
		cells, ok := stored[c.key]
		if !ok {
			return &runFailure{reason: FailInternal}
		}
		pc := report.FoldPerDC(objs[i]).Cells(plan.cols, readAt)
		if keep, err := report.EvalPerDC(plan.where, pc.Eval, readAt); err != nil {
			return err
		} else if !keep {
			drop = append(drop, c.key)
			continue
		}
		sk := map[string]string{}
		for j, col := range plan.cols {
			pos := plan.idx[j]
			if pos < 0 {
				continue
			}
			cell := pc.Stored[col.ID]
			cells[pos] = cell
			if k, ok := report.CellSortKey(cell, col); ok {
				sk[string(col.ID)] = k
			}
		}
		cj, err := jsonv2.Marshal(cells)
		if err != nil {
			return err
		}
		sj, err := jsonv2.Marshal(sk)
		if err != nil {
			return err
		}
		upKeys, upCells, upSorts = append(upKeys, c.key), append(upCells, string(cj)), append(upSorts, string(sj))
	}
	if len(upKeys) > 0 {
		if _, err := t.Exec(ctx, updateCells, r.ID.String(), upKeys, upCells, upSorts); err != nil {
			return err
		}
	}
	if len(drop) > 0 {
		if _, err := t.Exec(ctx, deleteSome, r.ID.String(), drop); err != nil {
			return err
		}
	}
	return s.setProgress(ctx, t, r.ID, attempt, progress)
}

// finalisePerDC orders the surviving rows (the stored order already follows the SQL sort keys; a sort on a
// per-DC column is applied here from the stored sort keys), renumbers them, feeds the digest in that order and
// succeeds the run (§6.5 stage 4).
func (s *Service) finalisePerDC(ctx context.Context, t store.Tx, r Run, attempt int, plan perDCPlan, pd *perDCStage,
	colIDs []string, fr FreshnessRecord, rec PerDCRecord, readAt time.Time) error {
	if err := lockRunning(ctx, t, r.ID, attempt); err != nil {
		return err
	}
	type rowRef struct {
		key  string
		ord  int64
		keys map[string]string
	}
	var all []rowRef
	rows, err := t.Query(ctx, allKeys, r.ID.String())
	if err != nil {
		return err
	}
	for rows.Next() {
		var rr rowRef
		var sj string
		if err := rows.Scan(&rr.key, &rr.ord, &sj); err != nil {
			rows.Close()
			return err
		}
		if err := jsonv2.Unmarshal([]byte(sj), &rr.keys); err != nil {
			rows.Close()
			return err
		}
		all = append(all, rr)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if len(plan.sortKeys) > 0 {
		slices.SortStableFunc(all, func(a, b rowRef) int {
			for _, k := range plan.sortKeys {
				x, xok := a.keys[string(k.Column)]
				y, yok := b.keys[string(k.Column)]
				switch {
				case !xok && !yok:
					continue
				case !xok: // a cell with no key sorts last in both directions
					return 1
				case !yok:
					return -1
				}
				c := strings.Compare(x, y)
				if c == 0 {
					continue
				}
				if k.Dir == report.Desc {
					c = -c
				}
				return c
			}
			return int(a.ord - b.ord)
		})
	}
	var rk []string
	var ro []int64
	flush := func() error {
		if len(rk) == 0 {
			return nil
		}
		_, err := t.Exec(ctx, setOrdinals, r.ID.String(), rk, ro)
		rk, ro = rk[:0], ro[:0]
		return err
	}
	for i, rr := range all {
		if int64(i) == rr.ord {
			continue
		}
		rk, ro = append(rk, rr.key), append(ro, int64(i))
		if len(rk) == BatchSize {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	if err := flush(); err != nil {
		return err
	}

	dig := export.NewDigester(colIDs)
	after := int64(-1)
	for {
		page, err := t.Query(ctx, cellsByOrder, r.ID.String(), after, BatchSize)
		if err != nil {
			return err
		}
		n := 0
		for page.Next() {
			var cj string
			if err := page.Scan(&after, &cj); err != nil {
				page.Close()
				return err
			}
			var cells []report.Cell
			if err := jsonv2.Unmarshal([]byte(cj), &cells); err != nil {
				page.Close()
				return err
			}
			dig.Row(typed(cells))
			n++
		}
		page.Close()
		if err := page.Err(); err != nil {
			return err
		}
		if n < BatchSize {
			break
		}
	}

	now := s.now()
	count := int64(len(all))
	hj, _ := jsonv2.Marshal(pd.hidden)
	fj, _ := jsonv2.Marshal(fr)
	saj, _ := jsonv2.Marshal(pd.sa)
	pj, _ := jsonv2.Marshal(rec)
	sum := dig.Sum()
	tag, err := t.Exec(ctx, succeedPerDC, r.ID.String(), attempt, count, count+pd.hiddenN, string(hj), sum[:], readAt, string(fj), string(saj), string(pj), now, now.Add(ResultRetention))
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return errStopped
	}
	return s.appendCompleted(ctx, t, r, now, sum, count, pd.fp,
		chain.Detail{Key: "dcs_answered", Value: strconv.Itoa(rec.DCsAnswered)},
		chain.Detail{Key: "dcs_in_scope", Value: strconv.Itoa(rec.DCsInScope)})
}

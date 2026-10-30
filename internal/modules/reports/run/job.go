package run

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"encoding/json/jsontext"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/audit/chain"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/reportsql"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// Kind is the reports.run job kind (EP-5), registered by the composition root.
func (s *Service) Kind() jobs.Kind {
	return jobs.Kind{
		Name: JobKind, Timeout: JobTimeout, Mode: jobs.ModeManagedTx,
		ValidateArgs: func(args jsontext.Value) error {
			var a jobArgs
			if err := json.Unmarshal(args, &a); err != nil {
				return errors.New("reports.run: bad args")
			}
			if _, err := ParseID(a.RunID); err != nil {
				return errors.New("reports.run: bad run id")
			}
			return nil
		},
		RunManaged: s.runJob,
	}
}

// errStopped aborts T2 when the run is no longer ours (cancelled, failed, or another attempt).
var errStopped = errors.New("run: the run is no longer this attempt's")

// runFailure is a T2 outcome that fails the run with a stable reason.
type runFailure struct {
	reason FailureReason
	detail map[string]int64
}

func (f *runFailure) Error() string { return "run failed: " + string(f.reason) }

func (s *Service) runJob(ctx context.Context, tx jobs.TenantTx, c jobs.Claimed) error {
	var a jobArgs
	if err := json.Unmarshal(c.Args, &a); err != nil {
		return &jobs.Failure{Code: "bad_args", Permanent: true}
	}
	id, err := ParseID(a.RunID)
	if err != nil {
		return &jobs.Failure{Code: "bad_args", Permanent: true}
	}

	// T1: take the run. The row lock serialises two deliveries of the same job.
	var r Run
	var go_ bool
	err = tx.Run(ctx, func(ctx context.Context, t store.Tx) error {
		cur, err := load(ctx, t, id, true)
		if errors.Is(err, ErrRunNotFound) {
			return nil // the record is gone: nothing to do
		}
		if err != nil {
			return err
		}
		r = cur
		switch cur.State {
		case StateQueued:
			def, ok := s.Catalog.Definition(cur.DefinitionID, cur.DefinitionVer)
			if !ok || def.SHA256 != cur.DefinitionSHA256 {
				return s.finish(ctx, t, cur, StateFailed, FailDefinitionRetired, nil)
			}
			if _, err := t.Exec(ctx, startRun, id.String(), c.Attempt, s.now()); err != nil {
				return err
			}
			go_ = true
		case StateRunning:
			// A delivery that finds its run running never resumes it (§6.3 rule 6).
			return s.finish(ctx, t, cur, StateFailed, FailInterrupted, nil)
		}
		return nil
	})
	if err != nil || !go_ {
		return err
	}

	// T2: read, store, finish. One transaction, one commit.
	fail := s.execute(ctx, tx, c.Tenant, r, c.Attempt)
	if fail == nil {
		return nil
	}
	if errors.Is(fail, errStopped) {
		return nil
	}
	reason, detail := FailInternal, map[string]int64(nil)
	var rf *runFailure
	switch {
	case errors.As(fail, &rf):
		reason, detail = rf.reason, rf.detail
	case errors.Is(fail, ctx.Err()) && ctx.Err() != nil:
		return fail // the worker is stopping: leave the claim to lapse
	}
	return tx.Run(ctx, func(ctx context.Context, t store.Tx) error {
		cur, err := load(ctx, t, id, true)
		if err != nil {
			return err
		}
		if cur.State != StateRunning || cur.Attempt != c.Attempt {
			return nil
		}
		return s.finish(ctx, t, cur, StateFailed, reason, detail)
	})
}

const startRun = `UPDATE public.report_runs SET state = 'running', attempt = $2, started_at = $3 WHERE id = $1::uuid AND state = 'queued'`

const fenceScope = `UPDATE public.report_runs SET scope_fingerprint = $2 WHERE id = $1::uuid AND state = 'running' AND attempt = $3`

const insertRows = `INSERT INTO public.report_run_rows (tenant_id, run_id, row_key, ordinal, cells, sort_keys)
SELECT NULLIF(current_setting('app.tenant_id', true), '')::uuid, $1::uuid, u.row_key, u.ordinal, u.cells::jsonb, u.sort_keys::jsonb
FROM unnest($2::text[], $3::bigint[], $4::text[], $5::text[]) AS u(row_key, ordinal, cells, sort_keys)`

const succeedRun = `UPDATE public.report_runs SET state = 'succeeded', row_count = $3, objects_checked = $4, hidden_counts = $5::jsonb,
  digest = $6, as_of = $7, freshness = $8::jsonb, scope_applied = $9::jsonb, finished_at = $10, expires_at = $11
WHERE id = $1::uuid AND state = 'running' AND attempt = $2`

// execute is T2. Any non-nil result rolled the transaction back, so no row of this attempt survives.
func (s *Service) execute(ctx context.Context, jt jobs.TenantTx, tid tenant.ID, r Run, attempt int) error {
	def, ok := s.Catalog.Definition(r.DefinitionID, r.DefinitionVer)
	if !ok || def.SHA256 != r.DefinitionSHA256 {
		return &runFailure{reason: FailDefinitionRetired}
	}
	if def.Def.PerDC != nil {
		return &runFailure{reason: FailInternal} // per-DC runs are row B8's
	}
	rp, err := s.Codec.Decode(r.Params)
	if err != nil {
		return err
	}
	q, err := report.Resolve(def.Def, r.Preset, rp, def.Dataset)
	if err != nil {
		return err
	}
	if q.Hash() != r.QueryHash || q.PerDCWhere != nil {
		return &runFailure{reason: FailInternal}
	}
	cols := make([]report.Column, len(q.Columns))
	for i, id := range q.Columns {
		c, ok := def.Dataset.Column(id)
		if !ok {
			return &runFailure{reason: FailInternal}
		}
		if _, perDC := c.Source.(report.PerDC); perDC {
			return &runFailure{reason: FailInternal}
		}
		cols[i] = c
	}
	colIDs := columnIDs(q.Columns)
	rowCap := s.rowCap()

	// The freshness reader opens its own transaction, and a transaction cannot open another on its own
	// context, so the watermarks are read between two short transactions: the first names the connections
	// the scope reaches, the second (T2) proves the scope is still that one before it reads anything.
	for try := 0; ; try++ {
		var conns []authz.ObjectID
		var fp0 [32]byte
		if err := jt.Run(ctx, func(ctx context.Context, t store.Tx) error {
			scope, err := s.scopeOf(ctx, t, tid, r.Chain)
			if err != nil {
				return err
			}
			fp0, conns = scope.Fingerprint(), s.covered(scope, q.Narrowing.Connections)
			return nil
		}); err != nil {
			return err
		}
		now := s.now()
		fr, err := s.freshness(ctx, tid, conns, now)
		if err != nil {
			return err
		}
		err = s.store(ctx, jt, tid, r, attempt, def, q, cols, colIDs, fp0, fr, now, rowCap)
		if errors.Is(err, errScopeMoved) && try < 2 {
			continue
		}
		if errors.Is(err, errScopeMoved) {
			return &runFailure{reason: FailInternal}
		}
		return err
	}
}

var errScopeMoved = errors.New("run: the read scope changed while the run started")

func (s *Service) scopeOf(ctx context.Context, t store.Tx, tid tenant.ID, c authority.Chain) (authz.ReadScope, error) {
	scope, err := s.Scopes.For(ctx, t, tid, c, Perm)
	switch {
	case errors.Is(err, authz.ErrOwnerDead):
		return authz.ReadScope{}, &runFailure{reason: FailRunnerInactive}
	case errors.Is(err, authz.ErrTokenRefused):
		return authz.ReadScope{}, &runFailure{reason: FailTokenRefused}
	}
	return scope, err
}

// covered is the connections the scope reaches, narrowed by the admin's pick.
func (s *Service) covered(scope authz.ReadScope, narrowed []authz.ObjectID) []authz.ObjectID {
	conns := scope.Connections()
	if len(narrowed) > 0 {
		conns = slices.DeleteFunc(conns, func(c authz.ObjectID) bool { return !slices.Contains(narrowed, c) })
	}
	return conns
}

// store is T2: one transaction holds the snapshot, the rows and the final state.
func (s *Service) store(ctx context.Context, jt jobs.TenantTx, tid tenant.ID, r Run, attempt int, def Definition, q report.Query,
	cols []report.Column, colIDs []string, fp0 [32]byte, fr FreshnessRecord, now time.Time, rowCap int) error {
	return jt.Run(ctx, func(ctx context.Context, t store.Tx) error {
		// 2.1 the scope, now
		scope, err := s.scopeOf(ctx, t, tid, r.Chain)
		if err != nil {
			return err
		}
		// 2.2 the scope APPLIED is what later reads compare with
		fp := scope.Fingerprint()
		if fp != fp0 {
			return errScopeMoved
		}
		if tag, err := t.Exec(ctx, fenceScope, r.ID.String(), fp[:], attempt); err != nil {
			return err
		} else if tag.RowsAffected() != 1 {
			return errStopped
		}
		// 2.3 freshness was read before this snapshot opened, so as_of never claims newer data
		// 2.4 compile
		cq, err := reportsql.Compile(q, def.SQL, scope, reportsql.Inputs{Now: now, Limit: rowCap + 1})
		switch {
		case errors.Is(err, reportsql.ErrScopeTooLarge):
			return &runFailure{reason: FailScopeTooLarge}
		case err != nil:
			return err
		}
		// 2.5 stream, 2.6 cap
		dig := newDigester(colIDs)
		hidden := map[string]int64{}
		var stored, hiddenN, ordinal int64
		var keys, cells, sorts []string
		var ords []int64
		flush := func(ctx context.Context) error {
			if len(keys) == 0 {
				return nil
			}
			if _, err := t.Exec(ctx, insertRows, r.ID.String(), keys, ords, cells, sorts); err != nil {
				return err
			}
			keys, ords, cells, sorts = keys[:0], ords[:0], cells[:0], sorts[:0]
			return nil
		}
		delivered, err := reportsql.Exec(ctx, t, cq, BatchSize, func(ctx context.Context, rows []report.Row) error {
			for _, row := range rows {
				if g := firstHidden(row.Hidden); g >= 0 {
					hidden[q.Hidden[g].ID]++
					hiddenN++
					continue
				}
				cj, err := json.Marshal(row.Cells)
				if err != nil {
					return err
				}
				sk := make(map[string]string, len(cols))
				for i, c := range cols {
					if k, ok := report.CellSortKey(row.Cells[i], c); ok {
						sk[string(c.ID)] = k
					}
				}
				sj, err := json.Marshal(sk)
				if err != nil {
					return err
				}
				keys, ords, cells, sorts = append(keys, row.Key), append(ords, ordinal), append(cells, string(cj)), append(sorts, string(sj))
				ordinal++
				stored++
				dig.row(row.Cells)
			}
			return flush(ctx)
		})
		if err != nil {
			switch {
			case errors.Is(err, reportsql.ErrQueryTimeout):
				return &runFailure{reason: FailQueryTimeout}
			case store.SQLState(err) == "AD403":
				return errStopped // the run was cancelled or failed under us
			}
			return err
		}
		if delivered > int64(rowCap) {
			// Refuse and explain (FR-18): count the whole result in this doomed transaction for the message.
			total := delivered
			if cc, err := reportsql.CompileCount(q, def.SQL, scope, reportsql.Inputs{Now: now}); err == nil {
				if n, err := reportsql.Count(ctx, t, cc); err == nil {
					total = n
				}
			}
			return &runFailure{reason: FailRowCapExceeded, detail: map[string]int64{"cap": int64(rowCap), "rows": total}}
		}
		// 2.7 finish in the same transaction
		hj, _ := json.Marshal(hidden)
		fj, _ := json.Marshal(fr)
		sa := ScopeApplied{Summary: scope.Summary(), Reasons: cq.ScopeReasons()}
		if stored == 0 {
			sa.EmptyReason = emptyReason(cq.ScopeReasons())
		}
		saj, _ := json.Marshal(sa)
		asOf := now
		if fr.AsOf != nil {
			asOf = *fr.AsOf
		}
		tag, err := t.Exec(ctx, succeedRun, r.ID.String(), attempt, stored, stored+hiddenN, string(hj), dig.sum(), asOf, string(fj), string(saj), now, now.Add(ResultRetention))
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return errStopped
		}
		return s.Audit.Append(ctx, t, audit.Event{ID: "run:" + r.ID.String() + ":completed", Kind: KindCompleted, At: now, Actor: r.Chain,
			Target: authority.TargetRef{GUID: r.ID.String(), Class: "report_run"}, Component: Component, Outcome: audit.Success,
			Details: sortDetails([]chain.Detail{
				{Key: "definition", Value: r.DefinitionID + "@" + strconv.Itoa(r.DefinitionVer)},
				{Key: "digest", Value: hexOf(dig.sum())},
				{Key: "preset", Value: r.Preset},
				{Key: "query_hash", Value: hexOf(r.QueryHash[:])},
				{Key: "row_count", Value: strconv.FormatInt(stored, 10)},
				{Key: "run_id", Value: r.ID.String()},
				{Key: "scope_fingerprint", Value: hexOf(fp[:])},
			})})
	})
}

func firstHidden(h []bool) int {
	for i, x := range h {
		if x {
			return i
		}
	}
	return -1
}

func hexOf(b []byte) string { return hex.EncodeToString(b) }

// emptyReason says why a scope-empty result is empty, in the API's two words; "" when filters did it.
func emptyReason(reasons []string) string {
	out := ""
	for _, r := range reasons {
		switch {
		case strings.HasPrefix(r, "scope_kind_unsupported:"), strings.HasPrefix(r, "scope_term_unsupported:"):
			return "unsupported_scope_kind"
		case r == "scope_empty":
			out = "scope_grants_nothing"
		}
	}
	return out
}

// freshness reads the watermarks of the covered connections
// and labels them (§6.4). A scope that reaches no connection covers nothing: not synced yet.
func (s *Service) freshness(ctx context.Context, tid tenant.ID, conns []authz.ObjectID, now time.Time) (FreshnessRecord, error) {
	var lbl report.Freshness
	var thr time.Duration
	if len(conns) == 0 {
		lbl = report.Label(nil, 0, now)
	} else {
		var err error
		if lbl, thr, err = s.Fresh.Freshness(ctx, tid, conns, now); err != nil {
			return FreshnessRecord{}, err
		}
	}
	rec := FreshnessRecord{State: lbl.State.String(), Threshold: int64(thr / time.Second), ComputedAt: now}
	if !lbl.AsOf.IsZero() {
		t := lbl.AsOf.UTC()
		rec.AsOf = &t
	}
	for _, st := range lbl.Stale {
		rec.Stale = append(rec.Stale, StaleEntry{Connection: report.GUIDString(st.Connection), NC: report.GUIDString(st.NC),
			AgeSeconds: int64(st.Age / time.Second), State: ncStateText(st.State)})
	}
	for _, c := range lbl.NotSynced {
		rec.NotSynced = append(rec.NotSynced, report.GUIDString(c))
	}
	rec.Label = LabelText(rec.State, rec.Stale)
	return rec, nil
}

func ncStateText(s report.NCState) string {
	switch s {
	case report.NCOK:
		return "ok"
	case report.NCResyncRequired:
		return "resync_required"
	case report.NCPaused:
		return "paused"
	}
	return "never_synced"
}

// LabelText is the header text of a freshness state: "Live" is never used (§6.4).
func LabelText(state string, stale []StaleEntry) string {
	switch state {
	case "synced":
		return "Synced"
	case "stale":
		if len(stale) > 0 {
			return "Stale: oldest sync pass " + (time.Duration(stale[0].AgeSeconds) * time.Second).Round(time.Minute).String() + " ago"
		}
		return "Stale"
	}
	return "Not synced yet"
}

package run

import (
	"context"
	"errors"
	"slices"

	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// LatestState is the one state a Home widget renders (home-report-widgets §3.3). The two states the
// client alone decides (a failed request, a missing permission) are not here.
type LatestState string

// The states Latest answers.
const (
	LatestCurrent      LatestState = "current"
	LatestStaleData    LatestState = "stale_data"
	LatestScopeChanged LatestState = "scope_changed"
	LatestExpired      LatestState = "expired"
	LatestRunning      LatestState = "running"
	LatestFailed       LatestState = "failed"
	LatestNeverRun     LatestState = "never_run"
	LatestUnavailable  LatestState = "unavailable"
)

// WidgetRows is the page size of a table widget (§3.1).
const WidgetRows = 10

// ErrNoTableView means rows were asked of a definition whose widget profile has no table view.
var ErrNoTableView = errors.New("run: the definition has no table widget view") // 400

// Latest is the answer of the widget host's one backend call.
type Latest struct {
	State    LatestState
	Run      *Run // the run the state describes; nil for never_run and unavailable
	InFlight *Run // a queued or running run newer than Run
	// Serves is true when Run is a succeeded, unexpired run trimmed with the caller's current scope: only then
	// are its row count and rows the caller's to see.
	Serves  bool
	Columns []report.Column
	Rows    []StoredRow
}

// A scheduled run belongs to the schedule's owner, so the only runs that can be candidates are the
// caller's: runner_account is bound to the principal and no parameter names another account.
const latestRuns = `SELECT id::text, definition_id, definition_version, definition_sha256, preset, params, query_hash,
  scope_fingerprint, runner_account::text, chain, schedule_id::text, rerun_of::text, state, failure_reason, attempt,
  scope_applied, freshness, per_dc, as_of, row_count, objects_checked, hidden_counts, digest, columns,
  created_at, started_at, finished_at, expires_at FROM public.report_runs
WHERE runner_account = $1::uuid AND definition_id = $2 AND preset = $3
  AND state IN ('queued', 'running', 'succeeded', 'failed', 'expired')
ORDER BY created_at DESC, id DESC LIMIT $4`

// latestWindow bounds the look-back: enough newer failed or running runs to reach the last success.
const latestWindow = 50

// Latest answers the caller's latest run of a definition and preset for a widget. It never creates a run.
// When rows is WidgetRows the first page goes through Page, so run.ReadAccess is the only gate to rows;
// the header-only state compares the stored scope fingerprint with the caller's current one, as List does.
func (s *Service) Latest(ctx context.Context, tid tenant.ID, chain authority.Chain, definitionID, preset string, rows int) (Latest, error) {
	if rows != 0 && rows != WidgetRows {
		return Latest{}, ErrBadLimit
	}
	def, ok := s.Catalog.Definition(definitionID, 0)
	if !ok {
		return Latest{State: LatestUnavailable}, nil
	}
	if preset == "" {
		preset = def.Def.Presets[0].ID
	} else if _, ok := def.Def.Preset(preset); !ok {
		return Latest{State: LatestUnavailable}, nil
	}
	if rows > 0 && !def.Def.SupportsWidget(report.WidgetTable) {
		return Latest{}, ErrNoTableView
	}
	var runs []Run
	var fp [32]byte
	err := s.DB.WithTenant(ctx, tid, func(ctx context.Context, tx store.Tx) error {
		scope, err := s.Scopes.For(ctx, tx, tid, chain, Perm)
		if err != nil {
			return err
		}
		fp = scope.Fingerprint()
		rs, err := tx.Query(ctx, latestRuns, string(chain.Requester.ID), definitionID, preset, latestWindow)
		if err != nil {
			return err
		}
		defer rs.Close()
		for rs.Next() {
			r, err := scanRun(rs)
			if err != nil {
				return err
			}
			runs = append(runs, r)
		}
		return rs.Err()
	})
	if err != nil {
		return Latest{}, err
	}
	out := s.chooseLatest(runs, fp)
	if rows == 0 || !out.Serves {
		return out, nil
	}
	pg, err := s.Page(ctx, tid, chain, out.Run.ID, PageQuery{Limit: WidgetRows})
	switch {
	case errors.Is(err, ErrScopeChanged): // narrowed between the header read and the page
		return Latest{State: LatestScopeChanged, Run: out.Run, InFlight: out.InFlight}, nil // Serves stays false
	case errors.Is(err, ErrRunExpired):
		return Latest{State: LatestExpired, Run: out.Run, InFlight: out.InFlight}, nil
	case err != nil:
		return Latest{}, err
	}
	out.Columns, out.Rows = widgetTable(def.Def, pg)
	return out, nil
}

// chooseLatest picks the run a widget describes from the caller's runs, newest first. The latest
// succeeded run is preferred over a newer failed one; a newer queued or running run is InFlight.
func (s *Service) chooseLatest(runs []Run, fp [32]byte) Latest {
	if len(runs) == 0 {
		return Latest{State: LatestNeverRun}
	}
	now := s.now()
	var out Latest
	newest := runs[0]
	if newest.State == StateQueued || newest.State == StateRunning {
		r := newest
		out.InFlight = &r
	}
	i := slices.IndexFunc(runs, func(r Run) bool { return r.State == StateSucceeded || r.State == StateExpired })
	var done *Run
	if i >= 0 {
		done = &runs[i]
	}
	live := done != nil && done.EffectiveState(now) == StateSucceeded
	switch {
	case live && done.ScopeFingerprint != fp:
		out.Run = done
		out.State = LatestScopeChanged
		if out.InFlight != nil {
			out.State = LatestRunning
		}
	case live:
		out.Run = done
		out.Serves = true
		out.State = LatestCurrent
		if f := done.Freshness; f != nil && f.State == "stale" {
			out.State = LatestStaleData
		}
		if out.InFlight != nil {
			out.State = LatestRunning
		}
	case out.InFlight != nil:
		out.State = LatestRunning
		out.Run = out.InFlight
	case newest.State == StateFailed:
		out.State, out.Run = LatestFailed, &runs[0]
	case done != nil:
		out.State, out.Run = LatestExpired, done
	default:
		out.State = LatestNeverRun
	}
	return out
}

// widgetTable trims a page to the profile's table columns, in the profile's order.
func widgetTable(def report.Definition, pg Page) ([]report.Column, []StoredRow) {
	if def.Widget == nil {
		return nil, nil
	}
	var idx []int
	var cols []report.Column
	for _, id := range def.Widget.TableColumns {
		if i := slices.IndexFunc(pg.Columns, func(c report.Column) bool { return c.ID == id }); i >= 0 {
			idx = append(idx, i)
			cols = append(cols, pg.Columns[i])
		}
	}
	rows := make([]StoredRow, 0, len(pg.Rows))
	for _, r := range pg.Rows {
		nr := StoredRow{Key: r.Key, Ordinal: r.Ordinal}
		for _, i := range idx {
			if i < len(r.Cells) {
				nr.Cells = append(nr.Cells, r.Cells[i])
			}
		}
		rows = append(rows, nr)
	}
	return cols, rows
}

package run

import (
	"context"
	"strconv"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/audit/chain"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// retentionActor is the system principal of the events the sweep appends.
var retentionActor = authority.Chain{Requester: authority.Principal{ID: "reports-retention", Kind: authority.System}}

// RetentionBatch is how many rows one delete transaction removes (§11).
const RetentionBatch = 10_000

// RetentionResult counts what one sweep did.
type RetentionResult struct{ Expired, RowsDeleted, RecordsDeleted, ExportsExpired, ExportRecordsDeleted int64 }

const (
	// succeeded runs past their expiry become expired; the rows follow in batches
	expireRuns = `UPDATE public.report_runs SET state = 'expired' WHERE state = 'succeeded' AND expires_at <= $1`
	// an export whose file is past its expiry is flipped; blob.Sweep removes the artefact itself
	expireExports = `UPDATE public.report_exports SET state = 'expired' WHERE state = 'succeeded' AND expires_at <= $1
  RETURNING id::text, format, row_count, encode(digest, 'hex')`
	// an export record that holds no file is kept as long as a run record, then goes
	deleteExportRecords = `DELETE FROM public.report_exports e WHERE e.state IN ('failed', 'expired', 'deleted')
  AND e.expires_at + make_interval(secs => $2::double precision) <= $1`
	// a run that holds no result (failed, cancelled, expired) and still has rows
	runsWithRows = `SELECT r.id::text FROM public.report_runs r WHERE r.state IN ('failed', 'cancelled', 'expired')
  AND EXISTS (SELECT 1 FROM public.report_run_rows w WHERE w.tenant_id = r.tenant_id AND w.run_id = r.id) LIMIT 100`
	deleteRowBatch = `DELETE FROM public.report_run_rows WHERE (tenant_id, run_id, row_key) IN
  (SELECT tenant_id, run_id, row_key FROM public.report_run_rows WHERE run_id = $1::uuid LIMIT ` + "10000" + `)`
	// the record stays readable for RecordRetention after expires_at; a run another still names as its
	// source stays until that one goes
	deleteRecords = `DELETE FROM public.report_runs r WHERE r.state IN ('failed', 'cancelled', 'expired')
  AND r.expires_at + make_interval(secs => $2::double precision) <= $1
  AND NOT EXISTS (SELECT 1 FROM public.report_run_rows w WHERE w.tenant_id = r.tenant_id AND w.run_id = r.id)
  AND NOT EXISTS (SELECT 1 FROM public.report_runs x WHERE x.tenant_id = r.tenant_id AND x.rerun_of = r.id)
  AND NOT EXISTS (SELECT 1 FROM public.report_exports e WHERE e.tenant_id = r.tenant_id AND (e.run_id = r.id OR e.rerun_of_run_id = r.id))`
)

// Retention is the reports.retention sweep for one tenant (§11): flip runs past expires_at to expired,
// delete their rows in batches of RetentionBatch (each batch its own transaction, so it never holds a
// long lock), flip exports past their expiry to expired (audited, system actor) and delete final run and
// export records RecordRetention after expires_at.
func (s *Service) Retention(ctx context.Context, tid tenant.ID, now time.Time) (RetentionResult, error) {
	var res RetentionResult
	if err := s.DB.WithTenant(ctx, tid, func(ctx context.Context, tx store.Tx) error {
		tag, err := tx.Exec(ctx, expireRuns, now)
		res.Expired = tag.RowsAffected()
		return err
	}); err != nil {
		return res, err
	}
	if err := s.DB.WithTenant(ctx, tid, func(ctx context.Context, tx store.Tx) error {
		rows, err := tx.Query(ctx, expireExports, now)
		if err != nil {
			return err
		}
		type expired struct {
			id, format, digest string
			rows               *int64
		}
		var done []expired
		for rows.Next() {
			var e expired
			var digest *string
			if err := rows.Scan(&e.id, &e.format, &e.rows, &digest); err != nil {
				rows.Close()
				return err
			}
			if digest != nil {
				e.digest = *digest
			}
			done = append(done, e)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, e := range done {
			det := []chain.Detail{{Key: "digest", Value: e.digest}, {Key: "export_id", Value: e.id}, {Key: "format", Value: e.format}}
			if e.rows != nil {
				det = append(det, chain.Detail{Key: "row_count", Value: strconv.FormatInt(*e.rows, 10)})
			}
			if err := s.Audit.Append(ctx, tx, audit.Event{ID: "export:" + e.id + ":expired", Kind: KindExportExpired, At: now, Actor: retentionActor,
				Target: authority.TargetRef{GUID: e.id, Class: "report_export"}, Component: Component, Outcome: audit.Success,
				Details: sortDetails(det)}); err != nil {
				return err
			}
		}
		res.ExportsExpired = int64(len(done))
		return nil
	}); err != nil {
		return res, err
	}
	for {
		var ids []string
		if err := s.DB.WithTenant(ctx, tid, func(ctx context.Context, tx store.Tx) error {
			rows, err := tx.Query(ctx, runsWithRows)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var id string
				if err := rows.Scan(&id); err != nil {
					return err
				}
				ids = append(ids, id)
			}
			return rows.Err()
		}); err != nil {
			return res, err
		}
		if len(ids) == 0 {
			break
		}
		for _, id := range ids {
			for {
				var n int64
				if err := s.DB.WithTenant(ctx, tid, func(ctx context.Context, tx store.Tx) error {
					tag, err := tx.Exec(ctx, deleteRowBatch, id)
					n = tag.RowsAffected()
					return err
				}); err != nil {
					return res, err
				}
				res.RowsDeleted += n
				if n < RetentionBatch {
					break
				}
				if err := ctx.Err(); err != nil {
					return res, err
				}
			}
		}
	}
	err := s.DB.WithTenant(ctx, tid, func(ctx context.Context, tx store.Tx) error {
		tag, err := tx.Exec(ctx, deleteExportRecords, now, RecordRetention.Seconds())
		if err != nil {
			return err
		}
		res.ExportRecordsDeleted = tag.RowsAffected()
		tag, err = tx.Exec(ctx, deleteRecords, now, RecordRetention.Seconds())
		res.RecordsDeleted = tag.RowsAffected()
		return err
	})
	return res, err
}

// RetentionKind is the daily per-tenant reports.retention job. It reschedules itself 24 hours on, keyed
// by day, so seeding it on every boot leaves one cadence (the pattern of authn.throttle.purge).
func (s *Service) RetentionKind() jobs.Kind {
	return jobs.Kind{
		Name: RetentionKind, Timeout: 30 * time.Minute, Mode: jobs.ModeManagedTx,
		RunManaged: func(ctx context.Context, tx jobs.TenantTx, c jobs.Claimed) error {
			if _, err := s.Retention(ctx, c.Tenant, s.now()); err != nil {
				return err
			}
			return tx.Run(ctx, func(ctx context.Context, t store.Tx) error {
				return s.scheduleRetention(ctx, t, c.Tenant, s.now().Add(24*time.Hour))
			})
		},
	}
}

// ScheduleRetention seeds the tenant's cadence; it is safe to call on every boot.
func (s *Service) ScheduleRetention(ctx context.Context, tx store.Tx, tid tenant.ID) error {
	return s.scheduleRetention(ctx, tx, tid, s.now())
}

func (s *Service) scheduleRetention(ctx context.Context, tx store.Tx, tid tenant.ID, at time.Time) error {
	_, err := s.Jobs.Enqueue(ctx, tx, jobs.Job{Kind: RetentionKind, Tenant: tid, Args: struct{}{},
		UniqueKey: "day:" + at.UTC().Format("2006-01-02"), RunAt: at})
	return err
}

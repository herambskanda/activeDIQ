package run

import (
	"context"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// RetentionBatch is how many rows one delete transaction removes (§11).
const RetentionBatch = 10_000

// RetentionResult counts what one sweep did.
type RetentionResult struct{ Expired, RowsDeleted, RecordsDeleted int64 }

const (
	// succeeded runs past their expiry become expired; the rows follow in batches
	expireRuns = `UPDATE public.report_runs SET state = 'expired' WHERE state = 'succeeded' AND expires_at <= $1`
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
  AND NOT EXISTS (SELECT 1 FROM public.report_runs x WHERE x.tenant_id = r.tenant_id AND x.rerun_of = r.id)`
)

// Retention is the reports.retention sweep for one tenant (§11): flip runs past expires_at to expired,
// delete their rows in batches of RetentionBatch (each batch its own transaction, so it never holds a
// long lock), and delete final records RecordRetention after expires_at. Exports are B9's.
func (s *Service) Retention(ctx context.Context, tid tenant.ID, now time.Time) (RetentionResult, error) {
	var res RetentionResult
	if err := s.DB.WithTenant(ctx, tid, func(ctx context.Context, tx store.Tx) error {
		tag, err := tx.Exec(ctx, expireRuns, now)
		res.Expired = tag.RowsAffected()
		return err
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
		tag, err := tx.Exec(ctx, deleteRecords, now, RecordRetention.Seconds())
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

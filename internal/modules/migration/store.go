package migration

import (
	"context"
	"errors"
	"fmt"

	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/store"
)

// This file holds all the SQL of the module. Every write takes a step.Step and runs in its transaction
// (the O3 rule): only the two Actions reach it.

// insertProject adds a project and returns its ID.
func insertProject(ctx context.Context, s step.Step, tenantID, name, createdBy string) (string, error) {
	tx := s.Tx()
	if tx == nil {
		return "", errors.New("migration: no step transaction")
	}
	var id string
	err := tx.QueryRow(ctx, `INSERT INTO public.migration_projects (tenant_id, name, created_by)
		VALUES ($1::uuid, $2, $3) RETURNING project_id::text`, tenantID, name, createdBy).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("migration: insert project: %w", err)
	}
	return id, nil
}

// activeCounts returns the active (quarantined or running) jobs of the tenant and of the actor.
func activeCounts(ctx context.Context, tx store.Tx, tenantID, actor string) (tenantN, userN int, err error) {
	err = tx.QueryRow(ctx, `SELECT count(*)::int, count(*) FILTER (WHERE actor = $2)::int
		FROM public.migration_jobs WHERE tenant_id = $1::uuid AND state IN ('quarantined', 'running')`,
		tenantID, actor).Scan(&tenantN, &userN)
	return
}

// projectOpen reports whether the tenant has an open project with that ID.
func projectOpen(ctx context.Context, tx store.Tx, tenantID, projectID string) (bool, error) {
	var n int
	err := tx.QueryRow(ctx, `SELECT count(*)::int FROM public.migration_projects
		WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND closed_at IS NULL`, tenantID, projectID).Scan(&n)
	return n == 1, err
}

// jobRow is the stored form of a job's identity.
type jobRow struct {
	JobID, ProjectID, Actor, Kind, Build, State, LimitHit string
	SHA                                                   []byte
	Size                                                  int64
}

// insertJob adds a job. A rejected job has no SHA-256 and a limit code; any other starts quarantined and
// is counted against the quotas, re-checked here under a per-tenant advisory lock so two concurrent
// submissions cannot both pass.
func insertJob(ctx context.Context, s step.Step, tenantID string, j jobRow) error {
	tx := s.Tx()
	if tx == nil {
		return errors.New("migration: no step transaction")
	}
	if j.State != "rejected" {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('migration.quota:' || $1, 0))`, tenantID); err != nil {
			return fmt.Errorf("migration: quota lock: %w", err)
		}
		tn, un, err := activeCounts(ctx, tx, tenantID, j.Actor)
		if err != nil {
			return fmt.Errorf("migration: quota count: %w", err)
		}
		if un >= MaxActivePerUser {
			return ErrQuotaUser
		}
		if tn >= MaxActivePerTenant {
			return ErrQuotaTenant
		}
	}
	var sha, limit any
	if j.State != "rejected" {
		sha = j.SHA
	} else {
		limit = j.LimitHit
	}
	_, err := tx.Exec(ctx, `INSERT INTO public.migration_jobs
		(tenant_id, job_id, project_id, actor, source_kind, source_sha256, admp_build, size_bytes, state, limit_hit, finished_at)
		VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7, $8, $9, $10, CASE WHEN $9 = 'rejected' THEN now() END)`,
		tenantID, j.JobID, j.ProjectID, j.Actor, j.Kind, sha, j.Build, j.Size, j.State, limit)
	if err != nil {
		return fmt.Errorf("migration: insert job: %w", err)
	}
	return nil
}

// getJob reads one job of the transaction's tenant.
func getJob(ctx context.Context, tx store.Tx, jobID string) (jobRow, bool, error) {
	var j jobRow
	var limit *string
	err := tx.QueryRow(ctx, `SELECT job_id::text, project_id::text, actor, source_kind, source_sha256, admp_build, size_bytes, state, limit_hit
		FROM public.migration_jobs WHERE job_id = $1::uuid`, jobID).
		Scan(&j.JobID, &j.ProjectID, &j.Actor, &j.Kind, &j.SHA, &j.Build, &j.Size, &j.State, &limit)
	if store.IsNoRows(err) {
		return jobRow{}, false, nil
	}
	if limit != nil {
		j.LimitHit = *limit
	}
	return j, err == nil, err
}

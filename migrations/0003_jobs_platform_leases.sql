-- 0003_jobs_platform_leases: platform leases (DM-06, ADR-0002 Jobs row as amended 2026-10-02, ADR-0005
-- rule 6). Owner: internal/platform/jobs.
--
-- A lease is exclusive, expiring ownership of singleton platform work: the job rescuer and the job
-- cleaner today, schedulers and the migration lease later. `platform_leases` is a registered global table:
-- it has no tenant_id and no RLS, because the work it guards runs over every tenant. Only the owning
-- package may name it in SQL (fitness-tenancy T5 global-table-sql). Tenant leases (the DM-06 tenant shape,
-- under RLS) are a separate table that lands with its first user.
--
-- fencing_token only ever rises: every acquisition of a lease that was free or expired bumps it, so a
-- holder that lost the lease can be told apart from the one that took it over. Expiry is judged on the
-- database clock (now()), never a node's.

CREATE TABLE public.platform_leases (
  name text PRIMARY KEY CHECK (name ~ '^[a-z][a-z0-9_.]{0,99}$'),
  holder text NOT NULL CHECK (holder ~ '^[A-Za-z0-9._:@-]{1,200}$'),
  fencing_token bigint NOT NULL CHECK (fencing_token >= 1),
  expires_at timestamptz NOT NULL,
  acquired_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE public.platform_leases IS 'Registered global table (ADR-0002 Jobs row, DM-06): exclusive expiring ownership of singleton platform work, with a monotonic fencing token. Only internal/platform/jobs references it in SQL.';

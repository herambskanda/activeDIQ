-- 0002_jobs_jobs: the job queue (ADR-0001 E3, ADR-0002 Jobs row as amended 2026-10-02, DM-43). Owner:
-- internal/platform/jobs.
--
-- `jobs` is a registered global table: claiming must see every tenant's work, so it carries no RLS. Its
-- tenant_id is nullable (null only for a registered platform kind), and the guard trigger below is what
-- makes the database itself refuse a job enqueued for a tenant other than the transaction's context.
-- Only the owning package may name the table in SQL (fitness-tenancy T5 global-table-sql).

-- write-class: jobs system
CREATE TABLE public.jobs (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id uuid REFERENCES public.tenants (id),
  kind text NOT NULL CHECK (kind ~ '^[a-z][a-z0-9_.]{0,99}$'),
  -- Typed references only (T5 job-args-reference): never personal values, secrets or error text.
  args jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(args) = 'object' AND octet_length(args::text) <= 4096),
  unique_key text CHECK (unique_key <> '' AND length(unique_key) <= 200),
  state text NOT NULL DEFAULT 'available' CHECK (state IN ('available', 'running', 'completed', 'discarded', 'cancelled')),
  priority smallint NOT NULL DEFAULT 0,
  attempt integer NOT NULL DEFAULT 0 CHECK (attempt >= 0),
  max_attempts integer NOT NULL DEFAULT 5 CHECK (max_attempts BETWEEN 1 AND 100),
  run_at timestamptz NOT NULL DEFAULT now(),
  claimed_until timestamptz,
  -- A failure is stored as a code, never as error text.
  error_code text CHECK (error_code ~ '^[a-z][a-z0-9_]{0,63}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  finalized_at timestamptz,
  CHECK (attempt <= max_attempts),
  CHECK ((state = 'running') = (claimed_until IS NOT NULL)),
  CHECK ((state IN ('completed', 'discarded', 'cancelled')) = (finalized_at IS NOT NULL)),
  -- A platform job (no tenant) carries no tenant_id in its args; a tenant job's args name its own tenant.
  CHECK (CASE WHEN tenant_id IS NULL THEN NOT (args ? 'tenant_id') ELSE args ->> 'tenant_id' = tenant_id::text END)
);

-- DM-43 I5: a unique_key is unique per (tenant, kind) among available and running jobs. It
-- de-duplicates and never decides correctness (ADR-0005 rule 6). NULLS NOT DISTINCT makes it hold for
-- platform jobs too (PostgreSQL 15 and later; the floor is 16).
CREATE UNIQUE INDEX jobs_unique_key ON public.jobs (tenant_id, kind, unique_key) NULLS NOT DISTINCT
  WHERE unique_key IS NOT NULL AND state IN ('available', 'running');
-- The claim: runnable work in order.
CREATE INDEX jobs_claim ON public.jobs (priority, run_at, id) WHERE state = 'available';
-- The rescuer: lapsed claims.
CREATE INDEX jobs_lapsed ON public.jobs (claimed_until) WHERE state = 'running';
-- The cleaner: finished jobs past retention.
CREATE INDEX jobs_finished ON public.jobs (finalized_at) WHERE finalized_at IS NOT NULL;

COMMENT ON TABLE public.jobs IS 'Registered global table (ADR-0002 Jobs row, DM-43): the job queue. tenant_id is null only for a registered platform kind; jobs_guard refuses a cross-tenant enqueue. Only internal/platform/jobs references it in SQL.';

-- jobs_guard is SECURITY INVOKER: it reads the caller's own transaction setting, which a definer would
-- not see. The search_path is pinned so a planted object cannot shadow current_setting or NULLIF.
CREATE FUNCTION public.jobs_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $fn$
DECLARE
  ctx uuid := NULLIF(current_setting('app.tenant_id', true), '')::uuid;
BEGIN
  IF TG_OP = 'INSERT' THEN
    -- A tenant job needs that tenant's context; a platform job (null tenant) needs an empty one.
    IF NEW.tenant_id IS DISTINCT FROM ctx THEN
      RAISE EXCEPTION 'jobs: the job is for a different tenant than the transaction context' USING ERRCODE = 'AD403';
    END IF;
  ELSE
    -- The claim, rescue and clean run with no context over every tenant's rows, so an update is not
    -- compared with the context; it may not change what the job is.
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.kind IS DISTINCT FROM OLD.kind OR NEW.args IS DISTINCT FROM OLD.args THEN
      RAISE EXCEPTION 'jobs: tenant_id, kind and args never change after insert' USING ERRCODE = 'AD403';
    END IF;
  END IF;
  RETURN NEW;
END
$fn$;

CREATE TRIGGER jobs_guard BEFORE INSERT OR UPDATE ON public.jobs
  FOR EACH ROW EXECUTE FUNCTION public.jobs_guard();
-- Fire even under session_replication_role = replica.
ALTER TABLE public.jobs ENABLE ALWAYS TRIGGER jobs_guard;

-- 0079_migration_intake: migration projects and import jobs (T-2060; spec e2-11 §6.1, §7; DM-90, DM-91).
-- Owner: internal/modules/migration. Two tenant tables with forced RLS.
--
--   migration_projects  the container of one ManageEngine migration effort.
--   migration_jobs      one intake of one source. Starts `quarantined`; a source over its size limit is
--                       stored `rejected` with the limit hit and no SHA-256, because it was never read.
--
-- The runtime role cannot DELETE either table. A job's identity (project, actor, source kind, SHA-256,
-- build, size) is fixed at insert by a guard trigger; only its state and finish time move.

-- write-class: migration_projects config
CREATE TABLE public.migration_projects (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  project_id uuid NOT NULL DEFAULT gen_random_uuid(),
  name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
  created_by text NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 200),
  created_at timestamptz NOT NULL DEFAULT now(),
  closed_at timestamptz,
  PRIMARY KEY (tenant_id, project_id)
);

-- write-class: migration_jobs config
CREATE TABLE public.migration_jobs (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  job_id uuid NOT NULL DEFAULT gen_random_uuid(),
  project_id uuid NOT NULL,
  actor text NOT NULL CHECK (char_length(actor) BETWEEN 1 AND 200),
  source_kind text NOT NULL CHECK (source_kind IN ('csv', 'xlsx', 'html', 'db_dump')),
  source_sha256 bytea CHECK (octet_length(source_sha256) = 32),
  admp_build text NOT NULL CHECK (admp_build ~ '^[A-Za-z0-9._-]{1,64}$'),
  size_bytes bigint NOT NULL CHECK (size_bytes >= 0),
  state text NOT NULL DEFAULT 'quarantined' CHECK (state IN ('quarantined', 'running', 'completed', 'failed', 'cancelled', 'rejected')),
  limit_hit text CHECK (limit_hit ~ '^[a-z][a-z0-9_]{0,63}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  finished_at timestamptz,
  PRIMARY KEY (tenant_id, job_id),
  FOREIGN KEY (tenant_id, project_id) REFERENCES public.migration_projects (tenant_id, project_id),
  CHECK ((state = 'rejected') = (limit_hit IS NOT NULL)),
  CHECK ((state = 'rejected') = (source_sha256 IS NULL)),
  CHECK ((state IN ('completed', 'failed', 'cancelled', 'rejected')) = (finished_at IS NOT NULL))
);
-- The quota counts active jobs per tenant and per actor.
CREATE INDEX migration_jobs_active ON public.migration_jobs (tenant_id, actor) WHERE state IN ('quarantined', 'running');

ALTER TABLE public.migration_projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.migration_projects FORCE ROW LEVEL SECURITY;
CREATE POLICY migration_projects_tenant ON public.migration_projects
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

ALTER TABLE public.migration_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.migration_jobs FORCE ROW LEVEL SECURITY;
CREATE POLICY migration_jobs_tenant ON public.migration_jobs
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

REVOKE DELETE ON public.migration_projects, public.migration_jobs FROM activediq_app;

CREATE FUNCTION public.migration_jobs_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $fn$
BEGIN
  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.job_id IS DISTINCT FROM OLD.job_id
     OR NEW.project_id IS DISTINCT FROM OLD.project_id OR NEW.actor IS DISTINCT FROM OLD.actor
     OR NEW.source_kind IS DISTINCT FROM OLD.source_kind OR NEW.source_sha256 IS DISTINCT FROM OLD.source_sha256
     OR NEW.admp_build IS DISTINCT FROM OLD.admp_build OR NEW.size_bytes IS DISTINCT FROM OLD.size_bytes
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'migration_jobs: what a job is never changes after insert' USING ERRCODE = 'AD403';
  END IF;
  IF OLD.state IN ('completed', 'failed', 'cancelled', 'rejected') AND NEW.state IS DISTINCT FROM OLD.state THEN
    RAISE EXCEPTION 'migration_jobs: a finished job does not change state' USING ERRCODE = 'AD403';
  END IF;
  RETURN NEW;
END
$fn$;
CREATE TRIGGER migration_jobs_guard BEFORE UPDATE ON public.migration_jobs
  FOR EACH ROW EXECUTE FUNCTION public.migration_jobs_guard();
ALTER TABLE public.migration_jobs ENABLE ALWAYS TRIGGER migration_jobs_guard;

COMMENT ON TABLE public.migration_projects IS 'DM-90: a tenant''s ManageEngine migration project. Tenant table, RLS; no DELETE for the runtime role. Only internal/modules/migration references it in SQL.';
COMMENT ON TABLE public.migration_jobs IS 'DM-91: one quarantined intake of one migration source; identity fixed at insert. Tenant table, RLS; no DELETE for the runtime role. Only internal/modules/migration references it in SQL.';

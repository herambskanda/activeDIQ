-- 0064_reports_runs: the report run record and its stored result (T-0959; ADR-0010; reports.md §6.2,
-- row B4; DM-72). Owner: internal/modules/reports (run subpackage). Both are tenant tables: RLS with FORCE
-- and a tenant-led key.
--
--   report_runs       one execution of a report definition over one frozen set of inputs. The runner and
--                     the read-scope fingerprint it was trimmed with bind every later read (§6.6).
--   report_run_rows   the run's result, one row per object, written only while the run is 'running' and
--                     read only once it has 'succeeded' (ADR-0010 rule 2).
--
-- The two triggers carry the invariants the application also checks, so a bug in a caller cannot break
-- them: report_runs_guard refuses every state edge outside reports.md §6.2 and every change to a final
-- record, and report_run_rows_guard refuses a write to the rows of a run that is not running and a delete
-- of the rows of a run that is not failed, cancelled or expired.

-- write-class: report_runs system
CREATE TABLE public.report_runs (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  id uuid NOT NULL,
  definition_id text NOT NULL CHECK (definition_id ~ '^[a-z][a-z0-9-]{1,63}$'),
  definition_version integer NOT NULL CHECK (definition_version >= 1),
  definition_sha256 bytea NOT NULL CHECK (octet_length(definition_sha256) = 32),
  preset text NOT NULL CHECK (preset ~ '^[a-z][a-z0-9_]{0,63}$'),
  -- the validated request parameters, in the API shape (what a retry resolves again)
  params jsonb NOT NULL CHECK (jsonb_typeof(params) = 'object' AND octet_length(params::text) <= 65536),
  query_hash bytea NOT NULL CHECK (octet_length(query_hash) = 32),
  -- the read-scope fingerprint: set at create, overwritten by the job with the scope APPLIED (§6.3 2.2).
  scope_fingerprint bytea NOT NULL CHECK (octet_length(scope_fingerprint) = 32),
  runner_account uuid NOT NULL,
  -- the full authority.Chain (requester, then every principal acted through)
  chain jsonb NOT NULL CHECK (jsonb_typeof(chain) = 'object'),
  schedule_id uuid,
  rerun_of uuid,
  state text NOT NULL CHECK (state IN ('queued', 'running', 'succeeded', 'failed', 'cancelled', 'expired')),
  failure_reason text CHECK (failure_reason IN ('runner_inactive', 'token_refused', 'row_cap_exceeded',
    'per_dc_read_cap_exceeded', 'scope_too_large', 'query_timeout', 'connection_unavailable',
    'definition_retired', 'interrupted', 'internal')),
  -- the job attempt that owns the run (§6.3): a delivery that is not this attempt changes nothing
  attempt integer NOT NULL DEFAULT 0 CHECK (attempt >= 0),
  scope_applied jsonb CHECK (scope_applied IS NULL OR jsonb_typeof(scope_applied) = 'object'),
  freshness jsonb CHECK (freshness IS NULL OR jsonb_typeof(freshness) = 'object'),
  per_dc jsonb CHECK (per_dc IS NULL OR jsonb_typeof(per_dc) = 'object'),
  as_of timestamptz,
  row_count bigint CHECK (row_count >= 0),
  objects_checked bigint CHECK (objects_checked >= 0),
  hidden_counts jsonb CHECK (hidden_counts IS NULL OR jsonb_typeof(hidden_counts) = 'object'),
  digest bytea CHECK (digest IS NULL OR octet_length(digest) = 32),
  -- the stored column IDs in order (= export order = digest order)
  columns jsonb NOT NULL CHECK (jsonb_typeof(columns) = 'array'),
  created_at timestamptz NOT NULL DEFAULT now(),
  started_at timestamptz,
  finished_at timestamptz,
  expires_at timestamptz,
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, rerun_of) REFERENCES public.report_runs (tenant_id, id),
  CHECK (state <> 'succeeded' OR (row_count IS NOT NULL AND digest IS NOT NULL AND as_of IS NOT NULL AND expires_at IS NOT NULL)),
  CHECK ((state = 'failed') = (failure_reason IS NOT NULL))
);

-- the history list (§6.6) is a keyset on (created_at, id) among one runner's runs
CREATE INDEX report_runs_by_runner ON public.report_runs (tenant_id, runner_account, created_at DESC, id DESC);
-- the job limit and the retention sweep read by state
CREATE INDEX report_runs_open ON public.report_runs (tenant_id, state) WHERE state IN ('queued', 'running');
CREATE INDEX report_runs_expiry ON public.report_runs (tenant_id, expires_at) WHERE expires_at IS NOT NULL;
-- the reuse window looks a recent identical run up by (runner, query, scope)
CREATE INDEX report_runs_reuse ON public.report_runs (tenant_id, runner_account, query_hash, created_at DESC);

-- write-class: report_run_rows system
CREATE TABLE public.report_run_rows (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  run_id uuid NOT NULL,
  row_key text NOT NULL CHECK (octet_length(row_key) BETWEEN 1 AND 200),
  ordinal bigint NOT NULL CHECK (ordinal >= 0),
  cells jsonb NOT NULL CHECK (jsonb_typeof(cells) = 'array'),
  sort_keys jsonb NOT NULL CHECK (jsonb_typeof(sort_keys) = 'object'),
  PRIMARY KEY (tenant_id, run_id, row_key),
  -- deferrable: a per-DC run renumbers before it finishes (ADR-0010 rule 1)
  UNIQUE (tenant_id, run_id, ordinal) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (tenant_id, run_id) REFERENCES public.report_runs (tenant_id, id)
);

CREATE FUNCTION public.report_runs_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    -- the retention job deletes a record only once it holds no result (failed, cancelled, expired)
    IF OLD.state NOT IN ('failed', 'cancelled', 'expired') THEN
      RAISE EXCEPTION 'report_runs: a % run is not deleted', OLD.state USING ERRCODE = 'AD403';
    END IF;
    RETURN OLD;
  END IF;
  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.id IS DISTINCT FROM OLD.id
     OR NEW.runner_account IS DISTINCT FROM OLD.runner_account OR NEW.chain IS DISTINCT FROM OLD.chain
     OR NEW.definition_id IS DISTINCT FROM OLD.definition_id
     OR NEW.definition_version IS DISTINCT FROM OLD.definition_version
     OR NEW.definition_sha256 IS DISTINCT FROM OLD.definition_sha256
     OR NEW.preset IS DISTINCT FROM OLD.preset OR NEW.params IS DISTINCT FROM OLD.params
     OR NEW.query_hash IS DISTINCT FROM OLD.query_hash OR NEW.columns IS DISTINCT FROM OLD.columns
     OR NEW.schedule_id IS DISTINCT FROM OLD.schedule_id OR NEW.rerun_of IS DISTINCT FROM OLD.rerun_of
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'report_runs: what a run is over never changes' USING ERRCODE = 'AD403';
  END IF;
  IF OLD.state IN ('failed', 'cancelled', 'expired') THEN
    RAISE EXCEPTION 'report_runs: a % run is final', OLD.state USING ERRCODE = 'AD403';
  END IF;
  IF NEW.state IS DISTINCT FROM OLD.state THEN
    IF NOT ((OLD.state = 'queued' AND NEW.state IN ('running', 'cancelled', 'failed'))
         OR (OLD.state = 'running' AND NEW.state IN ('succeeded', 'failed', 'cancelled'))
         OR (OLD.state = 'succeeded' AND NEW.state = 'expired')) THEN
      RAISE EXCEPTION 'report_runs: % -> % is not a state edge', OLD.state, NEW.state USING ERRCODE = 'AD403';
    END IF;
  ELSIF OLD.state = 'succeeded' THEN
    RAISE EXCEPTION 'report_runs: a succeeded run does not change except to expire' USING ERRCODE = 'AD403';
  END IF;
  -- the result a reader sees is fixed once the run succeeds; only the expiry flip follows
  IF OLD.state = 'succeeded' AND (NEW.scope_fingerprint IS DISTINCT FROM OLD.scope_fingerprint
     OR NEW.row_count IS DISTINCT FROM OLD.row_count OR NEW.digest IS DISTINCT FROM OLD.digest
     OR NEW.as_of IS DISTINCT FROM OLD.as_of OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
     OR NEW.freshness IS DISTINCT FROM OLD.freshness OR NEW.scope_applied IS DISTINCT FROM OLD.scope_applied
     OR NEW.hidden_counts IS DISTINCT FROM OLD.hidden_counts OR NEW.attempt IS DISTINCT FROM OLD.attempt) THEN
    RAISE EXCEPTION 'report_runs: the result of a succeeded run never changes' USING ERRCODE = 'AD403';
  END IF;
  RETURN NEW;
END $$;
-- AFTER, for the same reason as report_run_rows_guard below: row security refuses a cross-tenant write first.
CREATE TRIGGER report_runs_guard AFTER UPDATE OR DELETE ON public.report_runs
  FOR EACH ROW EXECUTE FUNCTION public.report_runs_guard();

CREATE FUNCTION public.report_run_rows_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  st text;
BEGIN
  IF TG_OP = 'DELETE' THEN
    SELECT state INTO st FROM public.report_runs WHERE tenant_id = OLD.tenant_id AND id = OLD.run_id;
    -- a missing run record cannot happen under the foreign key; refuse rather than assume
    IF st IS NULL OR st NOT IN ('failed', 'cancelled', 'expired') THEN
      RAISE EXCEPTION 'report_run_rows: rows of a % run are not deleted', COALESCE(st, 'missing') USING ERRCODE = 'AD403';
    END IF;
    RETURN OLD;
  END IF;
  SELECT state INTO st FROM public.report_runs WHERE tenant_id = NEW.tenant_id AND id = NEW.run_id;
  IF st IS NULL OR st <> 'running' THEN
    RAISE EXCEPTION 'report_run_rows: rows are written only while the run is running (it is %)', COALESCE(st, 'missing') USING ERRCODE = 'AD403';
  END IF;
  IF TG_OP = 'UPDATE' AND (NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.run_id IS DISTINCT FROM OLD.run_id
     OR NEW.row_key IS DISTINCT FROM OLD.row_key) THEN
    RAISE EXCEPTION 'report_run_rows: the identity of a row never changes' USING ERRCODE = 'AD403';
  END IF;
  RETURN NEW;
END $$;
-- AFTER, not BEFORE: row security rejects a write into another tenant before the guard looks at the run,
-- so the guard never has to read a run record it cannot see (and the isolation probes see RLS's refusal).
CREATE TRIGGER report_run_rows_guard AFTER INSERT OR UPDATE OR DELETE ON public.report_run_rows
  FOR EACH ROW EXECUTE FUNCTION public.report_run_rows_guard();

ALTER TABLE public.report_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.report_runs FORCE ROW LEVEL SECURITY;
CREATE POLICY report_runs_tenant ON public.report_runs
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

ALTER TABLE public.report_run_rows ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.report_run_rows FORCE ROW LEVEL SECURITY;
CREATE POLICY report_run_rows_tenant ON public.report_run_rows
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

COMMENT ON TABLE public.report_runs IS 'DM-72 report run record (tenant table, RLS). Readable only by its runner under the read-scope fingerprint it was trimmed with.';
COMMENT ON TABLE public.report_run_rows IS 'ADR-0010 stored result of a report run (tenant table, RLS). Written only while the run is running, read only once it has succeeded.';

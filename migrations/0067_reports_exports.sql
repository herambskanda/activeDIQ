-- 0067_reports_exports: the export of a stored report run (T-0963; reports.md §7, row B9; FR-16 to FR-22,
-- DM-72.I3). Owner: internal/modules/reports (export subpackage). A tenant table: RLS with FORCE and a
-- tenant-led key.
--
--   report_exports   one asynchronous export job and its stored file. The file is a tenant-prefixed blob
--                    that expires with the run it serialises; blob_key never leaves the server (every
--                    download resolves the export ID to this row first, and only the row names the blob).
--
-- report_exports_guard carries the invariants the application also checks, so a bug in a caller cannot
-- break them: the state edges, an identity that never changes, and a file that is described once.

-- write-class: report_exports system
CREATE TABLE public.report_exports (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  id uuid NOT NULL,
  -- the run this export serialises (the new run when the source had expired: rerun)
  run_id uuid NOT NULL,
  rerun boolean NOT NULL DEFAULT false,
  rerun_of_run_id uuid,
  format text NOT NULL CHECK (format IN ('csv', 'xlsx', 'pdf', 'html')),
  state text NOT NULL CHECK (state IN ('queued', 'running', 'succeeded', 'failed', 'expired', 'deleted')),
  failure_reason text CHECK (failure_reason IN ('row_cap_exceeded', 'definition_retired', 'interrupted', 'internal',
    'runner_inactive', 'token_refused', 'scope_too_large', 'query_timeout', 'per_dc_read_cap_exceeded', 'connection_unavailable')),
  -- the numbers a failure names (row_cap_exceeded: rows, cap); never a value
  failure_detail jsonb CHECK (failure_detail IS NULL OR jsonb_typeof(failure_detail) = 'object'),
  attempt integer NOT NULL DEFAULT 0 CHECK (attempt >= 0),
  created_by uuid NOT NULL,
  -- the full authority.Chain of the request (typed refs), recorded on every audit event of the export
  chain jsonb NOT NULL CHECK (jsonb_typeof(chain) = 'object'),
  row_count bigint CHECK (row_count >= 0),
  -- the run's stored digest, printed in the About block and recomputable from the run's rows
  digest bytea CHECK (digest IS NULL OR octet_length(digest) = 32),
  byte_size bigint CHECK (byte_size >= 0),
  -- the SHA-256 of the file's bytes (not the digest of the result)
  file_sha256 bytea CHECK (file_sha256 IS NULL OR octet_length(file_sha256) = 32),
  blob_key text NOT NULL CHECK (octet_length(blob_key) BETWEEN 1 AND 512),
  file_name text CHECK (file_name IS NULL OR octet_length(file_name) <= 256),
  created_at timestamptz NOT NULL DEFAULT now(),
  finished_at timestamptz,
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, run_id) REFERENCES public.report_runs (tenant_id, id),
  FOREIGN KEY (tenant_id, rerun_of_run_id) REFERENCES public.report_runs (tenant_id, id),
  CHECK (state <> 'succeeded' OR (row_count IS NOT NULL AND digest IS NOT NULL AND byte_size IS NOT NULL
    AND file_sha256 IS NOT NULL AND file_name IS NOT NULL AND finished_at IS NOT NULL)),
  CHECK ((state = 'failed') = (failure_reason IS NOT NULL))
);

-- the creator's own exports (get, delete, download resolve by id; this serves the open-job count and sweeps)
CREATE INDEX report_exports_open ON public.report_exports (tenant_id, state) WHERE state IN ('queued', 'running');
CREATE INDEX report_exports_expiry ON public.report_exports (tenant_id, expires_at);
CREATE INDEX report_exports_by_run ON public.report_exports (tenant_id, run_id);

CREATE FUNCTION public.report_exports_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    -- the retention job deletes a record only once it holds no file
    IF OLD.state NOT IN ('failed', 'expired', 'deleted') THEN
      RAISE EXCEPTION 'report_exports: a % export is not deleted', OLD.state USING ERRCODE = 'AD403';
    END IF;
    RETURN OLD;
  END IF;
  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.id IS DISTINCT FROM OLD.id
     OR NEW.run_id IS DISTINCT FROM OLD.run_id OR NEW.rerun IS DISTINCT FROM OLD.rerun
     OR NEW.rerun_of_run_id IS DISTINCT FROM OLD.rerun_of_run_id OR NEW.format IS DISTINCT FROM OLD.format
     OR NEW.created_by IS DISTINCT FROM OLD.created_by OR NEW.chain IS DISTINCT FROM OLD.chain
     OR NEW.blob_key IS DISTINCT FROM OLD.blob_key OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'report_exports: what an export is of never changes' USING ERRCODE = 'AD403';
  END IF;
  IF OLD.state IN ('failed', 'expired', 'deleted') THEN
    RAISE EXCEPTION 'report_exports: a % export is final', OLD.state USING ERRCODE = 'AD403';
  END IF;
  IF NEW.state IS DISTINCT FROM OLD.state THEN
    IF NOT ((OLD.state = 'queued' AND NEW.state IN ('running', 'failed'))
         OR (OLD.state = 'running' AND NEW.state IN ('succeeded', 'failed'))
         OR (OLD.state = 'succeeded' AND NEW.state IN ('expired', 'deleted'))) THEN
      RAISE EXCEPTION 'report_exports: % -> % is not a state edge', OLD.state, NEW.state USING ERRCODE = 'AD403';
    END IF;
  ELSIF OLD.state = 'succeeded' THEN
    RAISE EXCEPTION 'report_exports: a succeeded export does not change except to expire or be deleted' USING ERRCODE = 'AD403';
  END IF;
  -- the file a reader is given is fixed once the export succeeds
  IF OLD.state = 'succeeded' AND (NEW.row_count IS DISTINCT FROM OLD.row_count OR NEW.digest IS DISTINCT FROM OLD.digest
     OR NEW.byte_size IS DISTINCT FROM OLD.byte_size OR NEW.file_sha256 IS DISTINCT FROM OLD.file_sha256
     OR NEW.file_name IS DISTINCT FROM OLD.file_name OR NEW.expires_at IS DISTINCT FROM OLD.expires_at) THEN
    RAISE EXCEPTION 'report_exports: the file of a succeeded export never changes' USING ERRCODE = 'AD403';
  END IF;
  RETURN NEW;
END $$;
-- AFTER, for the same reason as report_runs_guard: row security refuses a cross-tenant write first.
CREATE TRIGGER report_exports_guard AFTER UPDATE OR DELETE ON public.report_exports
  FOR EACH ROW EXECUTE FUNCTION public.report_exports_guard();

ALTER TABLE public.report_exports ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.report_exports FORCE ROW LEVEL SECURITY;
CREATE POLICY report_exports_tenant ON public.report_exports
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

COMMENT ON TABLE public.report_exports IS 'DM-72.I3 export of a stored report run (tenant table, RLS). The file is a tenant-prefixed blob that expires with the run; blob_key never leaves the server.';

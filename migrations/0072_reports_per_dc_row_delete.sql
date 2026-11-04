-- 0072_reports_per_dc_row_delete: a per-DC run may delete candidate rows while it is running (T-0971; reports.md
-- §6.5 stage 3). Owner: internal/modules/reports (run subpackage).
--
-- A per-DC report (USR-04, PWD-03) stores its candidates first and reads the DCs afterwards. The part of its filter
-- that only the DC reads can answer (PerDCWhere) removes a candidate once its values are in, in the same short
-- transaction. Rows of a running run are never readable (pages need `succeeded`), so letting the run drop its own
-- candidates exposes nothing. Everything else is unchanged: a succeeded run's rows are still never deleted, only
-- the expiry sweep removes them, and a write still needs a running run.

CREATE OR REPLACE FUNCTION public.report_run_rows_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  st text;
BEGIN
  IF TG_OP = 'DELETE' THEN
    SELECT state INTO st FROM public.report_runs WHERE tenant_id = OLD.tenant_id AND id = OLD.run_id;
    -- a missing run record cannot happen under the foreign key; refuse rather than assume
    IF st IS NULL OR st NOT IN ('running', 'failed', 'cancelled', 'expired') THEN
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

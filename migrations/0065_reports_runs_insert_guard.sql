-- 0065_reports_runs_insert_guard: a report run is born queued (T-1061; reports.md §6.2, row B4; defence in depth
-- for 0064). report_runs_guard fires on UPDATE and DELETE only, so an INSERT could create a run that is already
-- 'succeeded', or one with a result, an attempt or an expiry it never earned. Only the run service inserts, and
-- it inserts 'queued'; this trigger makes a caller's bug unable to do otherwise. Owner: internal/modules/reports.
--
-- AFTER, like the other guards of the table: row security refuses a write into another tenant before this
-- trigger looks at the row. AD403 matches the other guards, so one probe tells a refusal from an outage.

CREATE FUNCTION public.report_runs_insert_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.state <> 'queued' OR NEW.attempt <> 0 THEN
    RAISE EXCEPTION 'report_runs: a run is created queued with attempt 0' USING ERRCODE = 'AD403';
  END IF;
  IF NEW.scope_applied IS NOT NULL OR NEW.freshness IS NOT NULL OR NEW.per_dc IS NOT NULL
     OR NEW.as_of IS NOT NULL OR NEW.row_count IS NOT NULL OR NEW.objects_checked IS NOT NULL
     OR NEW.hidden_counts IS NOT NULL OR NEW.digest IS NOT NULL OR NEW.failure_reason IS NOT NULL
     OR NEW.started_at IS NOT NULL OR NEW.finished_at IS NOT NULL OR NEW.expires_at IS NOT NULL THEN
    RAISE EXCEPTION 'report_runs: a new run holds no result' USING ERRCODE = 'AD403';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER report_runs_insert_guard AFTER INSERT ON public.report_runs
  FOR EACH ROW EXECUTE FUNCTION public.report_runs_insert_guard();

-- 0077_report_runs_runner_zone (T-1153; reports-2a §8.3): the IANA time zone the runner asked for, so PDF and
-- HTML exports show Time cells in it with the zone label. NULL means UTC. It is a display input only: it is not
-- part of the query hash, the rows or the digest.
ALTER TABLE public.report_runs
  ADD COLUMN runner_zone text CHECK (runner_zone IS NULL OR runner_zone ~ '^[A-Za-z][A-Za-z0-9_+-]*(/[A-Za-z0-9_+-]+){0,2}$');

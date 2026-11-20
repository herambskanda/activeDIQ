-- 0092_report_schedules: DM-73 ReportSchedule and its versions, recipients and fires (T-0965; reports.md §8,
-- row B11; reports-2a §8.4). Owner: internal/modules/reports (schedule subpackage). All four are tenant
-- tables: RLS with FORCE and a tenant-led key.
--
--   report_schedules            one recurring run plus delivery. owner_account is the authority every fire runs
--                               under (DM-73.I1); recurrence is the API-shape recurrence
--                               (converted to the DM-44 jobs.Schedule by Recurrence.Jobs).
--   report_schedule_versions    the AFTER-image of each version (header and recipients: what that version wrote), for undo
--                               (reports.schedule.restore). Immutable: a version is never edited or deleted.
--   report_schedule_recipients  the recipients of the CURRENT version: an account or an address, formats,
--                               attachment or link.
--   report_schedule_fires       one row per occurrence the tick enqueued: the idempotency key of a fire
--                               (schedule, occurrence), the run it made and what it did.

-- write-class: report_schedules config
CREATE TABLE public.report_schedules (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  id uuid NOT NULL,
  name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
  definition_id text NOT NULL CHECK (definition_id ~ '^[a-z][a-z0-9-]{1,63}$'),
  definition_version integer NOT NULL CHECK (definition_version >= 1),
  preset text CHECK (preset IS NULL OR preset ~ '^[a-z][a-z0-9_]{0,63}$'),
  -- the validated run parameters in the API shape, as saved (§8.4 "exactly as on screen when saved")
  params jsonb NOT NULL CHECK (jsonb_typeof(params) = 'object' AND octet_length(params::text) <= 65536),
  recurrence jsonb NOT NULL CHECK (jsonb_typeof(recurrence) = 'object'),
  time_zone text NOT NULL CHECK (time_zone ~ '^[A-Za-z][A-Za-z0-9_+-]*(/[A-Za-z0-9_+-]+){0,2}$'),
  owner_account uuid NOT NULL,
  notify_only_if_data boolean NOT NULL DEFAULT false,
  -- the external addresses the owner confirmed at the last write (SX-6): an address external now and not
  -- listed here fails alone at fire time, whatever the owner holds
  confirmed_external text[] NOT NULL DEFAULT '{}' CHECK (cardinality(confirmed_external) <= 200),
  state text NOT NULL CHECK (state IN ('active', 'paused', 'archived')),
  -- why a paused schedule is paused: a stable code (owner_disabled, owner_lost_permission, reassigned,
  -- paused_by_owner, paused_by_manager, per_dc_floor), never free text
  pause_reason text CHECK (pause_reason IS NULL OR pause_reason ~ '^[a-z][a-z0-9_]{0,63}$'),
  -- the version this row holds; bumped by every write, which also appends its before-image
  version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
  next_run_at timestamptz,
  last_fire_at timestamptz,
  created_by uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CHECK ((state = 'paused') = (pause_reason IS NOT NULL)),
  -- only an active schedule is due
  CHECK (state = 'active' OR next_run_at IS NULL)
);

-- the tick's scan for due schedules
CREATE INDEX report_schedules_due ON public.report_schedules (tenant_id, next_run_at) WHERE state = 'active';
-- the list: the owner's schedules, and the manage_all view
CREATE INDEX report_schedules_by_owner ON public.report_schedules (tenant_id, owner_account, created_at DESC, id DESC);

-- write-class: report_schedule_versions config
CREATE TABLE public.report_schedule_versions (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  schedule_id uuid NOT NULL,
  version integer NOT NULL CHECK (version >= 1),
  -- the whole schedule as this version wrote it: header, recipients and confirmed-external set
  content jsonb NOT NULL CHECK (jsonb_typeof(content) = 'object' AND octet_length(content::text) <= 262144),
  written_by uuid NOT NULL,
  written_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, schedule_id, version),
  FOREIGN KEY (tenant_id, schedule_id) REFERENCES public.report_schedules (tenant_id, id)
);

-- write-class: report_schedule_recipients config
CREATE TABLE public.report_schedule_recipients (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  schedule_id uuid NOT NULL,
  ordinal integer NOT NULL CHECK (ordinal >= 0),
  kind text NOT NULL CHECK (kind IN ('account', 'address')),
  account uuid,
  address text CHECK (address IS NULL OR char_length(address) BETWEEN 3 AND 254),
  formats text[] NOT NULL CHECK (cardinality(formats) BETWEEN 1 AND 4 AND formats <@ ARRAY['csv', 'xlsx', 'pdf', 'html']),
  delivery text NOT NULL CHECK (delivery IN ('attachment', 'link')),
  PRIMARY KEY (tenant_id, schedule_id, ordinal),
  FOREIGN KEY (tenant_id, schedule_id) REFERENCES public.report_schedules (tenant_id, id),
  CHECK ((kind = 'account' AND account IS NOT NULL AND address IS NULL) OR (kind = 'address' AND address IS NOT NULL AND account IS NULL)),
  -- a link is for an account only (§8.4: not offered for an external address, which has no sign-in)
  CHECK (kind = 'account' OR delivery = 'attachment')
);

-- write-class: report_schedule_fires system
CREATE TABLE public.report_schedule_fires (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  schedule_id uuid NOT NULL,
  -- the occurrence this fire is for (UTC); (schedule, due_at) is unique, so a tick that repeats enqueues once
  due_at timestamptz NOT NULL,
  id uuid NOT NULL,
  state text NOT NULL CHECK (state IN ('queued', 'running', 'sent', 'nothing_to_send', 'paused', 'failed')),
  -- why it did not send, a stable code
  reason text CHECK (reason IS NULL OR reason ~ '^[a-z][a-z0-9_]{0,63}$'),
  run_id uuid,
  -- the scope applied, copied from the run so the fire list needs no run read
  scope_applied jsonb CHECK (scope_applied IS NULL OR jsonb_typeof(scope_applied) = 'object'),
  row_count bigint CHECK (row_count >= 0),
  -- per recipient: {ordinal, outcome: queued|failed, reason} (the Delivery rows carry the later state)
  recipients jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(recipients) = 'array'),
  -- the exports made for this fire, format -> export id; the fire job stages run, exports and delivery
  exports jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(exports) = 'object'),
  created_at timestamptz NOT NULL DEFAULT now(),
  finished_at timestamptz,
  PRIMARY KEY (tenant_id, schedule_id, due_at),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, schedule_id) REFERENCES public.report_schedules (tenant_id, id)
);

CREATE INDEX report_schedule_fires_recent ON public.report_schedule_fires (tenant_id, schedule_id, due_at DESC);

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['report_schedules', 'report_schedule_versions', 'report_schedule_recipients', 'report_schedule_fires'] LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format($p$CREATE POLICY %I ON public.%I USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
      WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)$p$, t || '_tenant', t);
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON public.%I TO activediq_app', t);
  END LOOP;
END $$;

-- Schedules are archived, never deleted; a version is a record, never edited; a fire is bookkeeping that is
-- never removed by the runtime role.
REVOKE DELETE ON public.report_schedules FROM activediq_app;
REVOKE DELETE, UPDATE ON public.report_schedule_versions FROM activediq_app;
REVOKE DELETE ON public.report_schedule_fires FROM activediq_app;

-- tenant_id is deliberately not checked here: moving a row to another tenant is refused by the policy's WITH CHECK
-- (SQLSTATE 42501), which is the tenancy fitness probe's T4 contract; a trigger error would pre-empt it.
-- The guard keeps what the application also checks: an archived schedule is final, and the identity columns
-- never change, so a bug in a caller cannot reopen a deleted schedule or move one across tenants or owners'
-- history.
CREATE FUNCTION public.report_schedules_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $fn$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.created_at IS DISTINCT FROM OLD.created_at OR NEW.created_by IS DISTINCT FROM OLD.created_by THEN
    RAISE EXCEPTION 'report_schedules: identity columns are immutable' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF OLD.state = 'archived' AND NEW.state <> 'archived' THEN
    -- the one way back is undo of a delete, which restores a version through the restore Action
    IF NEW.version <= OLD.version THEN
      RAISE EXCEPTION 'report_schedules: an archived schedule changes only by a new version' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
  END IF;
  IF NEW.version < OLD.version THEN
    RAISE EXCEPTION 'report_schedules: the version never goes back' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END
$fn$;
CREATE TRIGGER report_schedules_guard BEFORE UPDATE ON public.report_schedules FOR EACH ROW EXECUTE FUNCTION public.report_schedules_guard();

COMMENT ON TABLE public.report_schedules IS 'DM-73 ReportSchedule (tenant table, RLS). Written only by the reports.schedule.* Actions and the fire job.';

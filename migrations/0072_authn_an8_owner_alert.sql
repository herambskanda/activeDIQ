-- 0072_authn_an8_owner_alert: the AN-8 owner alert outbox (T-1544; RULING AN8-A1, threat model §7.6 rules 3-4).
-- Owner: internal/platform/authn.
--
-- authn_authority_notices gains two events written by the break-glass password step in the transaction that
-- decides its outcome: break_glass_used (a successful AN-8) and break_glass_failures (the 10th failure of a
-- tenant inside one hour, once per window). Unlike the TM-D19 notices they have no recipient yet: the drain job
-- resolves the tenant-owners when it runs, so the sign-in path never fails on an owner lookup. The body of the
-- eventual message is made from the account (id), the time and the source address only.
--
--   source_ip, failure_count   what the message says; immutable
--   pending_audited_at         an8_alert_pending_over_threshold was audited for this row (once)
--   settled_at                 no Delivery of the row is queued or failed any more (sent or given up)
--   given_up_at                every Delivery of the row was given up, or no recipient resolved; shown as a
--                              banner to tenant-owners until acknowledged_at is set
--   authn_an8_failure_window   the per-tenant count of failures in the current hour (alerted: the 10th has
--                              raised its alert)

ALTER TABLE public.authn_authority_notices DROP CONSTRAINT authn_authority_notices_event_check;
ALTER TABLE public.authn_authority_notices
  ALTER COLUMN recipient_id DROP NOT NULL,
  ALTER COLUMN subject_id DROP NOT NULL,
  ALTER COLUMN actor_id DROP NOT NULL,
  ADD COLUMN source_ip text CHECK (source_ip IS NULL OR char_length(source_ip) BETWEEN 2 AND 45),
  ADD COLUMN failure_count integer CHECK (failure_count IS NULL OR failure_count > 0),
  ADD COLUMN pending_audited_at timestamptz,
  ADD COLUMN given_up_at timestamptz,
  ADD COLUMN settled_at timestamptz,
  ADD COLUMN acknowledged_at timestamptz,
  ADD CONSTRAINT authn_authority_notices_event_check CHECK (event IN ('enrolled', 'reset', 'removed', 'break_glass_used', 'break_glass_failures')),
  ADD CONSTRAINT authn_authority_notices_shape CHECK (
    (event IN ('enrolled', 'reset', 'removed') AND recipient_id IS NOT NULL AND subject_id IS NOT NULL AND actor_id IS NOT NULL
       AND source_ip IS NULL AND failure_count IS NULL)
    OR (event = 'break_glass_used' AND recipient_id IS NULL AND subject_id IS NOT NULL AND actor_id IS NULL AND failure_count IS NULL)
    OR (event = 'break_glass_failures' AND recipient_id IS NULL AND subject_id IS NULL AND actor_id IS NULL AND failure_count IS NOT NULL));

DROP INDEX public.authn_authority_notices_pending;
CREATE INDEX authn_authority_notices_pending ON public.authn_authority_notices (tenant_id, created_at)
  WHERE delivered_at IS NULL AND given_up_at IS NULL;
-- Rows handed to notify and not yet known to be given up (the drain checks their Deliveries).
-- settled_at leaves this set when no Delivery is queued or failed, so sent history never crowds out a newer row.
CREATE INDEX authn_authority_notices_enqueued ON public.authn_authority_notices (tenant_id, created_at)
  WHERE delivered_at IS NOT NULL AND settled_at IS NULL AND given_up_at IS NULL AND event IN ('break_glass_used', 'break_glass_failures');
-- Banner: given up and not acknowledged.
CREATE INDEX authn_authority_notices_banner ON public.authn_authority_notices (tenant_id, given_up_at)
  WHERE given_up_at IS NOT NULL AND acknowledged_at IS NULL;

-- write-class: authn_an8_failure_window system
CREATE TABLE public.authn_an8_failure_window (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  window_start timestamptz NOT NULL,
  failures integer NOT NULL CHECK (failures >= 0),
  alerted boolean NOT NULL DEFAULT false,
  PRIMARY KEY (tenant_id)
);
ALTER TABLE public.authn_an8_failure_window ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.authn_an8_failure_window FORCE ROW LEVEL SECURITY;
CREATE POLICY authn_an8_failure_window_tenant ON public.authn_an8_failure_window
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
REVOKE DELETE, TRUNCATE ON public.authn_an8_failure_window FROM activediq_app;
COMMENT ON TABLE public.authn_an8_failure_window IS 'AN-8 failures of a tenant in the current hour, to raise break_glass_failures once per window (tenant table, RLS). Only internal/platform/authn references it in SQL.';

-- Only the markers move, each once, from NULL; the rest of an AN-8 row is as written.
CREATE OR REPLACE FUNCTION public.authn_authority_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $fn$
BEGIN
  IF TG_TABLE_NAME = 'authn_authority_approvals' THEN
    IF NEW.id IS DISTINCT FROM OLD.id OR NEW.account_id IS DISTINCT FROM OLD.account_id OR NEW.approver_id IS DISTINCT FROM OLD.approver_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at OR NEW.expires_at IS DISTINCT FROM OLD.expires_at OR OLD.consumed_at IS NOT NULL THEN
      RAISE EXCEPTION 'authn_authority_approvals: an approval is consumed once and never changes' USING ERRCODE = 'AD403';
    END IF;
  ELSIF TG_TABLE_NAME = 'authn_authority_notices' THEN
    IF NEW.id IS DISTINCT FROM OLD.id OR NEW.recipient_id IS DISTINCT FROM OLD.recipient_id OR NEW.subject_id IS DISTINCT FROM OLD.subject_id
       OR NEW.event IS DISTINCT FROM OLD.event OR NEW.actor_id IS DISTINCT FROM OLD.actor_id OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.source_ip IS DISTINCT FROM OLD.source_ip OR NEW.failure_count IS DISTINCT FROM OLD.failure_count
       OR (OLD.delivered_at IS NOT NULL AND NEW.delivered_at IS DISTINCT FROM OLD.delivered_at)
       OR (OLD.pending_audited_at IS NOT NULL AND NEW.pending_audited_at IS DISTINCT FROM OLD.pending_audited_at)
       OR (OLD.settled_at IS NOT NULL AND NEW.settled_at IS DISTINCT FROM OLD.settled_at)
       OR (OLD.given_up_at IS NOT NULL AND NEW.given_up_at IS DISTINCT FROM OLD.given_up_at)
       OR (OLD.acknowledged_at IS NOT NULL AND NEW.acknowledged_at IS DISTINCT FROM OLD.acknowledged_at) THEN
      RAISE EXCEPTION 'authn_authority_notices: only the delivery markers move, once' USING ERRCODE = 'AD403';
    END IF;
  ELSE
    IF NEW.kind IS DISTINCT FROM OLD.kind OR NEW.subject_id IS DISTINCT FROM OLD.subject_id THEN
      RAISE EXCEPTION 'authn_authority_challenges: identity is immutable' USING ERRCODE = 'AD403';
    END IF;
    IF OLD.consumed_at IS NOT NULL AND NEW.challenge IS NOT DISTINCT FROM OLD.challenge AND NEW.consumed_at IS NULL THEN
      RAISE EXCEPTION 'authn_authority_challenges: a consumed challenge cannot be revived' USING ERRCODE = 'AD403';
    END IF;
  END IF;
  RETURN NEW;
END
$fn$;

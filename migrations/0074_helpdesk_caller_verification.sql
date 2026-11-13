-- 0074_helpdesk_caller_verification: the help-desk caller-verification challenge (T-1602; ENH-09 spec T-0192
-- §4 and §4a, DM-38). Owner: internal/modules/helpdesk.
--
-- One row per challenge a technician issues to prove a caller is the target user before a reset or unlock.
--   code_mac        keyed MAC of the six-digit code under a tenant-derived key (DM-38.I2). The code is never
--                   stored, logged or audited.
--   attempts        wrong-or-right entries charged BEFORE the code is compared, under the row lock, so parallel
--                   guesses cannot exceed 3 (rule 4.3, 4.9; DM-38.I6).
--   counted         whether the issue counts toward the hourly quotas (4.6, 4.7). Only a transport failure
--                   (4.17) turns it off; closing the sheet never does (C5).
--   authorised_until verified_at + 5 minutes (4.16); a verified challenge is consumed once, for the target it
--                   was issued for (DM-38.I3), by the operation named in consumed_operation.
-- One open ('issued') challenge per target (DM-38.I5): a partial unique index; the service cancels the older one
-- in the same transaction before it inserts.

-- write-class: helpdesk_caller_verifications system
CREATE TABLE public.helpdesk_caller_verifications (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  technician_id text NOT NULL CHECK (technician_id <> ''),
  connection_id uuid NOT NULL,
  object_guid uuid NOT NULL,
  factor text NOT NULL CHECK (factor IN ('email_otp', 'sms_otp', 'totp')),
  destination_masked text NOT NULL CHECK (destination_masked <> ''),
  code_mac bytea CHECK (code_mac IS NULL OR octet_length(code_mac) = 32),
  trigger text NOT NULL CHECK (trigger IN ('sheet_open', 'resend')),
  state text NOT NULL DEFAULT 'issued' CHECK (state IN ('issued', 'verified', 'failed', 'expired', 'cancelled', 'consumed')),
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 3),
  counted boolean NOT NULL DEFAULT true,
  cancel_reason text,
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  delivered_at timestamptz,
  failed_at timestamptz,
  verified_at timestamptz,
  authorised_until timestamptz,
  consumed_at timestamptz,
  consumed_operation text,
  factor_enrolled_at timestamptz,
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT helpdesk_cv_life CHECK (expires_at > created_at AND expires_at <= created_at + interval '5 minutes'),
  CONSTRAINT helpdesk_cv_code CHECK ((factor = 'totp') = (code_mac IS NULL)),
  CONSTRAINT helpdesk_cv_verified CHECK ((verified_at IS NULL) = (authorised_until IS NULL)
    AND (state NOT IN ('verified', 'consumed') OR verified_at IS NOT NULL)),
  CONSTRAINT helpdesk_cv_failed CHECK ((state = 'failed') = (failed_at IS NOT NULL)),
  CONSTRAINT helpdesk_cv_consumed CHECK ((state = 'consumed') = (consumed_at IS NOT NULL AND consumed_operation IS NOT NULL))
);

CREATE UNIQUE INDEX helpdesk_cv_one_open ON public.helpdesk_caller_verifications (tenant_id, connection_id, object_guid)
  WHERE state = 'issued';
CREATE INDEX helpdesk_cv_target_hour ON public.helpdesk_caller_verifications (tenant_id, connection_id, object_guid, created_at);
CREATE INDEX helpdesk_cv_technician_hour ON public.helpdesk_caller_verifications (tenant_id, technician_id, created_at);

ALTER TABLE public.helpdesk_caller_verifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.helpdesk_caller_verifications FORCE ROW LEVEL SECURITY;
CREATE POLICY helpdesk_caller_verifications_tenant ON public.helpdesk_caller_verifications
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

REVOKE DELETE ON public.helpdesk_caller_verifications FROM activediq_app;

COMMENT ON TABLE public.helpdesk_caller_verifications IS 'Help-desk caller-verification challenges (tenant table, RLS): a keyed MAC of a short-lived code, never the code. Only internal/modules/helpdesk references it in SQL.';

CREATE FUNCTION public.helpdesk_cv_insert_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $fn$
DECLARE
  now_ts timestamptz := pg_catalog.clock_timestamp();
BEGIN
  IF NEW.state <> 'issued' OR NEW.attempts <> 0 OR NEW.counted IS NOT TRUE OR NEW.verified_at IS NOT NULL
     OR NEW.consumed_at IS NOT NULL OR NEW.failed_at IS NOT NULL OR NEW.delivered_at IS NOT NULL OR NEW.cancel_reason IS NOT NULL THEN
    RAISE EXCEPTION 'helpdesk_caller_verifications: a challenge starts issued, counted, with no attempts' USING ERRCODE = 'AD403';
  END IF;
  IF NEW.created_at < now_ts - interval '5 minutes' OR NEW.created_at > now_ts + interval '5 minutes'
     OR NEW.expires_at <= now_ts THEN
    RAISE EXCEPTION 'helpdesk_caller_verifications: created_at must be current and the row not already expired' USING ERRCODE = 'AD403';
  END IF;
  RETURN NEW;
END
$fn$;
CREATE TRIGGER helpdesk_cv_insert_guard BEFORE INSERT ON public.helpdesk_caller_verifications
  FOR EACH ROW EXECUTE FUNCTION public.helpdesk_cv_insert_guard();
ALTER TABLE public.helpdesk_caller_verifications ENABLE ALWAYS TRIGGER helpdesk_cv_insert_guard;

CREATE FUNCTION public.helpdesk_cv_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $fn$
BEGIN
  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.id IS DISTINCT FROM OLD.id
     OR NEW.technician_id IS DISTINCT FROM OLD.technician_id OR NEW.connection_id IS DISTINCT FROM OLD.connection_id
     OR NEW.object_guid IS DISTINCT FROM OLD.object_guid OR NEW.factor IS DISTINCT FROM OLD.factor
     OR NEW.destination_masked IS DISTINCT FROM OLD.destination_masked OR NEW.code_mac IS DISTINCT FROM OLD.code_mac
     OR NEW.trigger IS DISTINCT FROM OLD.trigger OR NEW.created_at IS DISTINCT FROM OLD.created_at
     OR NEW.expires_at IS DISTINCT FROM OLD.expires_at OR NEW.factor_enrolled_at IS DISTINCT FROM OLD.factor_enrolled_at THEN
    RAISE EXCEPTION 'helpdesk_caller_verifications: identity, binding, code and expiry are never rewritten' USING ERRCODE = 'AD403';
  END IF;
  IF NEW.state IS DISTINCT FROM OLD.state AND NOT (
       (OLD.state = 'issued' AND NEW.state IN ('verified', 'failed', 'expired', 'cancelled'))
    OR (OLD.state = 'verified' AND NEW.state IN ('consumed', 'expired'))) THEN
    RAISE EXCEPTION 'helpdesk_caller_verifications: % -> % is not allowed', OLD.state, NEW.state USING ERRCODE = 'AD403';
  END IF;
  IF NEW.attempts < OLD.attempts OR NEW.attempts > OLD.attempts + 1 OR (NEW.attempts <> OLD.attempts AND OLD.state <> 'issued') THEN
    RAISE EXCEPTION 'helpdesk_caller_verifications: attempts only rise, by one, while issued' USING ERRCODE = 'AD403';
  END IF;
  IF NEW.counted IS DISTINCT FROM OLD.counted AND NOT (OLD.counted AND NOT NEW.counted AND NEW.cancel_reason = 'delivery_failed') THEN
    RAISE EXCEPTION 'helpdesk_caller_verifications: only a delivery failure releases the quota' USING ERRCODE = 'AD403';
  END IF;
  IF OLD.verified_at IS NOT NULL AND (NEW.verified_at IS DISTINCT FROM OLD.verified_at OR NEW.authorised_until IS DISTINCT FROM OLD.authorised_until) THEN
    RAISE EXCEPTION 'helpdesk_caller_verifications: the verified window is never rewritten' USING ERRCODE = 'AD403';
  END IF;
  RETURN NEW;
END
$fn$;
CREATE TRIGGER helpdesk_cv_guard BEFORE UPDATE ON public.helpdesk_caller_verifications
  FOR EACH ROW EXECUTE FUNCTION public.helpdesk_cv_guard();
ALTER TABLE public.helpdesk_caller_verifications ENABLE ALWAYS TRIGGER helpdesk_cv_guard;

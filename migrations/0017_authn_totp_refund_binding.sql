-- 0017_authn_totp_refund_binding: bind the TOTP attempt refund to a real step spend (T-0389; fixes the
-- xmin check of 0015's authn_totp_failures_update_guard). Owner: internal/platform/authn.
--
-- 0015 let a failure row flip to succeeded in any transaction that had written the enrolment row, so
-- 'UPDATE enrollments SET label = label' followed by 'UPDATE authn_totp_failures SET succeeded = true'
-- reset the budget. Now the spend UPDATE records the refunded attempt in refund_attempt; the enrolment
-- guard lets that column change only when last_used_step strictly increases; the failures guard requires
-- refund_attempt = the row being refunded. One refund per strictly increasing step: steps run ahead of
-- real time, so the app role cannot mint refunds in bulk.

ALTER TABLE public.authn_authenticator_enrollments ADD COLUMN refund_attempt uuid;

CREATE OR REPLACE FUNCTION public.authn_enrollments_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $fn$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.account_id IS DISTINCT FROM OLD.account_id OR NEW.connection_id IS DISTINCT FROM OLD.connection_id
     OR NEW.object_guid IS DISTINCT FROM OLD.object_guid OR NEW.method IS DISTINCT FROM OLD.method
     OR NEW.sealed_secret IS DISTINCT FROM OLD.sealed_secret OR NEW.key_version IS DISTINCT FROM OLD.key_version
     OR NEW.created_at IS DISTINCT FROM OLD.created_at OR NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
    RAISE EXCEPTION 'authn_authenticator_enrollments: identity, subject, seed and expiry are immutable' USING ERRCODE = 'AD403';
  END IF;
  IF NEW.state IS DISTINCT FROM OLD.state
     AND NOT ((OLD.state = 'pending' AND NEW.state IN ('active', 'revoked', 'expired')) OR (OLD.state = 'active' AND NEW.state = 'revoked')) THEN
    RAISE EXCEPTION 'authn_authenticator_enrollments: % -> % is not allowed', OLD.state, NEW.state USING ERRCODE = 'AD403';
  END IF;
  IF OLD.last_used_step IS NOT NULL AND (NEW.last_used_step IS NULL OR NEW.last_used_step < OLD.last_used_step) THEN
    RAISE EXCEPTION 'authn_authenticator_enrollments: last_used_step never decreases' USING ERRCODE = 'AD403';
  END IF;
  IF NEW.confirm_attempts < OLD.confirm_attempts THEN
    RAISE EXCEPTION 'authn_authenticator_enrollments: confirm_attempts never decreases' USING ERRCODE = 'AD403';
  END IF;
  -- A pause is cleared only by time passing: it can be set or extended, never cleared or shortened.
  IF OLD.paused_until IS NOT NULL AND (NEW.paused_until IS NULL OR NEW.paused_until < OLD.paused_until) THEN
    RAISE EXCEPTION 'authn_authenticator_enrollments: paused_until never decreases or clears' USING ERRCODE = 'AD403';
  END IF;
  -- The refunded attempt is named only by a statement that spends a step (strictly increases it).
  IF NEW.refund_attempt IS DISTINCT FROM OLD.refund_attempt
     AND NOT (NEW.last_used_step IS NOT NULL AND (OLD.last_used_step IS NULL OR NEW.last_used_step > OLD.last_used_step)) THEN
    RAISE EXCEPTION 'authn_authenticator_enrollments: refund_attempt changes only when a step is spent' USING ERRCODE = 'AD403';
  END IF;
  RETURN NEW;
END
$fn$;

-- A new enrolment names no refund.
CREATE OR REPLACE FUNCTION public.authn_enrollments_insert_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $fn$
BEGIN
  IF NEW.state <> 'pending' OR NEW.last_used_step IS NOT NULL OR NEW.last_used IS NOT NULL
     OR NEW.confirm_attempts <> 0 OR NEW.paused_until IS NOT NULL OR NEW.expires_at IS NULL
     OR NEW.refund_attempt IS NOT NULL THEN
    RAISE EXCEPTION 'authn_authenticator_enrollments: an enrollment starts pending, unused and with an expiry' USING ERRCODE = 'AD403';
  END IF;
  NEW.expires_at := LEAST(NEW.expires_at, pg_catalog.now() + interval '10 minutes');
  RETURN NEW;
END
$fn$;

CREATE OR REPLACE FUNCTION public.authn_totp_failures_update_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $fn$
BEGIN
  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.id IS DISTINCT FROM OLD.id
     OR NEW.enrollment_id IS DISTINCT FROM OLD.enrollment_id OR NEW.at IS DISTINCT FROM OLD.at
     OR OLD.succeeded OR NOT NEW.succeeded THEN
    RAISE EXCEPTION 'authn_totp_failures: a row only changes from failed to succeeded' USING ERRCODE = 'AD403';
  END IF;
  -- Refunded only when the enrolment row was written by this transaction AND names this very attempt as
  -- the one refunded by the step spend (refund_attempt can change only with a strictly increasing step).
  IF NOT EXISTS (SELECT 1 FROM public.authn_authenticator_enrollments e
                 WHERE e.tenant_id = OLD.tenant_id AND e.id = OLD.enrollment_id
                   AND e.refund_attempt = OLD.id
                   AND e.xmin = pg_catalog.pg_current_xact_id()::xid) THEN
    RAISE EXCEPTION 'authn_totp_failures: success is recorded only by the transaction that spent the step' USING ERRCODE = 'AD403';
  END IF;
  RETURN NEW;
END
$fn$;

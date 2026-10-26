-- 0015_authn_totp_failure_budget: the per-enrolment failure budget and pending expiry of DM-37 (T-0361;
-- ENH-09 §5, §9). Owner: internal/platform/authn.
--
--   expires_at        a pending enrolment is good for 10 minutes; after that it is 'expired' (terminal).
--   confirm_attempts  wrong codes sent to Activate; the 5th wrong one expires the enrolment.
--   paused_until      10 wrong codes in a rolling hour pause verification for 1 hour; while it is in the
--                     future even a correct code is refused.
--   authn_totp_failures  one row per refused code, written by a separate short transaction so a caller that
--                     rolls back on refusal cannot erase it. Insert-only for the app role apart from pruning rows older than 90 minutes (trigger).
-- The INSERT trigger makes a row start 'pending' with no used step: the guard on UPDATE alone left the app
-- role able to INSERT an 'active' enrolment with a chosen last_used_step.

ALTER TABLE public.authn_authenticator_enrollments
  ADD COLUMN expires_at timestamptz,
  ADD COLUMN confirm_attempts integer NOT NULL DEFAULT 0 CHECK (confirm_attempts BETWEEN 0 AND 5),
  ADD COLUMN paused_until timestamptz;

UPDATE public.authn_authenticator_enrollments SET expires_at = created_at + interval '10 minutes' WHERE state = 'pending';

ALTER TABLE public.authn_authenticator_enrollments DROP CONSTRAINT authn_authenticator_enrollments_state_check;
ALTER TABLE public.authn_authenticator_enrollments ADD CONSTRAINT authn_authenticator_enrollments_state_check
  CHECK (state IN ('pending', 'active', 'revoked', 'expired'));
ALTER TABLE public.authn_authenticator_enrollments ADD CONSTRAINT authn_enrollments_pending_expires
  CHECK (state <> 'pending' OR expires_at IS NOT NULL);

CREATE TABLE public.authn_totp_failures (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  enrollment_id uuid NOT NULL,
  at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, enrollment_id) REFERENCES public.authn_authenticator_enrollments (tenant_id, id)
);
CREATE INDEX authn_totp_failures_enrollment ON public.authn_totp_failures (tenant_id, enrollment_id, at);

ALTER TABLE public.authn_totp_failures ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.authn_totp_failures FORCE ROW LEVEL SECURITY;
CREATE POLICY authn_totp_failures_tenant ON public.authn_totp_failures
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
REVOKE UPDATE ON public.authn_totp_failures FROM activediq_app;
COMMENT ON TABLE public.authn_totp_failures IS 'Refused TOTP codes per enrolment (tenant table, RLS): the rolling-hour budget of ENH-09 §5. Only internal/platform/authn references it in SQL.';

-- Identity, seed and subject never change. State moves pending -> active|revoked|expired, active -> revoked;
-- expired and revoked are terminal. last_used_step and confirm_attempts only increase.
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
  RETURN NEW;
END
$fn$;

CREATE FUNCTION public.authn_enrollments_insert_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $fn$
BEGIN
  IF NEW.state <> 'pending' OR NEW.last_used_step IS NOT NULL OR NEW.last_used IS NOT NULL
     OR NEW.confirm_attempts <> 0 OR NEW.paused_until IS NOT NULL OR NEW.expires_at IS NULL THEN
    RAISE EXCEPTION 'authn_authenticator_enrollments: an enrollment starts pending, unused and with an expiry' USING ERRCODE = 'AD403';
  END IF;
  RETURN NEW;
END
$fn$;

CREATE TRIGGER authn_enrollments_insert_guard BEFORE INSERT ON public.authn_authenticator_enrollments
  FOR EACH ROW EXECUTE FUNCTION public.authn_enrollments_insert_guard();
ALTER TABLE public.authn_authenticator_enrollments ENABLE ALWAYS TRIGGER authn_enrollments_insert_guard;

-- Failure rows are pruned by the app, but only once they cannot count: the budget looks back one hour, the
-- app prunes at two, and the database refuses anything younger than 90 minutes (so a deleted row cannot
-- clear a pause that is about to be set).
CREATE FUNCTION public.authn_totp_failures_delete_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $fn$
BEGIN
  IF OLD.at > pg_catalog.now() - interval '90 minutes' THEN
    RAISE EXCEPTION 'authn_totp_failures: a failure younger than 90 minutes cannot be deleted' USING ERRCODE = 'AD403';
  END IF;
  RETURN OLD;
END
$fn$;

CREATE TRIGGER authn_totp_failures_delete_guard BEFORE DELETE ON public.authn_totp_failures
  FOR EACH ROW EXECUTE FUNCTION public.authn_totp_failures_delete_guard();
ALTER TABLE public.authn_totp_failures ENABLE ALWAYS TRIGGER authn_totp_failures_delete_guard;

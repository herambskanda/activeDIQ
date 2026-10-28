-- 0051_authn_enrollment_terminal_no_secret: TM-D29 controls 1+2 for DM-37 (T-0562; threat model §9.2.1).
-- Owner: internal/platform/authn.
--
-- A revoked or expired enrolment holds no seed: sealed_secret is NULL exactly in those two states, enforced
-- by a CHECK, and the guard lets the seed change only to NULL (the erase that rides with the terminal
-- transition). So an application-role attacker who saved an older blob cannot write it back into a
-- terminal row (the CHECK refuses it) and cannot make the row live again (terminal states are final).
-- Re-enrolment is a new row: no statement changes a seed in place.
-- DM-11 and DM-39 have no table yet; their tickets carry the same CHECK and trigger.

ALTER TABLE public.authn_authenticator_enrollments ALTER COLUMN sealed_secret DROP NOT NULL;

-- Erase the seeds of rows already terminal. The owner is bound by FORCE ROW LEVEL SECURITY and no tenant is
-- set here, so the policy would match no rows and the erase would silently do nothing (then the CHECK below
-- would fail the upgrade). Lift FORCE and the guard for this one statement, inside this migration's single
-- transaction, and put both back.
ALTER TABLE public.authn_authenticator_enrollments NO FORCE ROW LEVEL SECURITY;
ALTER TABLE public.authn_authenticator_enrollments DISABLE TRIGGER authn_enrollments_guard;
UPDATE public.authn_authenticator_enrollments SET sealed_secret = NULL WHERE state IN ('revoked', 'expired');
ALTER TABLE public.authn_authenticator_enrollments ENABLE ALWAYS TRIGGER authn_enrollments_guard;
ALTER TABLE public.authn_authenticator_enrollments FORCE ROW LEVEL SECURITY;

ALTER TABLE public.authn_authenticator_enrollments ADD CONSTRAINT authn_enrollments_terminal_no_secret
  CHECK ((state IN ('revoked', 'expired')) = (sealed_secret IS NULL));

CREATE OR REPLACE FUNCTION public.authn_enrollments_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $fn$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.account_id IS DISTINCT FROM OLD.account_id OR NEW.connection_id IS DISTINCT FROM OLD.connection_id
     OR NEW.object_guid IS DISTINCT FROM OLD.object_guid OR NEW.method IS DISTINCT FROM OLD.method
     OR NEW.key_version IS DISTINCT FROM OLD.key_version
     OR NEW.created_at IS DISTINCT FROM OLD.created_at OR NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
    RAISE EXCEPTION 'authn_authenticator_enrollments: identity, subject, key version and expiry are immutable' USING ERRCODE = 'AD403';
  END IF;
  -- The seed never changes in place; the one change is the erase that goes with a terminal state (the CHECK
  -- ties NULL to revoked/expired, so a NULL in any other state is refused there).
  IF NEW.sealed_secret IS DISTINCT FROM OLD.sealed_secret AND NEW.sealed_secret IS NOT NULL THEN
    RAISE EXCEPTION 'authn_authenticator_enrollments: the seed is immutable; re-enrolment is a new row' USING ERRCODE = 'AD403';
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
  IF OLD.paused_until IS NOT NULL AND (NEW.paused_until IS NULL OR NEW.paused_until < OLD.paused_until) THEN
    RAISE EXCEPTION 'authn_authenticator_enrollments: paused_until never decreases or clears' USING ERRCODE = 'AD403';
  END IF;
  IF NEW.refund_attempt IS DISTINCT FROM OLD.refund_attempt
     AND NOT (NEW.last_used_step IS NOT NULL AND (OLD.last_used_step IS NULL OR NEW.last_used_step > OLD.last_used_step)) THEN
    RAISE EXCEPTION 'authn_authenticator_enrollments: refund_attempt changes only when a step is spent' USING ERRCODE = 'AD403';
  END IF;
  RETURN NEW;
END
$fn$;

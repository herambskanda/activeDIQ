-- 0035_authn_totp_active_cap: at most three active console TOTP enrolments per account (T-0422; T-0198
-- review finding 2, AN-10). Sign-in tests every active enrolment of the account per attempt, so the
-- online guess rate would otherwise scale with N times the per-enrolment failure budget (DM-37.I5).
-- Enforced here, not in the application: a trigger on the transition into 'active' (and on an insert
-- that is born active) counts the account's other active TOTP rows under a per-account advisory lock,
-- so two concurrent activations cannot both pass. The count must see the other transaction's commit,
-- which a REPEATABLE READ snapshot taken before the lock would not, so that isolation level is refused
-- (READ COMMITTED re-reads after the lock; SERIALIZABLE fails the loser with 40001). End-user enrolments (keyed by directory object) are
-- not console factors and are not counted. SQLSTATE AD409 = cap reached.

CREATE FUNCTION public.authn_enrollments_active_cap() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, public
AS $fn$
DECLARE
  active_cap CONSTANT integer := 3;
  n integer;
BEGIN
  IF NEW.account_id IS NULL OR NEW.method <> 'totp' OR NEW.state <> 'active' THEN
    RETURN NEW;
  END IF;
  IF TG_OP = 'UPDATE' AND OLD.state = 'active' THEN
    RETURN NEW;
  END IF;
  IF current_setting('transaction_isolation') NOT IN ('read committed', 'read uncommitted') THEN
    RAISE EXCEPTION 'authn_authenticator_enrollments: activating a TOTP enrolment needs READ COMMITTED (the cap check must see concurrent commits)' USING ERRCODE = 'AD409';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('authn_totp_active_cap:' || NEW.tenant_id::text || ':' || NEW.account_id::text, 0));
  SELECT count(*) INTO n FROM public.authn_authenticator_enrollments
    WHERE tenant_id = NEW.tenant_id AND account_id = NEW.account_id AND method = 'totp' AND state = 'active' AND id <> NEW.id;
  IF n >= active_cap THEN
    RAISE EXCEPTION 'authn_authenticator_enrollments: an account may have at most % active TOTP enrolments', active_cap USING ERRCODE = 'AD409';
  END IF;
  RETURN NEW;
END
$fn$;

CREATE TRIGGER authn_enrollments_active_cap BEFORE INSERT OR UPDATE ON public.authn_authenticator_enrollments
  FOR EACH ROW EXECUTE FUNCTION public.authn_enrollments_active_cap();
ALTER TABLE public.authn_authenticator_enrollments ENABLE ALWAYS TRIGGER authn_enrollments_active_cap;

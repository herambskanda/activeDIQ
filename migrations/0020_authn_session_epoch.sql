-- 0020_authn_session_epoch: serialise session minting against credential, MFA and role changes (T-0429;
-- same race class as DM-31.I2). Owner: internal/platform/authn.
--
-- authn_accounts.session_epoch is bumped, under the row's exclusive lock, by every change that must end
-- the account's sessions and invalidate any sign-in that verified the old state: password reset, MFA
-- reset, role change (authn.Store.OnPasswordReset / OnMFAReset / OnRoleChanged). A sign-in reads the
-- epoch BEFORE it verifies a credential and presents it when it mints the session, which re-checks it
-- under FOR SHARE on the same row; a mismatch refuses the session.
--
-- authn_pending_signins.account_epoch carries the epoch captured before the first factor was verified,
-- so a second factor completed after a reset cannot turn the older first factor into a session.

ALTER TABLE public.authn_accounts ADD COLUMN session_epoch bigint NOT NULL DEFAULT 0 CHECK (session_epoch >= 0);
ALTER TABLE public.authn_pending_signins ADD COLUMN account_epoch bigint NOT NULL DEFAULT 0 CHECK (account_epoch >= 0);

-- The epoch is bound to the pending sign-in for life.
CREATE OR REPLACE FUNCTION public.authn_pending_signins_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $fn$
BEGIN
  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.id IS DISTINCT FROM OLD.id
     OR NEW.handle_hash IS DISTINCT FROM OLD.handle_hash OR NEW.account_id IS DISTINCT FROM OLD.account_id
     OR NEW.first_factor IS DISTINCT FROM OLD.first_factor OR NEW.client_ip IS DISTINCT FROM OLD.client_ip
     OR NEW.created_at IS DISTINCT FROM OLD.created_at OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
     OR NEW.account_epoch IS DISTINCT FROM OLD.account_epoch THEN
    RAISE EXCEPTION 'authn_pending_signins: identity, binding and expiry are never rewritten' USING ERRCODE = 'AD403';
  END IF;
  IF OLD.state <> 'active' THEN
    RAISE EXCEPTION 'authn_pending_signins: a % pending sign-in is final', OLD.state USING ERRCODE = 'AD403';
  END IF;
  IF NEW.attempts < OLD.attempts OR NEW.attempts > OLD.attempts + 1 THEN
    RAISE EXCEPTION 'authn_pending_signins: attempts only rise, by one' USING ERRCODE = 'AD403';
  END IF;
  RETURN NEW;
END
$fn$;

-- The epoch only rises, by one at a time.
CREATE FUNCTION public.authn_accounts_epoch_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $fn$
BEGIN
  IF NEW.session_epoch < OLD.session_epoch OR NEW.session_epoch > OLD.session_epoch + 1 THEN
    RAISE EXCEPTION 'authn_accounts: session_epoch only rises, by one' USING ERRCODE = 'AD403';
  END IF;
  RETURN NEW;
END
$fn$;

CREATE TRIGGER authn_accounts_epoch_guard BEFORE UPDATE ON public.authn_accounts
  FOR EACH ROW EXECUTE FUNCTION public.authn_accounts_epoch_guard();
ALTER TABLE public.authn_accounts ENABLE ALWAYS TRIGGER authn_accounts_epoch_guard;

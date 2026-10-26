-- 0017_authn_sessions_insert_guard: bound what the runtime role can INSERT into authn_sessions (T-0390).
-- Owner: internal/platform/authn.
--
-- 0013 guarded UPDATE and revoked DELETE but left INSERT open: arbitrary SQL as activediq_app could mint
-- an active session with a chosen token hash for any account, skipping password and TOTP. This trigger
-- makes a minted row at least look like a session the authn package could have written:
--   * it starts active and un-ended (also enforced by authn_sessions_ended);
--   * it is not already past its deadline and was last seen now (within 5 minutes of the DB clock);
--   * its absolute lifetime (created_at -> absolute_expiry) is at most 24 hours, the platform ceiling
--     (authn.DefaultBounds.AbsoluteMax), and the deadline is at most 24 hours + 5 minutes from now.
--     A rotated session legitimately keeps an older created_at, but never an older-than-24h window.
--
-- RESIDUAL (recorded in the threat model, §7.3): a session row IS the authentication result. A compromised
-- runtime role can still INSERT a well-formed, in-bounds session for any account, with a chosen hash.
-- The database cannot verify that a password or TOTP code was checked. The guard bounds the damage
-- (no immortal, backdated or pre-ended rows; at most 24 h of life) but is not a control against runtime
-- role compromise. Detection and containment are the audit trail and on-demand revocation.

CREATE FUNCTION public.authn_sessions_insert_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $fn$
DECLARE
  now_ts timestamptz := pg_catalog.clock_timestamp();
BEGIN
  IF NEW.state <> 'active' OR NEW.ended_at IS NOT NULL OR NEW.end_reason IS NOT NULL THEN
    RAISE EXCEPTION 'authn_sessions: a session starts active' USING ERRCODE = 'AD403';
  END IF;
  IF NEW.absolute_expiry <= now_ts OR NEW.idle_expiry <= now_ts THEN
    RAISE EXCEPTION 'authn_sessions: a session cannot start already expired' USING ERRCODE = 'AD403';
  END IF;
  IF NEW.last_seen_at < now_ts - interval '5 minutes' THEN
    RAISE EXCEPTION 'authn_sessions: a session cannot be backdated' USING ERRCODE = 'AD403';
  END IF;
  IF NEW.absolute_expiry - NEW.created_at > interval '24 hours'
     OR NEW.absolute_expiry > now_ts + interval '24 hours 5 minutes' THEN
    RAISE EXCEPTION 'authn_sessions: deadline beyond the platform maximum' USING ERRCODE = 'AD403';
  END IF;
  RETURN NEW;
END
$fn$;

CREATE TRIGGER authn_sessions_insert_guard BEFORE INSERT ON public.authn_sessions
  FOR EACH ROW EXECUTE FUNCTION public.authn_sessions_insert_guard();
ALTER TABLE public.authn_sessions ENABLE ALWAYS TRIGGER authn_sessions_insert_guard;

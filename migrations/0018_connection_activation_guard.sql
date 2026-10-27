-- 0018_connection_activation_guard: DM-10.I9 in the database (T-0246). Owner: internal/directory/connection.
--
-- Store.Activate is the one door into `active` from draft or verifying. This trigger makes the
-- database refuse any other door: a direct UPDATE (a repair by hand, a future writer, a compromised
-- runtime role) cannot move a connection draft|verifying -> active unless the gate evidence exists.
-- Evidence, as Qualifies/Activate read it in Go:
--   * last_verification_id names a run of this connection and its current credential (DM-10.I8, I9),
--   * the run completed no more than 15 minutes ago (FreshnessWindow),
--   * the run is a pass whose over-privilege check (V7 AD, EV3 Entra) is itself a pass, or
--   * the run is refused for over-privilege alone (that check failed; no other check failed or could
--     not be answered) and every over-privilege fingerprint is in the acknowledged set of the newest
--     Tier-0 override of the connection and credential, which no later passing run has cleared (DM-25.I4).
-- It fails closed: with no tenant context the tables read empty (FORCE RLS) and the update is refused.
-- The suspended -> active edge (resume, DM-10.I10) is not this gate and is not touched.
-- Freshness reads clock_timestamp(); the store's stamp is never earlier, so the Go gate is never looser.

CREATE FUNCTION public.connections_guard_activation() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $fn$
DECLARE
  v public.connection_verifications%ROWTYPE;
  chk text := CASE NEW.kind WHEN 'entra_tenant' THEN 'EV3' ELSE 'V7' END;
  ack text[];
  ack_at timestamptz;
BEGIN
  IF NEW.last_verification_id IS NULL THEN
    RAISE EXCEPTION 'connections: activation needs a verification (DM-10.I9)' USING ERRCODE = 'AD403';
  END IF;
  SELECT * INTO v FROM public.connection_verifications
    WHERE tenant_id = NEW.tenant_id AND id = NEW.last_verification_id
      AND connection_id = NEW.id AND credential_id = NEW.credential_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'connections: activation needs a verification of this connection and credential (DM-10.I9)' USING ERRCODE = 'AD403';
  END IF;
  IF clock_timestamp() - v.completed_at > interval '15 minutes' THEN
    RAISE EXCEPTION 'connections: the verification is older than 15 minutes (DM-10.I9)' USING ERRCODE = 'AD403';
  END IF;
  IF v.verdict = 'pass' AND v.outcomes ->> chk = 'pass' THEN
    RETURN NEW;
  END IF;
  IF v.verdict = 'refused' AND v.outcomes ->> chk = 'fail'
     AND NOT EXISTS (SELECT 1 FROM pg_catalog.jsonb_each_text(v.outcomes) o
                     WHERE o.key <> chk AND o.value IN ('fail', 'could_not_verify'))
     AND NOT EXISTS (SELECT 1 FROM pg_catalog.jsonb_each_text(v.outcomes) o WHERE o.value = 'could_not_verify') THEN
    SELECT o.acknowledged_fingerprints, o.acknowledged_at INTO ack, ack_at
      FROM public.connection_tier0_overrides o
      WHERE o.tenant_id = NEW.tenant_id AND o.connection_id = NEW.id AND o.credential_id = NEW.credential_id
      ORDER BY o.acknowledged_at DESC LIMIT 1;
    IF FOUND
       AND EXISTS (SELECT 1 FROM public.connection_verification_findings f
                   WHERE f.tenant_id = NEW.tenant_id AND f.verification_id = v.id AND f.check_name = chk)
       AND NOT EXISTS (SELECT 1 FROM public.connection_verification_findings f
                       WHERE f.tenant_id = NEW.tenant_id AND f.verification_id = v.id AND f.check_name = chk
                         AND NOT (f.fingerprint = ANY (ack)))
       AND NOT EXISTS (SELECT 1 FROM public.connection_verifications c
                       WHERE c.tenant_id = NEW.tenant_id AND c.connection_id = NEW.id AND c.credential_id = NEW.credential_id
                         AND c.completed_at > ack_at AND c.outcomes ->> chk = 'pass') THEN
      RETURN NEW;
    END IF;
  END IF;
  RAISE EXCEPTION 'connections: the verification does not open the activation gate (DM-10.I9)' USING ERRCODE = 'AD403';
END
$fn$;

CREATE TRIGGER connections_guard_activation BEFORE UPDATE ON public.connections
  FOR EACH ROW WHEN (OLD.state IN ('draft', 'verifying') AND NEW.state = 'active')
  EXECUTE FUNCTION public.connections_guard_activation();
ALTER TABLE public.connections ENABLE ALWAYS TRIGGER connections_guard_activation;

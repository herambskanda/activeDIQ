-- 0070_connection_activation_guard_warn: V7/EV3 `warn` is not a fail (T-1245). Owner: internal/directory/connection.
--
-- Replaces connections_guard_activation() from 0028. The rule of DM-10.I9 (a) and DM-25.I4 is now:
-- a pass verdict opens the gate when its over-privilege check (V7 AD, EV3 Entra) is `pass` or `warn`.
-- `warn` is a finding about the customer's own ACL (a broad principal holding a right on a tier0
-- object, T-0237), not rights the connection's identity holds; DM-24.I2 says warn never changes the
-- verdict. A run that clears an acknowledged override is likewise one whose check is pass or warn.
-- fail, could_not_verify and not_run still refuse, and the override still covers `fail` alone.
-- The trigger itself is unchanged.

CREATE OR REPLACE FUNCTION public.connections_guard_activation() RETURNS trigger
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
  IF v.verdict = 'pass' AND v.outcomes ->> chk IN ('pass', 'warn') THEN
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
                         AND c.completed_at > ack_at AND c.outcomes ->> chk IN ('pass', 'warn')) THEN
      RETURN NEW;
    END IF;
  END IF;
  RAISE EXCEPTION 'connections: the verification does not open the activation gate (DM-10.I9)' USING ERRCODE = 'AD403';
END
$fn$;

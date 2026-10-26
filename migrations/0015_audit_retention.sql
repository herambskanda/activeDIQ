-- 0015_audit_retention: key wipe, boundary lookups (T-0305; ADR-0005 rule 11, DM-81, AG-4, AG-6).
-- Owner: internal/platform/audit.
--
--   I5  a retired checkpoint key's private material can be destroyed, and only through
--       audit_wipe_retired_key(text). The runtime role still has no UPDATE on audit_checkpoint_key; it has
--       EXECUTE on that one SECURITY DEFINER function. The function refuses the newest key, a key whose
--       chained audit.checkpoint_key.retired event is not committed, and any other tenant's key, and the
--       table's update trigger refuses every change except "sealed_private_key becomes empty".
--   Retention (the purge itself) runs on the maintenance path under the owner role (I2) and needs no new
--   privilege. This migration adds the index that finds a time partition's last event.

CREATE INDEX audit_event_at ON public.audit_event (tenant_id, at);

-- The only update an audit_checkpoint_key row ever sees: its sealed private key is replaced by the empty
-- string. SECURITY INVOKER with a pinned search_path, as the other audit guards.
CREATE FUNCTION public.audit_checkpoint_key_guard_update() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $fn$
BEGIN
  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.key_id IS DISTINCT FROM OLD.key_id
     OR NEW.public_key IS DISTINCT FROM OLD.public_key OR NEW.key_version IS DISTINCT FROM OLD.key_version
     OR NEW.ordinal IS DISTINCT FROM OLD.ordinal OR NEW.sealed_private_key <> '\x'::bytea THEN
    RAISE EXCEPTION 'audit_checkpoint_key: the only change allowed is wiping the sealed private key' USING ERRCODE = 'AD403';
  END IF;
  RETURN NEW;
END
$fn$;

CREATE TRIGGER audit_checkpoint_key_guard_update BEFORE UPDATE ON public.audit_checkpoint_key
  FOR EACH ROW EXECUTE FUNCTION public.audit_checkpoint_key_guard_update();

-- I5. Runs with the owner's rights, which hold UPDATE; row-level security still applies (FORCE), so the
-- caller's tenant (app.tenant_id) is the only tenant it can touch. Returns true when it wiped, false when
-- the key was wiped already.
CREATE FUNCTION public.audit_wipe_retired_key(p_key_id text) RETURNS boolean
  LANGUAGE plpgsql
  SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  v_tenant uuid := NULLIF(current_setting('app.tenant_id', true), '')::uuid;
  v_ordinal integer;
  v_sealed bytea;
BEGIN
  IF v_tenant IS NULL THEN
    RAISE EXCEPTION 'audit_wipe_retired_key: no tenant context' USING ERRCODE = '42501';
  END IF;
  SELECT ordinal, sealed_private_key INTO v_ordinal, v_sealed
    FROM public.audit_checkpoint_key WHERE tenant_id = v_tenant AND key_id = p_key_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'audit_wipe_retired_key: unknown key' USING ERRCODE = 'AD403';
  END IF;
  IF v_ordinal = (SELECT max(ordinal) FROM public.audit_checkpoint_key WHERE tenant_id = v_tenant) THEN
    RAISE EXCEPTION 'audit_wipe_retired_key: the current key cannot be wiped' USING ERRCODE = 'AD403';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM public.audit_event e WHERE e.tenant_id = v_tenant
                 AND e.kind = 'audit.checkpoint_key.retired' AND e.event_id = 'audit.key.retired.' || p_key_id) THEN
    RAISE EXCEPTION 'audit_wipe_retired_key: the key has no committed retirement event' USING ERRCODE = 'AD403';
  END IF;
  IF octet_length(v_sealed) = 0 THEN
    RETURN false;
  END IF;
  UPDATE public.audit_checkpoint_key SET sealed_private_key = '\x'::bytea WHERE tenant_id = v_tenant AND key_id = p_key_id;
  RETURN true;
END
$fn$;

REVOKE ALL ON FUNCTION public.audit_wipe_retired_key(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.audit_wipe_retired_key(text) TO activediq_app;

COMMENT ON FUNCTION public.audit_wipe_retired_key(text) IS 'I5: destroys a retired checkpoint key''s sealed private key. The one SECURITY DEFINER function of the audit tables; the runtime role has no UPDATE on audit_checkpoint_key.';

-- 0055_fleet_ca_trust: the cross-tenant reader of fleet_ca public certificates for the gateway client-CA
-- pool, and the terminal 'withdrawn' CA state (T-0733; design T-0712, fleet-contract.md 'Gateway
-- client-CA pool'; TM-A11, TM-D24, TM-D29, TM-Q8). Owner: internal/platform/fleet (SQL in fleet/fleetsql).
--
--   activediq_catrust  NOLOGIN NOSUPERUSER NOBYPASSRLS, created by the installer beside the other two
--                      roles, with activediq_owner a member of it (ALTER FUNCTION ... OWNER TO needs the
--                      membership). It owns exactly one object, fleet_ca_trust_anchors(), and holds SELECT
--                      on six columns of fleet_ca: never sealed_key, key_version or created_at, and no write.
--                      A bug in the function body therefore cannot reach a key: the privilege error is the
--                      control. activediq_app is not a member (the 0001 guard refuses an owner of objects).

DO $guard$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'activediq_catrust') THEN
    RAISE EXCEPTION 'role activediq_catrust does not exist: the installer must create the trust-anchor reader role before migrating';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'activediq_catrust' AND (rolsuper OR rolbypassrls OR rolcanlogin OR rolcreaterole OR rolcreatedb)) THEN
    RAISE EXCEPTION 'activediq_catrust must be NOLOGIN, NOSUPERUSER, NOBYPASSRLS, NOCREATEROLE and NOCREATEDB (T-0712)';
  END IF;
  IF NOT pg_has_role(current_user, 'activediq_catrust', 'MEMBER') THEN
    RAISE EXCEPTION 'the migration role must be a member of activediq_catrust: the installer must GRANT activediq_catrust TO the owner role';
  END IF;
  IF pg_has_role('activediq_app', 'activediq_catrust', 'MEMBER') THEN
    RAISE EXCEPTION 'activediq_app must not be a member of activediq_catrust: it holds EXECUTE on the function only (T-0712)';
  END IF;
END
$guard$;

-- ---------------------------------------------------------------------------------------------------
-- The 'withdrawn' state and the sealed key that does not outlive its signing duty.
-- A retired or withdrawn CA signs nothing, so its sealed key is destroyed on the transition (NULL).
-- Rows retired before this migration still hold theirs; clear them first. The owner is bound by FORCE
-- row security and the guard refuses a key change, so both are lifted for this one statement and put back.
-- ---------------------------------------------------------------------------------------------------
-- This migration MUST apply atomically (one transaction): if it stopped between NO FORCE and FORCE,
-- fleet_ca would stay unforced and its guard disabled.
ALTER TABLE public.fleet_ca NO FORCE ROW LEVEL SECURITY;
ALTER TABLE public.fleet_ca DISABLE TRIGGER fleet_ca_guard;
UPDATE public.fleet_ca SET sealed_key = NULL WHERE state = 'retired';
ALTER TABLE public.fleet_ca ENABLE ALWAYS TRIGGER fleet_ca_guard;
ALTER TABLE public.fleet_ca FORCE ROW LEVEL SECURITY;

ALTER TABLE public.fleet_ca DROP CONSTRAINT fleet_ca_state_check;
ALTER TABLE public.fleet_ca ADD CONSTRAINT fleet_ca_state_check CHECK (state IN ('active', 'retired', 'withdrawn'));
ALTER TABLE public.fleet_ca ALTER COLUMN sealed_key DROP NOT NULL;
ALTER TABLE public.fleet_ca DROP CONSTRAINT fleet_ca_sealed_key_check;
ALTER TABLE public.fleet_ca ADD CONSTRAINT fleet_ca_sealed_key_check CHECK (
  (state = 'active' AND sealed_key IS NOT NULL AND octet_length(sealed_key) BETWEEN 32 AND 16384)
  OR (state <> 'active' AND sealed_key IS NULL));

-- Explicit transition allow-list; withdrawn is terminal (TM-D29). Only state (and the sealed key it
-- takes with it) is ever written.
CREATE OR REPLACE FUNCTION public.fleet_ca_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $fn$
BEGIN
  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.id IS DISTINCT FROM OLD.id
     OR NEW.cert_der IS DISTINCT FROM OLD.cert_der OR NEW.spki_sha256 IS DISTINCT FROM OLD.spki_sha256
     OR NEW.key_version IS DISTINCT FROM OLD.key_version OR NEW.not_after IS DISTINCT FROM OLD.not_after
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'fleet_ca: only state is ever written' USING ERRCODE = 'AD403';
  END IF;
  IF NEW.state IS NOT DISTINCT FROM OLD.state THEN
    IF NEW.sealed_key IS DISTINCT FROM OLD.sealed_key THEN
      RAISE EXCEPTION 'fleet_ca: the sealed key changes only with a state transition' USING ERRCODE = 'AD403';
    END IF;
    RETURN NEW;
  END IF;
  IF NOT ((OLD.state = 'active' AND NEW.state IN ('retired', 'withdrawn'))
          OR (OLD.state = 'retired' AND NEW.state = 'withdrawn')) THEN
    RAISE EXCEPTION 'fleet_ca: % -> % is not allowed', OLD.state, NEW.state USING ERRCODE = 'AD403';
  END IF;
  IF NEW.sealed_key IS NOT NULL THEN
    RAISE EXCEPTION 'fleet_ca: the sealed key is destroyed when a CA leaves the active state' USING ERRCODE = 'AD403';
  END IF;
  RETURN NEW;
END
$fn$;

-- A tenant is never left without a signing CA by a withdrawal. Checked at commit, so the compromise path
-- (active -> withdrawn, then insert the replacement active row) passes and a bare withdrawal does not.
-- SECURITY INVOKER: it counts under the caller's tenant (RLS), which is the tenant of the row.
CREATE FUNCTION public.fleet_ca_withdrawal_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $fn$
BEGIN
  IF (SELECT count(*) FROM public.fleet_ca WHERE tenant_id = NEW.tenant_id AND state = 'active') <> 1 THEN
    RAISE EXCEPTION 'fleet_ca: a withdrawal must leave the tenant with exactly one active CA' USING ERRCODE = 'AD403';
  END IF;
  RETURN NULL;
END
$fn$;

CREATE CONSTRAINT TRIGGER fleet_ca_withdrawal_guard AFTER UPDATE ON public.fleet_ca
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
  WHEN (NEW.state = 'withdrawn' AND OLD.state IS DISTINCT FROM 'withdrawn')
  EXECUTE FUNCTION public.fleet_ca_withdrawal_guard();
ALTER TABLE public.fleet_ca ENABLE ALWAYS TRIGGER fleet_ca_withdrawal_guard;

-- ---------------------------------------------------------------------------------------------------
-- The trust-anchor reader.
-- ---------------------------------------------------------------------------------------------------
GRANT USAGE ON SCHEMA public TO activediq_catrust;
GRANT SELECT (tenant_id, id, state, cert_der, spki_sha256, not_after) ON public.fleet_ca TO activediq_catrust;

CREATE POLICY fleet_ca_trust_read ON public.fleet_ca FOR SELECT TO activediq_catrust
  USING (state IN ('active', 'retired'));

-- Inverse of the guard in audit_wipe_retired_key: a tenant transaction can never call it; only a
-- platform-scope transaction (no app.tenant_id) can.
CREATE FUNCTION public.fleet_ca_trust_anchors()
  RETURNS TABLE (tenant_id uuid, spki_sha256 bytea, cert_der bytea, not_after timestamptz)
  LANGUAGE plpgsql
  SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $fn$
BEGIN
  IF NULLIF(current_setting('app.tenant_id', true), '') IS NOT NULL THEN
    RAISE EXCEPTION 'fleet_ca_trust_anchors: platform scope only' USING ERRCODE = '42501';
  END IF;
  RETURN QUERY
    SELECT c.tenant_id, c.spki_sha256, c.cert_der, c.not_after
      FROM public.fleet_ca c
     WHERE c.state IN ('active', 'retired') AND c.not_after > now();
END
$fn$;

REVOKE ALL ON FUNCTION public.fleet_ca_trust_anchors() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.fleet_ca_trust_anchors() TO activediq_app;

-- Hand ownership over. The new owner needs CREATE on the schema to receive it (PostgreSQL 15+ gives
-- public none); the grant lives only inside this migration.
GRANT CREATE ON SCHEMA public TO activediq_catrust;
ALTER FUNCTION public.fleet_ca_trust_anchors() OWNER TO activediq_catrust;
REVOKE CREATE ON SCHEMA public FROM activediq_catrust;

COMMENT ON FUNCTION public.fleet_ca_trust_anchors() IS 'Public CA certificates of every tenant (active and retired, unexpired) for the gateway client-CA pool. SECURITY DEFINER owned by activediq_catrust, which cannot read sealed_key; platform scope only. T-0712.';

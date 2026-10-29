-- Fixture: the gateway client-CA pool, as the real migration builds it (fleet-contract "Gateway client-CA pool").
-- A fleet_ca table with the secret columns, the column-limited reader role and the definer function.
CREATE TABLE fleet_ca (
  tenant_id uuid NOT NULL REFERENCES tenants (id),
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  state text NOT NULL DEFAULT 'active',
  cert_der bytea NOT NULL DEFAULT '\x00',
  spki_sha256 bytea NOT NULL DEFAULT '\x00',
  not_after timestamptz NOT NULL DEFAULT now() + interval '1 day',
  sealed_key bytea,
  key_version int NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id)
);
ALTER TABLE fleet_ca ENABLE ROW LEVEL SECURITY;
ALTER TABLE fleet_ca FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON fleet_ca
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
CREATE POLICY fleet_ca_trust_read ON fleet_ca FOR SELECT TO activediq_catrust USING (state IN ('active', 'retired'));

GRANT USAGE ON SCHEMA public TO activediq_catrust;
GRANT SELECT (tenant_id, id, state, cert_der, spki_sha256, not_after) ON public.fleet_ca TO activediq_catrust;

GRANT CREATE ON SCHEMA public TO activediq_catrust;
CREATE FUNCTION public.fleet_ca_trust_anchors() RETURNS TABLE (tenant_id uuid, spki_sha256 bytea, cert_der bytea, not_after timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $f$
BEGIN
  IF NULLIF(current_setting('app.tenant_id', true), '') IS NOT NULL THEN
    RAISE EXCEPTION 'platform scope only' USING ERRCODE = '42501';
  END IF;
  RETURN QUERY SELECT c.tenant_id, c.spki_sha256, c.cert_der, c.not_after FROM public.fleet_ca c
    WHERE c.state IN ('active', 'retired') AND c.not_after > now();
END
$f$;
ALTER FUNCTION public.fleet_ca_trust_anchors() OWNER TO activediq_catrust;
REVOKE CREATE ON SCHEMA public FROM activediq_catrust;
REVOKE ALL ON FUNCTION public.fleet_ca_trust_anchors() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.fleet_ca_trust_anchors() TO activediq_app;

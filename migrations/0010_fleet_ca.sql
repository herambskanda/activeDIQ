-- 0010_fleet_ca: the installation CA of the fleet (T-0155; threat model TM-A11, TM-D24 rule D).
-- Owner: internal/platform/fleet (SQL in fleet/fleetsql). One tenant table.
--
-- The CA that signs component leaf certificates is held per tenant, so its private key is sealed under
-- that tenant's DEK (keys.Seal, bound to tenant, table, row, column and key version) and a tenant
-- row cannot be read or replaced from another tenant's context (FORCE ROW LEVEL SECURITY).
--
--   cert_der      the public CA certificate, one DER certificate per row. Never PEM, never a key.
--                 The bundle served to a host is built from these rows by parsing each one.
--   sealed_key    the CA private key, PKCS#8, AEAD-sealed. Never plaintext; no column holds it.
--   spki_sha256   SHA-256 of the certificate's SubjectPublicKeyInfo: the pin shown with enrolment
--                 material (TM-D24 D1).
-- At most one 'active' CA per tenant signs leaves; a 'retired' CA stays in the bundle until removed so
-- that leaves it signed keep verifying.

-- write-class: fleet_ca system
CREATE TABLE public.fleet_ca (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  state text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'retired')),
  cert_der bytea NOT NULL CHECK (octet_length(cert_der) BETWEEN 64 AND 16384),
  spki_sha256 bytea NOT NULL CHECK (octet_length(spki_sha256) = 32),
  sealed_key bytea NOT NULL CHECK (octet_length(sealed_key) BETWEEN 32 AND 16384),
  key_version integer NOT NULL CHECK (key_version > 0),
  not_after timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id)
);

CREATE UNIQUE INDEX fleet_ca_one_active ON public.fleet_ca (tenant_id) WHERE state = 'active';
CREATE UNIQUE INDEX fleet_ca_spki ON public.fleet_ca (tenant_id, spki_sha256);

ALTER TABLE public.fleet_ca ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.fleet_ca FORCE ROW LEVEL SECURITY;
CREATE POLICY fleet_ca_tenant ON public.fleet_ca
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

REVOKE DELETE ON public.fleet_ca FROM activediq_app;

COMMENT ON TABLE public.fleet_ca IS 'Installation CA of the fleet (tenant table, RLS). The private key is sealed (TM-A11). Only internal/platform/fleet/fleetsql references it in SQL.';

-- Only the state may change, and only active -> retired.
CREATE FUNCTION public.fleet_ca_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $fn$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id OR NEW.cert_der IS DISTINCT FROM OLD.cert_der
     OR NEW.spki_sha256 IS DISTINCT FROM OLD.spki_sha256 OR NEW.sealed_key IS DISTINCT FROM OLD.sealed_key
     OR NEW.key_version IS DISTINCT FROM OLD.key_version OR NEW.not_after IS DISTINCT FROM OLD.not_after
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'fleet_ca: only state is ever written' USING ERRCODE = 'AD403';
  END IF;
  IF NEW.state IS DISTINCT FROM OLD.state AND NOT (OLD.state = 'active' AND NEW.state = 'retired') THEN
    RAISE EXCEPTION 'fleet_ca: % -> % is not allowed', OLD.state, NEW.state USING ERRCODE = 'AD403';
  END IF;
  RETURN NEW;
END
$fn$;

CREATE TRIGGER fleet_ca_guard BEFORE UPDATE ON public.fleet_ca
  FOR EACH ROW EXECUTE FUNCTION public.fleet_ca_guard();
ALTER TABLE public.fleet_ca ENABLE ALWAYS TRIGGER fleet_ca_guard;

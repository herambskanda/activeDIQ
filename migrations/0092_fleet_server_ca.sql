-- 0084_fleet_server_ca: the installation-scope server CA of the fleet gateway (T-0735; ADR-0008 item 1,
-- obligation 7; TM-TB6-T15). Owner: internal/platform/fleet (SQL in fleet/fleetsql). One registered-global
-- table: no tenant_id and no RLS (ADR-0002 rule 4), because the CA belongs to the installation.
--
-- This CA signs ServerAuth leaves only. Its certificate is ECDSA P-384, IsCA, MaxPathLen 0, KeyUsageCertSign
-- only and EKU ServerAuth, and it is never in the gateway's client pool, so it cannot validate a component
-- identity. Component identities stay under the per-tenant CAs (fleet_ca).
--
--   cert_der      the public CA certificate, one DER certificate per row. Never PEM, never a key.
--   sealed_key    the CA private key, PKCS#8, sealed under the INSTALLATION DEK (keys.SealInstallation, bound
--                 to table, row, column and key version; no tenant). Present while the CA is active; a
--                 retired or withdrawn CA signs nothing, so its key is destroyed (NULL) by the transition.
--   spki_sha256   SHA-256 of the certificate's SubjectPublicKeyInfo: the installation-wide pin (TM-D24 D1).
-- At most one 'active' row signs. Only state (and the key it takes with it) is ever written.

-- write-class: fleet_server_ca system
CREATE TABLE public.fleet_server_ca (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  state text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'retired', 'withdrawn')),
  cert_der bytea NOT NULL CHECK (octet_length(cert_der) BETWEEN 64 AND 16384),
  spki_sha256 bytea NOT NULL CHECK (octet_length(spki_sha256) = 32),
  sealed_key bytea,
  key_version integer NOT NULL CHECK (key_version > 0),
  not_after timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT fleet_server_ca_sealed_key_check CHECK (
    (state = 'active' AND sealed_key IS NOT NULL AND octet_length(sealed_key) BETWEEN 32 AND 16384)
    OR (state <> 'active' AND sealed_key IS NULL))
);

CREATE UNIQUE INDEX fleet_server_ca_one_active ON public.fleet_server_ca ((true)) WHERE state = 'active';
CREATE UNIQUE INDEX fleet_server_ca_spki ON public.fleet_server_ca (spki_sha256);

REVOKE DELETE, TRUNCATE ON public.fleet_server_ca FROM activediq_app;

COMMENT ON TABLE public.fleet_server_ca IS 'Installation server CA of the fleet gateway (registered-global). Signs ServerAuth leaves only. The private key is sealed under the installation DEK (TM-A11, ADR-0008). Only internal/platform/fleet/fleetsql references it in SQL.';

CREATE FUNCTION public.fleet_server_ca_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $fn$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id OR NEW.cert_der IS DISTINCT FROM OLD.cert_der
     OR NEW.spki_sha256 IS DISTINCT FROM OLD.spki_sha256 OR NEW.key_version IS DISTINCT FROM OLD.key_version
     OR NEW.not_after IS DISTINCT FROM OLD.not_after OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'fleet_server_ca: only state is ever written' USING ERRCODE = 'AD403';
  END IF;
  IF NEW.state IS NOT DISTINCT FROM OLD.state THEN
    IF NEW.sealed_key IS DISTINCT FROM OLD.sealed_key THEN
      RAISE EXCEPTION 'fleet_server_ca: the sealed key changes only with a state transition' USING ERRCODE = 'AD403';
    END IF;
    RETURN NEW;
  END IF;
  IF NOT ((OLD.state = 'active' AND NEW.state IN ('retired', 'withdrawn'))
          OR (OLD.state = 'retired' AND NEW.state = 'withdrawn')) THEN
    RAISE EXCEPTION 'fleet_server_ca: % -> % is not allowed', OLD.state, NEW.state USING ERRCODE = 'AD403';
  END IF;
  IF NEW.sealed_key IS NOT NULL THEN
    RAISE EXCEPTION 'fleet_server_ca: the sealed key is destroyed when a CA leaves the active state' USING ERRCODE = 'AD403';
  END IF;
  RETURN NEW;
END
$fn$;

CREATE TRIGGER fleet_server_ca_guard BEFORE UPDATE ON public.fleet_server_ca
  FOR EACH ROW EXECUTE FUNCTION public.fleet_server_ca_guard();
ALTER TABLE public.fleet_server_ca ENABLE ALWAYS TRIGGER fleet_server_ca_guard;

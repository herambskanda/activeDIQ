-- 0016_authn_authenticator_enrollments: DM-37 AuthenticatorEnrollment, the TOTP slice (T-0196; threat
-- model §7.2, TM-F-SEAL). Owner: internal/platform/authn. One tenant table.
--
--   sealed_secret   the TOTP seed, AEAD-sealed under the tenant DEK with associated data binding tenant,
--                   table, row, column and key version (keys.Seal, TM-D7). No column holds it in clear
--                   and no read path of the package returns it (DM-37.I1).
--   key_version     the DEK version that sealed it (DM-02.I2).
--   last_used_step  the highest 30 s time step a code was accepted for. A code verifies only for a step
--                   strictly above it, so no code verifies twice (RFC 6238 §5.2). The update that
--                   advances it is conditional, so two concurrent submissions of one code cannot both win.
--   subject         a console account (account_id), or a directory user as connection + objectGUID.
-- Methods other than totp arrive with their own tickets; they get their own columns and checks.

-- write-class: authn_authenticator_enrollments system
CREATE TABLE public.authn_authenticator_enrollments (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  account_id uuid,
  connection_id uuid,
  object_guid uuid,
  method text NOT NULL CHECK (method IN ('totp')),
  sealed_secret bytea NOT NULL CHECK (octet_length(sealed_secret) BETWEEN 32 AND 1024),
  key_version integer NOT NULL CHECK (key_version > 0),
  label text NOT NULL CHECK (char_length(label) BETWEEN 1 AND 128),
  state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'active', 'revoked')),
  last_used_step bigint CHECK (last_used_step >= 0),
  last_used timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CHECK ((account_id IS NOT NULL AND connection_id IS NULL AND object_guid IS NULL)
      OR (account_id IS NULL AND connection_id IS NOT NULL AND object_guid IS NOT NULL)),
  CHECK ((last_used_step IS NULL) = (last_used IS NULL))
);

CREATE INDEX authn_enrollments_account ON public.authn_authenticator_enrollments (tenant_id, account_id) WHERE account_id IS NOT NULL;
CREATE INDEX authn_enrollments_directory ON public.authn_authenticator_enrollments (tenant_id, connection_id, object_guid) WHERE object_guid IS NOT NULL;

ALTER TABLE public.authn_authenticator_enrollments ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.authn_authenticator_enrollments FORCE ROW LEVEL SECURITY;
CREATE POLICY authn_enrollments_tenant ON public.authn_authenticator_enrollments
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

REVOKE DELETE ON public.authn_authenticator_enrollments FROM activediq_app;

COMMENT ON TABLE public.authn_authenticator_enrollments IS 'DM-37 AuthenticatorEnrollment (tenant table, RLS). The TOTP seed is sealed (TM-F-SEAL). Only internal/platform/authn references it in SQL.';

-- Identity, seed and subject never change (tenant_id is held by the RLS WITH CHECK). The state moves pending -> active -> revoked only.
-- last_used_step only ever increases.
CREATE FUNCTION public.authn_enrollments_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $fn$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.account_id IS DISTINCT FROM OLD.account_id OR NEW.connection_id IS DISTINCT FROM OLD.connection_id
     OR NEW.object_guid IS DISTINCT FROM OLD.object_guid OR NEW.method IS DISTINCT FROM OLD.method
     OR NEW.sealed_secret IS DISTINCT FROM OLD.sealed_secret OR NEW.key_version IS DISTINCT FROM OLD.key_version
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'authn_authenticator_enrollments: identity, subject and seed are immutable' USING ERRCODE = 'AD403';
  END IF;
  IF NEW.state IS DISTINCT FROM OLD.state
     AND NOT ((OLD.state = 'pending' AND NEW.state IN ('active', 'revoked')) OR (OLD.state = 'active' AND NEW.state = 'revoked')) THEN
    RAISE EXCEPTION 'authn_authenticator_enrollments: % -> % is not allowed', OLD.state, NEW.state USING ERRCODE = 'AD403';
  END IF;
  IF OLD.last_used_step IS NOT NULL AND (NEW.last_used_step IS NULL OR NEW.last_used_step < OLD.last_used_step) THEN
    RAISE EXCEPTION 'authn_authenticator_enrollments: last_used_step never decreases' USING ERRCODE = 'AD403';
  END IF;
  RETURN NEW;
END
$fn$;

CREATE TRIGGER authn_enrollments_guard BEFORE UPDATE ON public.authn_authenticator_enrollments
  FOR EACH ROW EXECUTE FUNCTION public.authn_enrollments_guard();
ALTER TABLE public.authn_authenticator_enrollments ENABLE ALWAYS TRIGGER authn_enrollments_guard;

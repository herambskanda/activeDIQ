-- 0022_connection_takeover_attestation: DM-10.I7 takeover-protection attestation (threat model §6.8,
-- TM-D17). Owner: internal/directory/connection.
--
-- The latest attestation lives on the Entra connection: who signed in (the Global Administrator's
-- object ID), when, and the two values read from Graph. takeover_protection is DERIVED from these
-- columns at every evaluation and is never stored, so ageing out needs no job (I7(c)).
-- No token column exists anywhere: the delegated token is used once, in memory, and discarded.
--
--   attestation_max_age  seconds; default and cap 90 days (I7(c)); a tenant may shorten, never lengthen.
--   first_attested_at    set once by the first attestation that yields 'attested', never changed (I7(f)).
--   demoted_at           a demotion signal (I7(d)): a sync-feature change seen after attested_at.
--
-- connection_attestation_attempts holds the PKCE verifier and the hashed state of a started attempt
-- until the callback consumes it (single use, short expiry). It holds no token.

ALTER TABLE public.connections
  ADD COLUMN attested_by text CHECK (attested_by IS NULL OR attested_by ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
  ADD COLUMN attested_at timestamptz,
  ADD COLUMN attested_block_hard_match boolean,
  ADD COLUMN attested_block_soft_match boolean,
  ADD COLUMN attestation_max_age_seconds integer NOT NULL DEFAULT 7776000
    CHECK (attestation_max_age_seconds > 0 AND attestation_max_age_seconds <= 7776000),
  ADD COLUMN first_attested_at timestamptz,
  ADD COLUMN demoted_at timestamptz,
  ADD CONSTRAINT connections_attestation_whole CHECK (
    (attested_by IS NULL) = (attested_at IS NULL)
    AND (attested_by IS NULL) = (attested_block_hard_match IS NULL)
    AND (attested_by IS NULL) = (attested_block_soft_match IS NULL)),
  ADD CONSTRAINT connections_attestation_entra_only CHECK (kind = 'entra_tenant' OR
    (attested_at IS NULL AND first_attested_at IS NULL AND demoted_at IS NULL)),
  ADD CONSTRAINT connections_first_attested_has_attestation CHECK (first_attested_at IS NULL OR attested_at IS NOT NULL);

-- I7(f): first_attested_at is set once and never changes.
CREATE FUNCTION public.connections_first_attested_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $fn$
BEGIN
  IF OLD.first_attested_at IS NOT NULL AND NEW.first_attested_at IS DISTINCT FROM OLD.first_attested_at THEN
    RAISE EXCEPTION 'connections: first_attested_at is set once (DM-10.I7(f))' USING ERRCODE = 'AD403';
  END IF;
  RETURN NEW;
END
$fn$;

CREATE TRIGGER connections_first_attested_guard BEFORE UPDATE ON public.connections
  FOR EACH ROW EXECUTE FUNCTION public.connections_first_attested_guard();
ALTER TABLE public.connections ENABLE ALWAYS TRIGGER connections_first_attested_guard;

CREATE TABLE public.connection_attestation_attempts (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  connection_id uuid NOT NULL,
  state_hash bytea NOT NULL CHECK (length(state_hash) = 32),
  code_verifier text NOT NULL CHECK (length(code_verifier) BETWEEN 43 AND 128),
  started_by text NOT NULL CHECK (started_by <> ''),
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, connection_id) REFERENCES public.connections (tenant_id, id),
  UNIQUE (tenant_id, state_hash)
);

ALTER TABLE public.connection_attestation_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.connection_attestation_attempts FORCE ROW LEVEL SECURITY;
CREATE POLICY connection_attestation_attempts_tenant ON public.connection_attestation_attempts
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

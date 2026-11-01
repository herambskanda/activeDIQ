-- 0017_authn_sessions: console sessions (T-0194; DM-31, threat model §7.3, ADR-0002 rule 6, ADM-145).
-- Owner: internal/platform/authn. One tenant table.
--
-- A session lives in PostgreSQL so any server node serves it and a revocation made on one node is seen
-- by every other on its next lookup. Only a SHA-256 of the session token is stored (id_hash): a read of
-- this table, a backup or a replica yields nothing that can be replayed as a cookie.
--
--   id                 a stable handle for listing and revoking on demand. It is not the token.
--   id_hash            SHA-256 of the token, 32 bytes. Unique per tenant.
--   methods            how the account authenticated (for example password, totp); a closed set is
--                      the caller's, the store only bounds it.
--   mfa_at             when the session last passed MFA (step-up reads it, threat model §7.4).
--   authority_factor_at  DM-31.I3: set when the session verified an authority factor; the authn
--                      package clears it on a failed verification.
--   idle_expiry        slides forward on use, never past absolute_expiry.
--   absolute_expiry    fixed at creation.
--   state              active -> expired | revoked, and nothing leaves expired or revoked.
--   ended_at, end_reason  when and why it ended; end_reason is a closed set.
-- Rows are kept after they end (the audit trail refers to them); the runtime role cannot delete them.

-- write-class: authn_sessions system
CREATE TABLE public.authn_sessions (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  id_hash bytea NOT NULL CHECK (octet_length(id_hash) = 32),
  account_id uuid NOT NULL,
  methods text[] NOT NULL CHECK (cardinality(methods) BETWEEN 1 AND 8),
  mfa_at timestamptz,
  authority_factor_at timestamptz,
  client_ip inet,
  created_at timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL,
  idle_expiry timestamptz NOT NULL,
  absolute_expiry timestamptz NOT NULL,
  state text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'expired', 'revoked')),
  ended_at timestamptz,
  end_reason text CHECK (end_reason IN ('idle_timeout', 'absolute_timeout', 'concurrent_limit', 'account_disabled',
    'role_changed', 'password_reset', 'mfa_reset', 'logout', 'on_demand')),
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT authn_sessions_expiry_order CHECK (idle_expiry <= absolute_expiry AND absolute_expiry > created_at),
  CONSTRAINT authn_sessions_ended CHECK ((state = 'active') = (ended_at IS NULL AND end_reason IS NULL)),
  CONSTRAINT authn_sessions_expired_reason CHECK (state <> 'expired' OR end_reason IN ('idle_timeout', 'absolute_timeout')),
  CONSTRAINT authn_sessions_revoked_reason CHECK (state <> 'revoked' OR end_reason NOT IN ('idle_timeout', 'absolute_timeout'))
);

CREATE UNIQUE INDEX authn_sessions_hash ON public.authn_sessions (tenant_id, id_hash);
CREATE INDEX authn_sessions_account_active ON public.authn_sessions (tenant_id, account_id, created_at) WHERE state = 'active';

ALTER TABLE public.authn_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.authn_sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY authn_sessions_tenant ON public.authn_sessions
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

REVOKE DELETE ON public.authn_sessions FROM activediq_app;

COMMENT ON TABLE public.authn_sessions IS 'DM-31 console sessions (tenant table, RLS). Only a hash of the session token is stored. Only internal/platform/authn references it in SQL.';

-- Identity and the expiry bounds never change; an ended session never comes back; only the liveness
-- fields move while it is active.
CREATE FUNCTION public.authn_sessions_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $fn$
BEGIN
  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.id IS DISTINCT FROM OLD.id
     OR NEW.id_hash IS DISTINCT FROM OLD.id_hash OR NEW.account_id IS DISTINCT FROM OLD.account_id
     OR NEW.methods IS DISTINCT FROM OLD.methods OR NEW.client_ip IS DISTINCT FROM OLD.client_ip
     OR NEW.created_at IS DISTINCT FROM OLD.created_at OR NEW.absolute_expiry IS DISTINCT FROM OLD.absolute_expiry THEN
    RAISE EXCEPTION 'authn_sessions: identity and absolute expiry are never rewritten' USING ERRCODE = 'AD403';
  END IF;
  IF OLD.state <> 'active' THEN
    RAISE EXCEPTION 'authn_sessions: a % session is final', OLD.state USING ERRCODE = 'AD403';
  END IF;
  RETURN NEW;
END
$fn$;

CREATE TRIGGER authn_sessions_guard BEFORE UPDATE ON public.authn_sessions
  FOR EACH ROW EXECUTE FUNCTION public.authn_sessions_guard();
ALTER TABLE public.authn_sessions ENABLE ALWAYS TRIGGER authn_sessions_guard;

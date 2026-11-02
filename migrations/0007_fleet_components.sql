-- 0007_fleet_components: DM-12 Component and its sub-entity EnrollmentToken (domain-model DM-12,
-- ADR-0003 F1, threat model TM-TB6-T1). Owner: internal/platform/fleet (SQL in fleet/fleetsql, which
-- only the server links: blueprint §2 rule 7).
--
-- Database-stated invariants:
--   I1  every row carries tenant_id with a composite foreign key and one fail-closed FORCE ROW LEVEL
--       SECURITY policy; the tenant of a component comes from here, never from a message.
--   I2  an enrollment token is single-use (used_at is written once, by compare-and-set), expiring
--       (expires_at is mandatory and at most 24 hours after creation) and stored hashed (only the
--       SHA-256 of the secret, 32 bytes; the plaintext never reaches this table).
--   Lifecycle  pending -> enrolled -> active -> revoked -> removed, with enrolled -> revoked and
--       pending -> removed (a token that was never redeemed). The SQL twin of the Go table in
--       fleetsql; removed is terminal.
-- Host facts, providers, server endpoints and the certificate identity arrive with the Enroll
-- handler, which is the first writer of them.

-- write-class: components system
CREATE TABLE public.components (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  kind text NOT NULL CHECK (kind IN ('connector', 'agent')),
  name text NOT NULL CHECK (name <> '' AND length(name) <= 200),
  state text NOT NULL DEFAULT 'pending'
    CHECK (state IN ('pending', 'enrolled', 'active', 'revoked', 'removed')),
  -- Hex serial of the current leaf certificate; set at enrolment, replaced on rotation (I3).
  cert_serial text CHECK (cert_serial IS NULL OR cert_serial ~ '^[0-9a-f]{1,80}$'),
  last_seen_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id)
);

CREATE INDEX components_tenant_state ON public.components (tenant_id, state, created_at, id);

-- write-class: enrollment_tokens config
CREATE TABLE public.enrollment_tokens (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  component_id uuid NOT NULL,
  -- SHA-256 of the token secret. The secret is 256 random bits, so a fast hash is the right one.
  token_hash bytea NOT NULL CHECK (octet_length(token_hash) = 32),
  -- The real human who issued it (the principal ID behind any delegated account).
  issued_by text NOT NULL CHECK (issued_by <> '' AND length(issued_by) <= 200),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  used_at timestamptz,
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, component_id) REFERENCES public.components (tenant_id, id),
  CHECK (expires_at > created_at AND expires_at <= created_at + interval '24 hours'),
  CHECK (used_at IS NULL OR used_at >= created_at)
);

-- The redeem lookup, and the guarantee that two tokens never collide on one hash.
CREATE UNIQUE INDEX enrollment_tokens_hash ON public.enrollment_tokens (tenant_id, token_hash);
CREATE INDEX enrollment_tokens_component ON public.enrollment_tokens (tenant_id, component_id);

ALTER TABLE public.components ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.components FORCE ROW LEVEL SECURITY;
CREATE POLICY components_tenant ON public.components
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

ALTER TABLE public.enrollment_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.enrollment_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY enrollment_tokens_tenant ON public.enrollment_tokens
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

-- Removal is a state and a used token is evidence: neither table loses rows.
REVOKE DELETE ON public.components FROM activediq_app;
REVOKE DELETE ON public.enrollment_tokens FROM activediq_app;

COMMENT ON TABLE public.components IS 'DM-12 Component (tenant table, RLS). Only internal/platform/fleet/fleetsql references it in SQL.';
COMMENT ON TABLE public.enrollment_tokens IS 'DM-12 EnrollmentToken (tenant table, RLS). Holds the SHA-256 of the token, never the token.';

-- Guards back up the Go store for what must hold whatever writes the row. SECURITY INVOKER with a
-- pinned search_path, as connections_guard.
CREATE FUNCTION public.components_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $fn$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id OR NEW.kind IS DISTINCT FROM OLD.kind THEN
    RAISE EXCEPTION 'components: id and kind never change' USING ERRCODE = 'AD403';
  END IF;
  IF NEW.state IS DISTINCT FROM OLD.state AND (OLD.state, NEW.state) NOT IN (
    ('pending', 'enrolled'),
    ('pending', 'removed'),
    ('enrolled', 'active'),
    ('enrolled', 'revoked'),
    ('active', 'revoked'),
    ('revoked', 'removed')
  ) THEN
    RAISE EXCEPTION 'components: % -> % is not a DM-12 transition', OLD.state, NEW.state USING ERRCODE = 'AD403';
  END IF;
  RETURN NEW;
END
$fn$;

CREATE TRIGGER components_guard BEFORE UPDATE ON public.components
  FOR EACH ROW EXECUTE FUNCTION public.components_guard();
ALTER TABLE public.components ENABLE ALWAYS TRIGGER components_guard;

CREATE FUNCTION public.components_guard_insert() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $fn$
BEGIN
  IF NEW.state <> 'pending' OR NEW.cert_serial IS NOT NULL OR NEW.last_seen_at IS NOT NULL THEN
    RAISE EXCEPTION 'components: a component is created pending, with no certificate (DM-12)' USING ERRCODE = 'AD403';
  END IF;
  RETURN NEW;
END
$fn$;

CREATE TRIGGER components_guard_insert BEFORE INSERT ON public.components
  FOR EACH ROW EXECUTE FUNCTION public.components_guard_insert();
ALTER TABLE public.components ENABLE ALWAYS TRIGGER components_guard_insert;

-- DM-12.I2: a token is born unused; afterwards the only legal change is used_at going from NULL to a
-- time within its lifetime, once. The hash, the expiry and the issuer never change.
CREATE FUNCTION public.enrollment_tokens_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $fn$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id OR NEW.component_id IS DISTINCT FROM OLD.component_id
     OR NEW.token_hash IS DISTINCT FROM OLD.token_hash OR NEW.issued_by IS DISTINCT FROM OLD.issued_by
     OR NEW.created_at IS DISTINCT FROM OLD.created_at OR NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
    RAISE EXCEPTION 'enrollment_tokens: only used_at is ever written (DM-12.I2)' USING ERRCODE = 'AD403';
  END IF;
  IF OLD.used_at IS NOT NULL AND NEW.used_at IS DISTINCT FROM OLD.used_at THEN
    RAISE EXCEPTION 'enrollment_tokens: a token is single-use (DM-12.I2)' USING ERRCODE = 'AD403';
  END IF;
  IF NEW.used_at IS NOT NULL AND OLD.used_at IS NULL AND NEW.used_at > OLD.expires_at THEN
    RAISE EXCEPTION 'enrollment_tokens: an expired token cannot be used (DM-12.I2)' USING ERRCODE = 'AD403';
  END IF;
  RETURN NEW;
END
$fn$;

CREATE TRIGGER enrollment_tokens_guard BEFORE UPDATE ON public.enrollment_tokens
  FOR EACH ROW EXECUTE FUNCTION public.enrollment_tokens_guard();
ALTER TABLE public.enrollment_tokens ENABLE ALWAYS TRIGGER enrollment_tokens_guard;

CREATE FUNCTION public.enrollment_tokens_guard_insert() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $fn$
BEGIN
  IF NEW.used_at IS NOT NULL THEN
    RAISE EXCEPTION 'enrollment_tokens: a token is created unused (DM-12.I2)' USING ERRCODE = 'AD403';
  END IF;
  RETURN NEW;
END
$fn$;

CREATE TRIGGER enrollment_tokens_guard_insert BEFORE INSERT ON public.enrollment_tokens
  FOR EACH ROW EXECUTE FUNCTION public.enrollment_tokens_guard_insert();
ALTER TABLE public.enrollment_tokens ENABLE ALWAYS TRIGGER enrollment_tokens_guard_insert;

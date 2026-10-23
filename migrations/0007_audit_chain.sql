-- 0007_audit_chain: the per-tenant audit hash chain (DM-80, DM-81; ADR-0005 rule 11, threat model
-- TM-F-AUDIT). Owner: internal/platform/audit.
--
-- Database-stated invariants:
--   I1  every table carries tenant_id with a foreign key to tenants and one fail-closed FORCE ROW LEVEL
--       SECURITY policy.
--   I2  the runtime role can only add to audit_event, audit_checkpoint and audit_checkpoint_key: UPDATE and
--       DELETE are revoked, TRUNCATE is never granted. Retention purges run on the maintenance path under the
--       owner role, not here.
--   I3  audit_head is the one mutable audit table. Its row lock serialises a tenant's appenders. A row can
--       only be created as the genesis (seq 0, hash_0 recomputed here with sha256()) and with `at` set by the
--       database; it can only move forward. The triggers are not SECURITY DEFINER; they bind a role that cannot
--       set session_replication_role, which fitness-audit A1 asserts (fitness-tenancy T3 does too).
--   I4  a checkpoint can only name an event that exists with the same hash, so the runtime role cannot
--       insert a checkpoint for a head that was never chained.
--   Tail-keeping: (tenant_id, seq) is the primary key of audit_event, so a stale head cannot fork the chain,
--   and (tenant_id, event_id) is unique so a retried append after an ambiguous COMMIT is not recorded twice.

CREATE TABLE public.audit_head (
  tenant_id uuid PRIMARY KEY REFERENCES public.tenants (id),
  seq bigint NOT NULL CHECK (seq >= 0),
  hash bytea NOT NULL CHECK (octet_length(hash) = 32),
  at timestamptz NOT NULL
);

CREATE TABLE public.audit_event (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  seq bigint NOT NULL CHECK (seq >= 1),
  at timestamptz NOT NULL,
  event_id text NOT NULL CHECK (event_id <> '' AND length(event_id) <= 200),
  kind text NOT NULL CHECK (kind <> '' AND length(kind) <= 200),
  -- adq-canon/1 of the envelope without prev_hash and hash. The hashed bytes, so the verifier needs no
  -- re-encoding.
  envelope bytea NOT NULL,
  prev_hash bytea NOT NULL CHECK (octet_length(prev_hash) = 32),
  hash bytea NOT NULL CHECK (octet_length(hash) = 32),
  PRIMARY KEY (tenant_id, seq)
);

CREATE UNIQUE INDEX audit_event_event_id ON public.audit_event (tenant_id, event_id);

CREATE TABLE public.audit_checkpoint (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  seq bigint NOT NULL CHECK (seq >= 1),
  hash bytea NOT NULL CHECK (octet_length(hash) = 32),
  signed_at timestamptz NOT NULL,
  key_id text NOT NULL CHECK (key_id ~ '^[0-9a-f]{64}$'),
  prev_checkpoint_seq bigint NOT NULL CHECK (prev_checkpoint_seq >= 0 AND prev_checkpoint_seq < seq),
  prev_checkpoint_hash bytea NOT NULL CHECK (octet_length(prev_checkpoint_hash) = 32),
  signature bytea NOT NULL CHECK (octet_length(signature) = 64),
  PRIMARY KEY (tenant_id, seq)
);

-- The tenant's Ed25519 checkpoint keys (ADR-0005 rule 11). The private key is sealed under the tenant data
-- key (TM-D7); the window of a key is stated in the chain by its created and retired events, not here.
CREATE TABLE public.audit_checkpoint_key (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  key_id text NOT NULL CHECK (key_id ~ '^[0-9a-f]{64}$'),
  public_key bytea NOT NULL CHECK (octet_length(public_key) = 32),
  sealed_private_key bytea NOT NULL,
  key_version integer NOT NULL CHECK (key_version >= 1),
  -- 1, 2, 3...: the newest key signs. The key's window is in the chain (created and retired events).
  ordinal integer NOT NULL CHECK (ordinal >= 1),
  PRIMARY KEY (tenant_id, key_id),
  UNIQUE (tenant_id, ordinal)
);

ALTER TABLE public.audit_head ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_head FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_head_tenant ON public.audit_head
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

ALTER TABLE public.audit_event ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_event FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_event_tenant ON public.audit_event
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

ALTER TABLE public.audit_checkpoint ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_checkpoint FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_checkpoint_tenant ON public.audit_checkpoint
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

ALTER TABLE public.audit_checkpoint_key ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_checkpoint_key FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_checkpoint_key_tenant ON public.audit_checkpoint_key
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

-- I2. DELETE on audit_head is revoked too: a head cannot be recreated (a recreated head would restart the
-- chain). TRUNCATE is never in the default privileges.
REVOKE UPDATE, DELETE ON public.audit_event FROM activediq_app;
REVOKE UPDATE, DELETE ON public.audit_checkpoint FROM activediq_app;
REVOKE UPDATE, DELETE ON public.audit_checkpoint_key FROM activediq_app;
REVOKE DELETE ON public.audit_head FROM activediq_app;

COMMENT ON TABLE public.audit_head IS 'DM-80 chain head per tenant (tenant table, RLS). The only mutable audit table; its row lock serialises appenders. Only internal/platform/audit references it in SQL.';
COMMENT ON TABLE public.audit_event IS 'DM-80 AuditEvent (tenant table, RLS, append-only for the runtime role). Only internal/platform/audit references it in SQL.';
COMMENT ON TABLE public.audit_checkpoint IS 'DM-81 ChainCheckpoint (tenant table, RLS, append-only for the runtime role). Never purged.';
COMMENT ON TABLE public.audit_checkpoint_key IS 'DM-81 checkpoint signing keys (tenant table, RLS, append-only); the private key is sealed under the tenant data key.';

-- I3. Genesis-only insert. The first check repeats the row-security condition so that a row for another
-- tenant is refused for the reason row security gives, not as a malformed head.
-- Genesis-only insert. SECURITY INVOKER with a pinned search_path, as components_guard.
CREATE FUNCTION public.audit_head_guard_insert() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $fn$
BEGIN
  IF NEW.tenant_id IS DISTINCT FROM NULLIF(current_setting('app.tenant_id', true), '')::uuid THEN
    RAISE EXCEPTION 'new row violates row-level security policy for table "audit_head"' USING ERRCODE = '42501';
  END IF;
  IF NEW.seq <> 0 OR NEW.hash IS DISTINCT FROM
     sha256(convert_to('adq-audit-genesis/1', 'UTF8') || '\x00'::bytea || decode(replace(NEW.tenant_id::text, '-', ''), 'hex')) THEN
    RAISE EXCEPTION 'audit_head: a head is created at seq 0 with the tenant genesis hash' USING ERRCODE = 'AD403';
  END IF;
  NEW.at := now();
  RETURN NEW;
END
$fn$;

CREATE TRIGGER audit_head_guard_insert BEFORE INSERT ON public.audit_head
  FOR EACH ROW EXECUTE FUNCTION public.audit_head_guard_insert();

-- The head only moves forward, in seq and in time.
CREATE FUNCTION public.audit_head_guard_update() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $fn$
BEGIN
  IF NEW.tenant_id IS DISTINCT FROM NULLIF(current_setting('app.tenant_id', true), '')::uuid THEN
    RAISE EXCEPTION 'new row violates row-level security policy for table "audit_head"' USING ERRCODE = '42501';
  END IF;
  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.seq <= OLD.seq OR NEW.at < OLD.at THEN
    RAISE EXCEPTION 'audit_head: the head only moves forward' USING ERRCODE = 'AD403';
  END IF;
  RETURN NEW;
END
$fn$;

CREATE TRIGGER audit_head_guard_update BEFORE UPDATE ON public.audit_head
  FOR EACH ROW EXECUTE FUNCTION public.audit_head_guard_update();

-- I4. A checkpoint names a chained event. Under RLS the lookup sees only the tenant's own events.
CREATE FUNCTION public.audit_checkpoint_guard_insert() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $fn$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM public.audit_event e WHERE e.tenant_id = NEW.tenant_id AND e.seq = NEW.seq AND e.hash = NEW.hash) THEN
    RAISE EXCEPTION 'audit_checkpoint: no chained event with this seq and hash' USING ERRCODE = 'AD403';
  END IF;
  RETURN NEW;
END
$fn$;

-- AFTER, so that row security judges the row first.
CREATE TRIGGER audit_checkpoint_guard_insert AFTER INSERT ON public.audit_checkpoint
  FOR EACH ROW EXECUTE FUNCTION public.audit_checkpoint_guard_insert();

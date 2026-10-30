-- 0053_keys_tenant_keys: DM-02 TenantKey (T-0520; keys-custody-design §4, threat model TM-D7, TM-TB5-T2).
-- Owner: internal/platform/keys. One tenant table. It holds each tenant's data-encryption key (DEK) only
-- as the AEAD blob a key-provider adapter returned (wrapped_dek), with the KEK reference that wrapped it
-- (kek_provider, kek_key_id), pinned per version. No column holds a plaintext DEK (DM-02.I3).
--
--   state  active -> retired (decrypt-only) -> shredded. A retired row never becomes active again; a
--          shredded row never changes. wrapped_dek is empty exactly when the row is shredded.
--   DM-02.I1 (at most one active version per tenant) is the partial unique index below.
--
-- The runtime role (activediq_app) can SELECT and INSERT, and UPDATE only state, retired_at, shredded_at
-- and wrapped_dek (the last only to empty it on shred, which the trigger enforces). It has no DELETE, no
-- TRUNCATE, and no UPDATE on tenant_id, version, created_at, kek_provider or kek_key_id. Re-wrapping a DEK
-- under another KEK is an owner-role maintenance step (activediq_owner), never a runtime path.

CREATE TABLE public.tenant_keys (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  version integer NOT NULL CHECK (version > 0),
  state text NOT NULL CHECK (state IN ('active', 'retired', 'shredded')),
  wrapped_dek bytea NOT NULL,
  kek_provider text NOT NULL CHECK (char_length(kek_provider) BETWEEN 1 AND 64),
  kek_key_id text NOT NULL CHECK (char_length(kek_key_id) BETWEEN 1 AND 256),
  created_at timestamptz NOT NULL DEFAULT now(),
  retired_at timestamptz,
  shredded_at timestamptz,
  PRIMARY KEY (tenant_id, version),
  CHECK ((state = 'shredded') = (octet_length(wrapped_dek) = 0)),
  CHECK ((state = 'shredded') = (shredded_at IS NOT NULL)),
  CHECK (state <> 'active' OR retired_at IS NULL),
  CHECK (state <> 'retired' OR retired_at IS NOT NULL)
);

-- DM-02.I1: one active key per tenant.
CREATE UNIQUE INDEX tenant_keys_one_active ON public.tenant_keys (tenant_id) WHERE state = 'active';

ALTER TABLE public.tenant_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.tenant_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_keys_tenant ON public.tenant_keys
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

REVOKE UPDATE, DELETE, TRUNCATE ON public.tenant_keys FROM activediq_app;
GRANT UPDATE (state, retired_at, shredded_at, wrapped_dek) ON public.tenant_keys TO activediq_app;

COMMENT ON TABLE public.tenant_keys IS 'DM-02 TenantKey (tenant table, RLS): per-tenant DEK versions, wrapped by the installation KEK (TM-D7). wrapped_dek is sealed. Only internal/platform/keys references it in SQL.';

-- Transitions (keys-custody-design §4). Identity columns never change. active -> retired sets retired_at;
-- active|retired -> shredded empties wrapped_dek and sets shredded_at; retired -> active and anything out
-- of shredded are refused. A change of wrapped_dek, kek_provider or kek_key_id with the state unchanged
-- (KEK re-wrap, the plaintext DEK is the same) is allowed only to the owner role.
CREATE FUNCTION public.tenant_keys_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $fn$
BEGIN
  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.version IS DISTINCT FROM OLD.version
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'tenant_keys: identity is immutable' USING ERRCODE = 'AD403';
  END IF;

  IF NEW.state = OLD.state THEN
    IF NEW.retired_at IS DISTINCT FROM OLD.retired_at OR NEW.shredded_at IS DISTINCT FROM OLD.shredded_at THEN
      RAISE EXCEPTION 'tenant_keys: timestamps move only with a state change' USING ERRCODE = 'AD403';
    END IF;
    IF OLD.state = 'shredded' THEN
      IF NEW IS DISTINCT FROM OLD THEN
        RAISE EXCEPTION 'tenant_keys: a shredded key never changes' USING ERRCODE = 'AD403';
      END IF;
    ELSIF (NEW.wrapped_dek IS DISTINCT FROM OLD.wrapped_dek OR NEW.kek_provider IS DISTINCT FROM OLD.kek_provider
           OR NEW.kek_key_id IS DISTINCT FROM OLD.kek_key_id) AND current_user <> 'activediq_owner' THEN
      RAISE EXCEPTION 'tenant_keys: re-wrap is a maintenance operation' USING ERRCODE = 'AD403';
    END IF;
    RETURN NEW;
  END IF;

  IF OLD.state = 'active' AND NEW.state = 'retired' THEN
    IF NEW.wrapped_dek IS DISTINCT FROM OLD.wrapped_dek OR NEW.kek_provider IS DISTINCT FROM OLD.kek_provider
       OR NEW.kek_key_id IS DISTINCT FROM OLD.kek_key_id OR NEW.shredded_at IS DISTINCT FROM OLD.shredded_at THEN
      RAISE EXCEPTION 'tenant_keys: retiring changes only state and retired_at' USING ERRCODE = 'AD403';
    END IF;
    RETURN NEW;
  END IF;

  IF OLD.state IN ('active', 'retired') AND NEW.state = 'shredded' THEN
    IF NEW.kek_provider IS DISTINCT FROM OLD.kek_provider OR NEW.kek_key_id IS DISTINCT FROM OLD.kek_key_id
       OR NEW.retired_at IS DISTINCT FROM OLD.retired_at THEN
      RAISE EXCEPTION 'tenant_keys: shredding changes only state, wrapped_dek and shredded_at' USING ERRCODE = 'AD403';
    END IF;
    RETURN NEW;
  END IF;

  RAISE EXCEPTION 'tenant_keys: % -> % is not allowed', OLD.state, NEW.state USING ERRCODE = 'AD403';
END
$fn$;

CREATE TRIGGER tenant_keys_guard BEFORE UPDATE ON public.tenant_keys
  FOR EACH ROW EXECUTE FUNCTION public.tenant_keys_guard();
ALTER TABLE public.tenant_keys ENABLE ALWAYS TRIGGER tenant_keys_guard;

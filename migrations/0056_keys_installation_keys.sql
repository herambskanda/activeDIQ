-- 0056_keys_installation_keys: DM-02 installation-scope DEK (T-0715; ADR-0008, TM-D7, TM-TB5-T2).
-- Owner: internal/platform/keys. One registered-global table (no tenant_id, no RLS: ADR-0002 rule 4).
-- It holds the installation's data-encryption key only as the AEAD blob the key provider returned
-- (wrapped_dek), with the KEK reference that wrapped it, pinned per version. No column holds a plaintext
-- DEK. Its first consumer is the fleet SERVER CA key (fleet_server_ca); tenant data stays under tenant_keys.
--
--   state  active -> retired (decrypt-only). One active version at a time (partial unique index).
--
-- The runtime role (activediq_app) can SELECT and INSERT only: no UPDATE, DELETE or TRUNCATE. Rotation
-- and re-wrap are owner-role maintenance steps, never a runtime path.

CREATE TABLE public.installation_keys (
  version integer PRIMARY KEY CHECK (version > 0),
  state text NOT NULL CHECK (state IN ('active', 'retired')),
  wrapped_dek bytea NOT NULL CHECK (octet_length(wrapped_dek) > 0),
  kek_provider text NOT NULL CHECK (char_length(kek_provider) BETWEEN 1 AND 64),
  kek_key_id text NOT NULL CHECK (char_length(kek_key_id) BETWEEN 1 AND 256),
  created_at timestamptz NOT NULL DEFAULT now(),
  retired_at timestamptz,
  CHECK (state <> 'active' OR retired_at IS NULL),
  CHECK (state <> 'retired' OR retired_at IS NOT NULL)
);

-- One active installation key: a concurrent creation yields exactly one active row.
CREATE UNIQUE INDEX installation_keys_one_active ON public.installation_keys ((true)) WHERE state = 'active';

REVOKE UPDATE, DELETE, TRUNCATE ON public.installation_keys FROM activediq_app;

COMMENT ON TABLE public.installation_keys IS 'DM-02 installation-scope DEK (registered-global): wrapped by the installation KEK, seals installation-scope secrets such as the fleet server CA key. wrapped_dek is sealed. Only internal/platform/keys references it in SQL.';

-- 0057_authn_local_credentials: the password of a local console account and the AN-8 throttle state
-- (T-0783; threat model §7.6 rules 2-3). Owner: internal/platform/authn. Three tenant tables.
--
--   authn_local_credentials  one row per local account: the normalised username (trim, NFC, case-fold;
--                            the account lookup and the throttle key use the same function) and an
--                            argon2id hash in PHC string form. The password itself is never stored.
--   authn_signin_throttle    the AN-8 failure counter and not-before time per key. The key is
--                            HMAC-SHA256(pepper, tenant || normalised submitted name), created for every
--                            submitted name whether or not an account exists, so the table is not an
--                            account-existence oracle and holds no names. Rows older than the 15-minute
--                            window are dead and are replaced in place.
--   authn_signin_pepper      the per-tenant HMAC key for the throttle, sealed under the tenant data key.
-- The runtime role may not delete credentials (a removal is a state change of the account); throttle rows
-- are operational state and may be deleted.

-- write-class: authn_local_credentials config
CREATE TABLE public.authn_local_credentials (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  account_id uuid NOT NULL,
  username_norm text NOT NULL CHECK (char_length(username_norm) BETWEEN 1 AND 128),
  password_hash text NOT NULL CHECK (password_hash LIKE '$argon2id$%'),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, account_id),
  FOREIGN KEY (tenant_id, account_id) REFERENCES public.authn_accounts (tenant_id, id)
);
CREATE UNIQUE INDEX authn_local_credentials_username ON public.authn_local_credentials (tenant_id, username_norm);

-- write-class: authn_signin_throttle system
CREATE TABLE public.authn_signin_throttle (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  key_hash bytea NOT NULL CHECK (octet_length(key_hash) = 32),
  failures integer NOT NULL DEFAULT 0 CHECK (failures >= 0),
  window_start timestamptz NOT NULL,
  not_before timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, key_hash)
);
CREATE INDEX authn_signin_throttle_window ON public.authn_signin_throttle (tenant_id, window_start);

-- write-class: authn_signin_pepper system
CREATE TABLE public.authn_signin_pepper (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id) PRIMARY KEY,
  sealed_secret bytea NOT NULL,
  key_version integer NOT NULL CHECK (key_version > 0),
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE public.authn_local_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.authn_local_credentials FORCE ROW LEVEL SECURITY;
CREATE POLICY authn_local_credentials_tenant ON public.authn_local_credentials
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.authn_signin_throttle ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.authn_signin_throttle FORCE ROW LEVEL SECURITY;
CREATE POLICY authn_signin_throttle_tenant ON public.authn_signin_throttle
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE public.authn_signin_pepper ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.authn_signin_pepper FORCE ROW LEVEL SECURITY;
CREATE POLICY authn_signin_pepper_tenant ON public.authn_signin_pepper
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

REVOKE DELETE ON public.authn_local_credentials FROM activediq_app;
REVOKE DELETE ON public.authn_signin_pepper FROM activediq_app;
REVOKE UPDATE ON public.authn_signin_pepper FROM activediq_app;

COMMENT ON TABLE public.authn_local_credentials IS 'Local console account credentials (tenant table, RLS): normalised username and an argon2id hash. Only internal/platform/authn references it in SQL.';
COMMENT ON TABLE public.authn_signin_throttle IS 'AN-8 throttle state (tenant table, RLS) keyed by an HMAC of the normalised submitted name; holds no names. Only internal/platform/authn references it in SQL.';
COMMENT ON TABLE public.authn_signin_pepper IS 'Per-tenant HMAC key of the AN-8 throttle, sealed under the tenant data key (tenant table, RLS). Only internal/platform/authn references it in SQL.';

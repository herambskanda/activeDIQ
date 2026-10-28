-- 0046_authn_sso_transactions: the server-side SSO Transaction (T-0203; DM-39.I4, console-sso.md section 3, SSO-1).
-- Owner: internal/platform/authn (sso/signin). One tenant table, shared by every node through PostgreSQL.
--
-- Start writes one row and sets the browser-binding cookie; the first callback consumes it by DELETE ... RETURNING
-- before anything in the response is looked at, so a second callback with the same cookie finds nothing whatever
-- the first outcome was. Only a SHA-256 of the handle is stored: a read of this table yields nothing that can be
-- replayed as a cookie.
--
--   handle_hash  SHA-256 of the cookie handle, 32 bytes. Unique per tenant.
--   idp_id       the IdentityProvider the redirect went to; the callback path must name the same one.
--   intent       signin (stepup is a later ticket).
--   state, nonce, verifier, request_id   the OIDC state, nonce and PKCE verifier, or the SAML AuthnRequest ID,
--                as the verifier produced them. Short-lived; not evidence (the audit events are).
--   return_path  the console route chosen at Start; never taken from the callback.
--   expires_at   at most 5 minutes after created_at (CHECK); the server also refuses after it.
-- Rows are never updated. The runtime role may delete them (that is the consumption and the trim of expired rows).

CREATE TABLE public.authn_sso_transactions (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  handle_hash bytea NOT NULL CHECK (octet_length(handle_hash) = 32),
  idp_id text NOT NULL CHECK (char_length(idp_id) BETWEEN 1 AND 256),
  intent text NOT NULL CHECK (intent IN ('signin')),
  state text NOT NULL DEFAULT '' CHECK (char_length(state) <= 512),
  nonce text NOT NULL DEFAULT '' CHECK (char_length(nonce) <= 512),
  verifier text NOT NULL DEFAULT '' CHECK (char_length(verifier) <= 512),
  request_id text NOT NULL DEFAULT '' CHECK (char_length(request_id) <= 512),
  return_path text NOT NULL CHECK (char_length(return_path) BETWEEN 1 AND 512),
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT authn_sso_transactions_life CHECK (expires_at > created_at AND expires_at <= created_at + interval '5 minutes')
);

CREATE UNIQUE INDEX authn_sso_transactions_hash ON public.authn_sso_transactions (tenant_id, handle_hash);
CREATE INDEX authn_sso_transactions_expiry ON public.authn_sso_transactions (tenant_id, expires_at);

ALTER TABLE public.authn_sso_transactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.authn_sso_transactions FORCE ROW LEVEL SECURITY;
CREATE POLICY authn_sso_transactions_tenant ON public.authn_sso_transactions AS PERMISSIVE FOR ALL
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

REVOKE UPDATE, TRUNCATE ON public.authn_sso_transactions FROM activediq_app;

COMMENT ON TABLE public.authn_sso_transactions IS 'SSO Transactions (tenant table, RLS): one row per started sign-in, consumed by the first callback. Only a hash of the handle is stored. Insert and delete only. Only internal/platform/authn/sso/signin references it in SQL.';

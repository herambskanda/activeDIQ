-- 0044_authn_saml_replay: the SAML replay cache (T-0489; DM-39.I5, SAML-16). Owner: internal/platform/authn
-- (sso/saml). One tenant table, shared by every node through PostgreSQL (ADR-0002 rule 6).
--
-- One row per accepted assertion: (tenant, IdP, Assertion ID). The primary key is the replay check: a second
-- insert of the same triple conflicts, and the caller refuses it as saml.replay. The row lives until the
-- assertion's NotOnOrAfter plus skew (expires_at) and is then purged; it is not evidence (the audit events are).
--
--   idp_id        the IdentityProvider (DM-39) the assertion came from; text, as the verifier holds it.
--   assertion_id  the Assertion's ID attribute, as signed; 1..1024 characters.
--   created_at    when it was remembered.
--   expires_at    after created_at, at most 24 hours later (CHECK), so a hostile IdP cannot pin rows for ever.
-- Rows are never updated. The runtime role may delete only rows that have expired (a DELETE policy), which
-- is how the cache trims itself; an unexpired row cannot be removed, so a replay window cannot be reopened.

CREATE TABLE public.authn_saml_replay (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  idp_id text NOT NULL CHECK (char_length(idp_id) BETWEEN 1 AND 256),
  assertion_id text NOT NULL CHECK (char_length(assertion_id) BETWEEN 1 AND 1024),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, idp_id, assertion_id),
  CONSTRAINT authn_saml_replay_life CHECK (expires_at > created_at AND expires_at <= created_at + interval '24 hours')
);

CREATE INDEX authn_saml_replay_expiry ON public.authn_saml_replay (tenant_id, expires_at);

ALTER TABLE public.authn_saml_replay ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.authn_saml_replay FORCE ROW LEVEL SECURITY;
CREATE POLICY authn_saml_replay_select ON public.authn_saml_replay FOR SELECT
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
CREATE POLICY authn_saml_replay_insert ON public.authn_saml_replay FOR INSERT
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
CREATE POLICY authn_saml_replay_delete_expired ON public.authn_saml_replay FOR DELETE
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND expires_at <= clock_timestamp());

REVOKE UPDATE, TRUNCATE ON public.authn_saml_replay FROM activediq_app;

COMMENT ON TABLE public.authn_saml_replay IS 'SAML replay cache (tenant table, RLS): one row per accepted assertion until NotOnOrAfter plus skew. Insert-only; the runtime role deletes only expired rows. Only internal/platform/authn/sso/saml references it in SQL.';

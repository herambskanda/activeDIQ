-- 0047_authn_webauthn: WebAuthn credentials and sign-in challenges for AN-10 (T-0207; DM-37 webauthn slice,
-- threat model §7.2 and §7.6 rule 1). Owner: internal/platform/authn. Two tenant tables.
--
--   authn_webauthn_credentials  one row per registered authenticator of a console account. Public data only:
--                               the credential ID and the COSE public key (TM-F-SEAL: WebAuthn stores public
--                               keys, nothing to seal). sign_count is the authenticator's signature counter;
--                               it only ever increases (trigger), the clone check of WebAuthn §6.1.1 for
--                               authenticators that count. backup_eligible is the BE flag fixed at
--                               registration (the library checks it on every assertion). Registration is a
--                               later ticket; this table is read by AN-10.
--   authn_webauthn_challenges   at most one live challenge per pending sign-in (primary key). It is issued by
--                               createWebAuthnSignInChallenge and CONSUMED by the first assertion that names
--                               the pending sign-in, in its own committed transaction before the assertion
--                               is evaluated, so a captured assertion can be submitted once and never again.
--                               The challenge is public to the client by design; it carries no secret.

-- write-class: authn_webauthn_credentials system
CREATE TABLE public.authn_webauthn_credentials (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  account_id uuid NOT NULL,
  credential_id bytea NOT NULL CHECK (octet_length(credential_id) BETWEEN 16 AND 1023),
  public_key bytea NOT NULL CHECK (octet_length(public_key) BETWEEN 16 AND 2048),
  user_handle bytea NOT NULL CHECK (octet_length(user_handle) BETWEEN 16 AND 64),
  backup_eligible boolean NOT NULL,
  aaguid bytea CHECK (aaguid IS NULL OR octet_length(aaguid) = 16),
  sign_count bigint NOT NULL DEFAULT 0 CHECK (sign_count >= 0 AND sign_count <= 4294967295),
  label text NOT NULL CHECK (char_length(label) BETWEEN 1 AND 128),
  state text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'revoked')),
  created_at timestamptz NOT NULL DEFAULT now(),
  last_used timestamptz,
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, account_id) REFERENCES public.authn_accounts (tenant_id, id),
  UNIQUE (tenant_id, credential_id)
);

CREATE INDEX authn_webauthn_credentials_account ON public.authn_webauthn_credentials (tenant_id, account_id) WHERE state = 'active';

ALTER TABLE public.authn_webauthn_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.authn_webauthn_credentials FORCE ROW LEVEL SECURITY;
CREATE POLICY authn_webauthn_credentials_tenant ON public.authn_webauthn_credentials
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
REVOKE DELETE, TRUNCATE ON public.authn_webauthn_credentials FROM activediq_app;

COMMENT ON TABLE public.authn_webauthn_credentials IS 'DM-37 webauthn credentials (tenant table, RLS). Public keys only. Only internal/platform/authn references it in SQL.';

-- Identity, key and owner never change; the state only goes active -> revoked; the counter never decreases.
CREATE FUNCTION public.authn_webauthn_credentials_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $fn$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id OR NEW.account_id IS DISTINCT FROM OLD.account_id
     OR NEW.credential_id IS DISTINCT FROM OLD.credential_id OR NEW.public_key IS DISTINCT FROM OLD.public_key
     OR NEW.user_handle IS DISTINCT FROM OLD.user_handle OR NEW.backup_eligible IS DISTINCT FROM OLD.backup_eligible OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'authn_webauthn_credentials: identity, key and owner are immutable' USING ERRCODE = 'AD403';
  END IF;
  IF NEW.state IS DISTINCT FROM OLD.state AND NOT (OLD.state = 'active' AND NEW.state = 'revoked') THEN
    RAISE EXCEPTION 'authn_webauthn_credentials: % -> % is not allowed', OLD.state, NEW.state USING ERRCODE = 'AD403';
  END IF;
  IF NEW.sign_count < OLD.sign_count THEN
    RAISE EXCEPTION 'authn_webauthn_credentials: sign_count never decreases' USING ERRCODE = 'AD403';
  END IF;
  RETURN NEW;
END
$fn$;

CREATE TRIGGER authn_webauthn_credentials_guard BEFORE UPDATE ON public.authn_webauthn_credentials
  FOR EACH ROW EXECUTE FUNCTION public.authn_webauthn_credentials_guard();
ALTER TABLE public.authn_webauthn_credentials ENABLE ALWAYS TRIGGER authn_webauthn_credentials_guard;

-- write-class: authn_webauthn_challenges system
CREATE TABLE public.authn_webauthn_challenges (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  pending_id uuid NOT NULL,
  challenge bytea NOT NULL CHECK (octet_length(challenge) BETWEEN 32 AND 64),
  allowed_credential_ids bytea[] NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  PRIMARY KEY (tenant_id, pending_id),
  FOREIGN KEY (tenant_id, pending_id) REFERENCES public.authn_pending_signins (tenant_id, id) ON DELETE CASCADE,
  CONSTRAINT authn_webauthn_challenges_life CHECK (expires_at > created_at AND expires_at <= created_at + interval '5 minutes')
);

ALTER TABLE public.authn_webauthn_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.authn_webauthn_challenges FORCE ROW LEVEL SECURITY;
CREATE POLICY authn_webauthn_challenges_tenant ON public.authn_webauthn_challenges
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
REVOKE DELETE, TRUNCATE ON public.authn_webauthn_challenges FROM activediq_app;

COMMENT ON TABLE public.authn_webauthn_challenges IS 'AN-10 WebAuthn challenge, one per pending sign-in, consumed by the first assertion (tenant table, RLS). Only internal/platform/authn references it in SQL.';

-- A consumed challenge never comes back: once consumed_at is set, the row can change only by being replaced
-- with a new challenge (a new createWebAuthnSignInChallenge), never by clearing consumed_at in place.
CREATE FUNCTION public.authn_webauthn_challenges_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $fn$
BEGIN
  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.pending_id IS DISTINCT FROM OLD.pending_id THEN
    RAISE EXCEPTION 'authn_webauthn_challenges: identity is immutable' USING ERRCODE = 'AD403';
  END IF;
  IF OLD.consumed_at IS NOT NULL AND NEW.challenge IS NOT DISTINCT FROM OLD.challenge AND NEW.consumed_at IS NULL THEN
    RAISE EXCEPTION 'authn_webauthn_challenges: a consumed challenge cannot be revived' USING ERRCODE = 'AD403';
  END IF;
  RETURN NEW;
END
$fn$;

CREATE TRIGGER authn_webauthn_challenges_guard BEFORE UPDATE ON public.authn_webauthn_challenges
  FOR EACH ROW EXECUTE FUNCTION public.authn_webauthn_challenges_guard();
ALTER TABLE public.authn_webauthn_challenges ENABLE ALWAYS TRIGGER authn_webauthn_challenges_guard;

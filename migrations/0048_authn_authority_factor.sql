-- 0048_authn_authority_factor: the activeDIQ-held authority factor of an sso account (T-0283; threat model
-- §6.9 TM-D19 rules 1-2, DM-37 webauthn slice, DM-30.I6). Owner: internal/platform/authn.
--
-- An sso account uses AD-side grants that reach it through a correlation only in a session that verified a
-- WebAuthn credential held HERE, enrolled outside Entra (an AD-plane proof, or a tenant-owner's approval).
--
--   authn_webauthn_credentials.purpose  'second_factor' (AN-10, the sign-in factor of a local/directory
--                               account) or 'authority' (this ticket). AN-10 reads only second_factor, so an
--                               authority credential never signs anyone in. At most one ACTIVE authority
--                               credential per account; purpose never changes.
--   authn_authority_challenges  one live registration challenge per account and one live assertion challenge
--                               per session (subject_id). Consumed by the first use, in its own committed
--                               transaction, before the response is looked at (as AN-10).
--   authn_authority_approvals   a tenant-owner's approval of ONE enrolment for ONE account. Short-lived,
--                               single-use. The approver is never the account it approves for.
--   authn_authority_notices     a transactional outbox: one row per recipient (the account and every
--                               tenant-owner) of every enrolment, reset and removal. Delivery (mail, in-app)
--                               reads it; the row is written in the same transaction as the change.

ALTER TABLE public.authn_webauthn_credentials
  ADD COLUMN purpose text NOT NULL DEFAULT 'second_factor' CHECK (purpose IN ('second_factor', 'authority'));

CREATE UNIQUE INDEX authn_webauthn_credentials_one_authority ON public.authn_webauthn_credentials (tenant_id, account_id)
  WHERE purpose = 'authority' AND state = 'active';

CREATE OR REPLACE FUNCTION public.authn_webauthn_credentials_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $fn$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id OR NEW.account_id IS DISTINCT FROM OLD.account_id
     OR NEW.credential_id IS DISTINCT FROM OLD.credential_id OR NEW.public_key IS DISTINCT FROM OLD.public_key
     OR NEW.user_handle IS DISTINCT FROM OLD.user_handle OR NEW.backup_eligible IS DISTINCT FROM OLD.backup_eligible
     OR NEW.created_at IS DISTINCT FROM OLD.created_at OR NEW.purpose IS DISTINCT FROM OLD.purpose THEN
    RAISE EXCEPTION 'authn_webauthn_credentials: identity, key, owner and purpose are immutable' USING ERRCODE = 'AD403';
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

CREATE TABLE public.authn_authority_challenges (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  kind text NOT NULL CHECK (kind IN ('register', 'assert')),
  subject_id uuid NOT NULL,            -- register: the account; assert: the session
  account_id uuid NOT NULL,
  challenge bytea NOT NULL CHECK (octet_length(challenge) BETWEEN 32 AND 64),
  user_handle bytea NOT NULL CHECK (octet_length(user_handle) BETWEEN 16 AND 64),
  proof text CHECK (proof IN ('ad_proof', 'owner_approval')),  -- register only
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  PRIMARY KEY (tenant_id, kind, subject_id),
  FOREIGN KEY (tenant_id, account_id) REFERENCES public.authn_accounts (tenant_id, id),
  CONSTRAINT authn_authority_challenges_life CHECK (expires_at > created_at AND expires_at <= created_at + interval '5 minutes'),
  CONSTRAINT authn_authority_challenges_proof CHECK ((kind = 'register') = (proof IS NOT NULL))
);

CREATE TABLE public.authn_authority_approvals (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  account_id uuid NOT NULL,
  approver_id uuid NOT NULL,
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, account_id) REFERENCES public.authn_accounts (tenant_id, id),
  FOREIGN KEY (tenant_id, approver_id) REFERENCES public.authn_accounts (tenant_id, id),
  CONSTRAINT authn_authority_approvals_life CHECK (expires_at > created_at AND expires_at <= created_at + interval '1 hour'),
  CONSTRAINT authn_authority_approvals_not_self CHECK (approver_id <> account_id)
);

CREATE TABLE public.authn_authority_notices (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  recipient_id uuid NOT NULL,
  subject_id uuid NOT NULL,            -- the account whose factor changed
  event text NOT NULL CHECK (event IN ('enrolled', 'reset', 'removed')),
  actor_id uuid NOT NULL,
  created_at timestamptz NOT NULL,
  delivered_at timestamptz,
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, recipient_id) REFERENCES public.authn_accounts (tenant_id, id),
  FOREIGN KEY (tenant_id, subject_id) REFERENCES public.authn_accounts (tenant_id, id)
);
CREATE INDEX authn_authority_notices_pending ON public.authn_authority_notices (tenant_id, created_at) WHERE delivered_at IS NULL;

DO $rls$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['authn_authority_challenges', 'authn_authority_approvals', 'authn_authority_notices'] LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format($p$CREATE POLICY %I ON public.%I USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
      WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)$p$, t || '_tenant', t);
    EXECUTE format('REVOKE DELETE, TRUNCATE ON public.%I FROM activediq_app', t);
  END LOOP;
END
$rls$;

COMMENT ON TABLE public.authn_authority_challenges IS 'TM-D19 authority-factor registration and assertion challenges, consumed once (tenant table, RLS). Only internal/platform/authn references it in SQL.';
COMMENT ON TABLE public.authn_authority_approvals IS 'TM-D19 rule 2 tenant-owner approval of one authority-factor enrolment (tenant table, RLS). Only internal/platform/authn references it in SQL.';
COMMENT ON TABLE public.authn_authority_notices IS 'TM-D19 rule 2 notices of enrolment, reset and removal: account and every tenant-owner (tenant table, RLS, outbox). Only internal/platform/authn references it in SQL.';

-- Challenges are replaced in place by a new one, never revived; an approval only gets consumed, once.
CREATE FUNCTION public.authn_authority_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $fn$
BEGIN
  IF TG_TABLE_NAME = 'authn_authority_approvals' THEN
    IF NEW.id IS DISTINCT FROM OLD.id OR NEW.account_id IS DISTINCT FROM OLD.account_id OR NEW.approver_id IS DISTINCT FROM OLD.approver_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at OR NEW.expires_at IS DISTINCT FROM OLD.expires_at OR OLD.consumed_at IS NOT NULL THEN
      RAISE EXCEPTION 'authn_authority_approvals: an approval is consumed once and never changes' USING ERRCODE = 'AD403';
    END IF;
  ELSIF TG_TABLE_NAME = 'authn_authority_notices' THEN
    IF NEW.id IS DISTINCT FROM OLD.id OR NEW.recipient_id IS DISTINCT FROM OLD.recipient_id OR NEW.subject_id IS DISTINCT FROM OLD.subject_id
       OR NEW.event IS DISTINCT FROM OLD.event OR NEW.actor_id IS DISTINCT FROM OLD.actor_id OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
      RAISE EXCEPTION 'authn_authority_notices: only delivered_at moves' USING ERRCODE = 'AD403';
    END IF;
  ELSE
    IF NEW.kind IS DISTINCT FROM OLD.kind OR NEW.subject_id IS DISTINCT FROM OLD.subject_id THEN
      RAISE EXCEPTION 'authn_authority_challenges: identity is immutable' USING ERRCODE = 'AD403';
    END IF;
    IF OLD.consumed_at IS NOT NULL AND NEW.challenge IS NOT DISTINCT FROM OLD.challenge AND NEW.consumed_at IS NULL THEN
      RAISE EXCEPTION 'authn_authority_challenges: a consumed challenge cannot be revived' USING ERRCODE = 'AD403';
    END IF;
  END IF;
  RETURN NEW;
END
$fn$;

DO $trg$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['authn_authority_challenges', 'authn_authority_approvals', 'authn_authority_notices'] LOOP
    EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE ON public.%I FOR EACH ROW EXECUTE FUNCTION public.authn_authority_guard()', t || '_guard', t);
    EXECUTE format('ALTER TABLE public.%I ENABLE ALWAYS TRIGGER %I', t, t || '_guard');
  END LOOP;
END
$trg$;

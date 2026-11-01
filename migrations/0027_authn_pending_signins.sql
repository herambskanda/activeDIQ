-- 0027_authn_pending_signins: pending sign-ins, the state between a first factor and AN-10 (T-0198;
-- threat model §7.6 rule 1, DM-31). Owner: internal/platform/authn. One tenant table.
--
-- A first factor (AN-3 when the IdP does not assert MFA, AN-8, AN-9) yields a row here, never a session.
-- It authorises nothing except AN-10. Only a SHA-256 of the handle is stored: a read of this table yields
-- nothing that can be replayed as a cookie.
--
--   handle_hash   SHA-256 of the handle, 32 bytes. Unique per tenant.
--   account_id    the one account it is bound to.
--   first_factor  the factor that created it (password, sso, kerberos).
--   expires_at    at most 5 minutes after created_at (CHECK); the server also refuses after it.
--   attempts      second-factor submissions charged so far; at most 5 (CHECK). Charged before the code is looked at.
--   state         active -> consumed (AN-10 succeeded) | dead (expired or out of attempts). Final states are final.
-- Rows are kept after they end; the runtime role cannot delete them.

-- write-class: authn_pending_signins system
CREATE TABLE public.authn_pending_signins (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  handle_hash bytea NOT NULL CHECK (octet_length(handle_hash) = 32),
  account_id uuid NOT NULL,
  first_factor text NOT NULL CHECK (first_factor IN ('password', 'sso', 'kerberos')),
  client_ip inet,
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 5),
  state text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'consumed', 'dead')),
  ended_at timestamptz,
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT authn_pending_life CHECK (expires_at > created_at AND expires_at <= created_at + interval '5 minutes'),
  CONSTRAINT authn_pending_ended CHECK ((state = 'active') = (ended_at IS NULL))
);

CREATE UNIQUE INDEX authn_pending_signins_hash ON public.authn_pending_signins (tenant_id, handle_hash);

ALTER TABLE public.authn_pending_signins ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.authn_pending_signins FORCE ROW LEVEL SECURITY;
CREATE POLICY authn_pending_signins_tenant ON public.authn_pending_signins
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

REVOKE DELETE ON public.authn_pending_signins FROM activediq_app;

COMMENT ON TABLE public.authn_pending_signins IS 'Pending sign-ins (tenant table, RLS): first factor passed, second factor outstanding. Only a hash of the handle is stored. Only internal/platform/authn references it in SQL.';

-- Identity, binding and lifetime never change; attempts only go up, by one; a consumed or dead row is final.
CREATE FUNCTION public.authn_pending_signins_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $fn$
BEGIN
  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.id IS DISTINCT FROM OLD.id
     OR NEW.handle_hash IS DISTINCT FROM OLD.handle_hash OR NEW.account_id IS DISTINCT FROM OLD.account_id
     OR NEW.first_factor IS DISTINCT FROM OLD.first_factor OR NEW.client_ip IS DISTINCT FROM OLD.client_ip
     OR NEW.created_at IS DISTINCT FROM OLD.created_at OR NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
    RAISE EXCEPTION 'authn_pending_signins: identity, binding and expiry are never rewritten' USING ERRCODE = 'AD403';
  END IF;
  IF OLD.state <> 'active' THEN
    RAISE EXCEPTION 'authn_pending_signins: a % pending sign-in is final', OLD.state USING ERRCODE = 'AD403';
  END IF;
  IF NEW.attempts < OLD.attempts OR NEW.attempts > OLD.attempts + 1 THEN
    RAISE EXCEPTION 'authn_pending_signins: attempts only rise, by one' USING ERRCODE = 'AD403';
  END IF;
  RETURN NEW;
END
$fn$;

CREATE TRIGGER authn_pending_signins_guard BEFORE UPDATE ON public.authn_pending_signins
  FOR EACH ROW EXECUTE FUNCTION public.authn_pending_signins_guard();
ALTER TABLE public.authn_pending_signins ENABLE ALWAYS TRIGGER authn_pending_signins_guard;

-- A minted row must look like one the package wrote: active, no attempts used, created now, living at most 5 minutes.
CREATE FUNCTION public.authn_pending_signins_insert_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $fn$
DECLARE
  now_ts timestamptz := pg_catalog.clock_timestamp();
BEGIN
  IF NEW.state <> 'active' OR NEW.attempts <> 0 OR NEW.ended_at IS NOT NULL THEN
    RAISE EXCEPTION 'authn_pending_signins: a pending sign-in starts active with no attempts' USING ERRCODE = 'AD403';
  END IF;
  IF NEW.created_at < now_ts - interval '5 minutes' OR NEW.created_at > now_ts + interval '5 minutes'
     OR NEW.expires_at <= now_ts THEN
    RAISE EXCEPTION 'authn_pending_signins: created_at must be current and the row not already expired' USING ERRCODE = 'AD403';
  END IF;
  RETURN NEW;
END
$fn$;

CREATE TRIGGER authn_pending_signins_insert_guard BEFORE INSERT ON public.authn_pending_signins
  FOR EACH ROW EXECUTE FUNCTION public.authn_pending_signins_insert_guard();
ALTER TABLE public.authn_pending_signins ENABLE ALWAYS TRIGGER authn_pending_signins_insert_guard;

-- 0075_authn_ad_attempts: the shared per-account AD-password attempt counter (T-0197; threat model
-- TM-TB1-T9, §7.2). Owner: internal/platform/authn.
--
-- Before an AD password goes to a domain controller (the AN-5 enrolment page, AD-identity sign-in), the
-- counter takes one attempt for the account. When the attempts in the window reach the domain lockout
-- threshold minus one, further attempts are refused without reaching the directory, so our traffic never
-- locks a user out. The row is shared by every server node. The window is judged by the database clock
-- (clock_timestamp() after the row lock), never a node's clock.
--
--   key_hash      HMAC-SHA256(server key, tenant || domain || account), computed by the caller; the table
--                 holds no names, so it is not an account-existence oracle.
--   attempts      attempts taken in the current window, capped at the threshold.
--   window_start  when the current window opened. A row past its window is dead and is replaced in place.

-- write-class: authn_ad_attempts system
CREATE TABLE public.authn_ad_attempts (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  key_hash bytea NOT NULL CHECK (octet_length(key_hash) = 32),
  attempts integer NOT NULL CHECK (attempts >= 0),
  window_start timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, key_hash)
);
CREATE INDEX authn_ad_attempts_window ON public.authn_ad_attempts (tenant_id, window_start);

ALTER TABLE public.authn_ad_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.authn_ad_attempts FORCE ROW LEVEL SECURITY;
CREATE POLICY authn_ad_attempts_tenant ON public.authn_ad_attempts
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

COMMENT ON TABLE public.authn_ad_attempts IS 'Per-account AD-password attempt counter (tenant table, RLS) keyed by an HMAC; holds no names. Stops below the domain lockout threshold (TM-TB1-T9). Only internal/platform/authn references it in SQL.';

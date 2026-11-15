-- 0080_authn_selfservice_enrolment: the end-user TOTP enrolment page, AN-5 (T-0205; ENH-09 spec T-0192 §6,
-- threat model TM-TB1-T13). Owner: internal/platform/authn.
--
-- 1. authn_authenticator_enrollments gains the notice and cooling-off state of §5 and §6.5:
--      replaces            the enrolment this one replaced (re-enrolment §6.3a); set once.
--      notice_state        pending (activated, notice not yet delivered), sent, failed (retrying),
--                          abandoned (all retries over 24 h). NULL for console factors and for rows not yet
--                          active. Only a directory-user enrolment has one.
--      notice_attempts / notice_next_at / notice_started_at   the 15-minute retry for up to 24 hours.
--      cooling_off_until   set only when the notice was accepted by the transport: accepted time + 24 h.
--    A factor is usable for caller verification only when notice_state = 'sent' and cooling_off_until has
--    passed (DM-37 I7, I9); the CHECK below makes "cooling-off without a delivered notice" unrepresentable.
-- 2. authn_enrolment_sessions: the pending enrolment of §6.1 behind the __Host- cookie: a hashed 256-bit
--    handle bound to one directory user, 10 minutes, 5 code confirmations, consumed once.

ALTER TABLE public.authn_authenticator_enrollments
  ADD COLUMN replaces uuid,
  ADD COLUMN notice_state text CHECK (notice_state IN ('pending', 'sent', 'failed', 'abandoned')),
  ADD COLUMN notice_attempts integer NOT NULL DEFAULT 0 CHECK (notice_attempts >= 0),
  ADD COLUMN notice_started_at timestamptz,
  ADD COLUMN notice_next_at timestamptz,
  ADD COLUMN cooling_off_until timestamptz;

ALTER TABLE public.authn_authenticator_enrollments ADD CONSTRAINT authn_enrollments_notice_shape CHECK (
  (notice_state IS NULL OR (connection_id IS NOT NULL AND object_guid IS NOT NULL))
  AND (cooling_off_until IS NULL) = (notice_state IS NULL OR notice_state NOT IN ('sent'))
  AND (notice_state IS NULL OR notice_started_at IS NOT NULL));

CREATE INDEX authn_enrollments_notice_due ON public.authn_authenticator_enrollments (tenant_id, notice_next_at)
  WHERE notice_state IN ('pending', 'failed');

-- The new columns move only forward: replaces is set once, notice_state follows pending -> sent | failed,
-- failed -> sent | failed | abandoned, abandoned -> sent (a delivered resend), and sent is final; a
-- delivered notice's cooling-off time is never moved; notice_attempts never decreases.
CREATE FUNCTION public.authn_enrollments_notice_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $fn$
BEGIN
  IF OLD.replaces IS NOT NULL AND NEW.replaces IS DISTINCT FROM OLD.replaces THEN
    RAISE EXCEPTION 'authn_authenticator_enrollments: replaces is set once' USING ERRCODE = 'AD403';
  END IF;
  IF NEW.notice_state IS DISTINCT FROM OLD.notice_state THEN
    IF OLD.notice_state IS NULL THEN
      IF NEW.notice_state <> 'pending' OR NEW.state <> 'active' THEN
        RAISE EXCEPTION 'authn_authenticator_enrollments: a notice starts pending, on an active enrolment' USING ERRCODE = 'AD403';
      END IF;
    ELSIF NOT ((OLD.notice_state = 'pending' AND NEW.notice_state IN ('sent', 'failed'))
            OR (OLD.notice_state = 'failed' AND NEW.notice_state IN ('sent', 'abandoned'))
            OR (OLD.notice_state = 'abandoned' AND NEW.notice_state = 'sent')) THEN
      RAISE EXCEPTION 'authn_authenticator_enrollments: notice % -> % is not allowed', OLD.notice_state, NEW.notice_state USING ERRCODE = 'AD403';
    END IF;
  END IF;
  IF OLD.cooling_off_until IS NOT NULL AND NEW.cooling_off_until IS DISTINCT FROM OLD.cooling_off_until THEN
    RAISE EXCEPTION 'authn_authenticator_enrollments: cooling-off is never moved' USING ERRCODE = 'AD403';
  END IF;
  IF NEW.notice_attempts < OLD.notice_attempts THEN
    RAISE EXCEPTION 'authn_authenticator_enrollments: notice_attempts never decreases' USING ERRCODE = 'AD403';
  END IF;
  RETURN NEW;
END
$fn$;

CREATE TRIGGER authn_enrollments_notice_guard BEFORE UPDATE ON public.authn_authenticator_enrollments
  FOR EACH ROW EXECUTE FUNCTION public.authn_enrollments_notice_guard();
ALTER TABLE public.authn_authenticator_enrollments ENABLE ALWAYS TRIGGER authn_enrollments_notice_guard;

-- write-class: authn_enrolment_sessions system
CREATE TABLE public.authn_enrolment_sessions (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  handle_hash bytea NOT NULL CHECK (octet_length(handle_hash) = 32),
  connection_id uuid NOT NULL,
  object_guid uuid NOT NULL,
  proof text NOT NULL CHECK (proof IN ('password', 'kerberos')),
  client_ip inet,
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  confirmations integer NOT NULL DEFAULT 0 CHECK (confirmations BETWEEN 0 AND 5),
  existing_proved boolean NOT NULL DEFAULT false,
  enrollment_id uuid,
  consumed_at timestamptz,
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, handle_hash),
  CHECK (expires_at > created_at AND expires_at <= created_at + interval '10 minutes')
);
CREATE INDEX authn_enrolment_sessions_expiry ON public.authn_enrolment_sessions (tenant_id, expires_at);

ALTER TABLE public.authn_enrolment_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.authn_enrolment_sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY authn_enrolment_sessions_tenant ON public.authn_enrolment_sessions
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

COMMENT ON TABLE public.authn_enrolment_sessions IS 'AN-5 pending enrolments (tenant table, RLS): hashed handle, one directory user, 10 minutes, 5 confirmations. Only internal/platform/authn references it in SQL.';

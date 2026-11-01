-- 0062_notify_smtp_and_deliveries: tenant notify settings (SMTP relay, allowed recipient domains) and the
-- DM-84 Delivery (T-0950; modules/reports.md §7.2, §8; TM-D30 SX-7). Owner: internal/platform/notify.
--
--   notify_settings    one row per tenant. The SMTP relay (DM-82 channel kind smtp) and the allowed recipient
--                      domains. No row means no relay and an empty list, so every address is external.
--                      Written only by the notify.settings.update Action. Domains are stored in canonical
--                      form (IDNA ToASCII, lower case) by the writer; a CHECK cannot run IDNA, so the shape of an
--                      entry is the writer's to enforce (internal/platform/notify/settings).
--   notify_deliveries  one row per message per recipient: metadata and variable references, never a rendered
--                      body (DM-84.I1). The (source_kind, source_id, recipient_account) columns are the
--                      authority for a delivery-link download (reports §7.2), so they never change after
--                      insert (trigger below). Rows are not deleted by the runtime role.

-- write-class: notify_settings config
CREATE TABLE public.notify_settings (
  tenant_id uuid PRIMARY KEY REFERENCES public.tenants (id),
  allowed_domains text[] NOT NULL DEFAULT '{}',
  smtp_host text CHECK (smtp_host IS NULL OR char_length(smtp_host) BETWEEN 1 AND 253),
  smtp_port integer CHECK (smtp_port IS NULL OR smtp_port BETWEEN 1 AND 65535),
  smtp_security text CHECK (smtp_security IS NULL OR smtp_security IN ('starttls', 'tls', 'none')),
  smtp_from text CHECK (smtp_from IS NULL OR char_length(smtp_from) BETWEEN 3 AND 254),
  plaintext_opt_in boolean NOT NULL DEFAULT false,
  version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
  updated_at timestamptz NOT NULL DEFAULT now(),
  -- The relay is all there or all absent.
  CONSTRAINT notify_settings_relay_whole CHECK (
    (smtp_host IS NULL AND smtp_port IS NULL AND smtp_security IS NULL AND smtp_from IS NULL)
    OR (smtp_host IS NOT NULL AND smtp_port IS NOT NULL AND smtp_security IS NOT NULL AND smtp_from IS NOT NULL)),
  -- Plaintext SMTP exists only with the explicit opt-in, and the opt-in only with plaintext.
  CONSTRAINT notify_settings_plaintext_opt_in CHECK (plaintext_opt_in = coalesce(smtp_security = 'none', false)),
  CONSTRAINT notify_settings_domains_bounded CHECK (cardinality(allowed_domains) <= 200)
);

ALTER TABLE public.notify_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.notify_settings FORCE ROW LEVEL SECURITY;
CREATE POLICY notify_settings_tenant ON public.notify_settings
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
REVOKE DELETE ON public.notify_settings FROM activediq_app;

COMMENT ON TABLE public.notify_settings IS 'DM-82 smtp channel and the allowed recipient domains (tenant table, RLS). Only internal/platform/notify/settings references it in SQL.';

-- write-class: notify_deliveries system
CREATE TABLE public.notify_deliveries (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  -- The caller's idempotency key: enqueueing the same key again returns the stored delivery.
  dedup_key text NOT NULL CHECK (dedup_key ~ '^[\x21-\x7e]{1,200}$'),
  channel text NOT NULL DEFAULT 'smtp' CHECK (channel = 'smtp'),
  purpose text NOT NULL CHECK (purpose ~ '^[a-z][a-z0-9_.]{0,63}$'),
  template_version integer NOT NULL CHECK (template_version >= 1),
  -- Variable references for the renderer. Not a body, and never a secret (DM-83.I1).
  variables jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(variables) = 'object' AND octet_length(variables::text) <= 4096),
  recipient_kind text NOT NULL CHECK (recipient_kind IN ('account', 'address')),
  recipient_account uuid,
  recipient_address text CHECK (recipient_address IS NULL OR char_length(recipient_address) BETWEEN 3 AND 254),
  -- source_ref: what the message is about, for example ('report_export', <export id>).
  source_kind text NOT NULL CHECK (source_kind ~ '^[a-z][a-z0-9_]{0,47}$'),
  source_id text NOT NULL CHECK (source_id ~ '^[\x21-\x7e]{1,128}$'),
  -- The principal that caused the message (the real human, or the system job), for the audit trail.
  requested_by text NOT NULL CHECK (char_length(requested_by) BETWEEN 1 AND 128),
  -- The caller's rule for this message: an attachment never goes to an address outside the allowed domains.
  require_internal boolean NOT NULL DEFAULT false,
  state text NOT NULL CHECK (state IN ('queued', 'sent', 'failed', 'given_up')),
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  max_attempts integer NOT NULL CHECK (max_attempts BETWEEN 1 AND 20),
  next_attempt_at timestamptz,
  lease_until timestamptz,
  -- A stable code (no free text, no remote reply): see internal/platform/notify/delivery.
  last_error_code text CHECK (last_error_code IS NULL OR last_error_code ~ '^[a-z][a-z0-9_]{0,63}$'),
  provider_message_id text CHECK (provider_message_id IS NULL OR char_length(provider_message_id) <= 255),
  sent_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT notify_deliveries_dedup UNIQUE (tenant_id, dedup_key),
  CONSTRAINT notify_deliveries_recipient_kind CHECK (
    (recipient_kind = 'account' AND recipient_account IS NOT NULL AND recipient_address IS NULL)
    OR (recipient_kind = 'address' AND recipient_address IS NOT NULL AND recipient_account IS NULL)),
  -- The lifecycle (DM-84): queued -> sent; queued -> failed -> (retry) -> sent | given_up.
  CONSTRAINT notify_deliveries_state_shape CHECK (
    (state IN ('queued', 'failed') AND next_attempt_at IS NOT NULL AND sent_at IS NULL)
    OR (state = 'sent' AND next_attempt_at IS NULL AND sent_at IS NOT NULL AND lease_until IS NULL)
    OR (state = 'given_up' AND next_attempt_at IS NULL AND sent_at IS NULL AND lease_until IS NULL AND last_error_code IS NOT NULL)),
  CONSTRAINT notify_deliveries_failed_has_reason CHECK (state <> 'failed' OR last_error_code IS NOT NULL),
  CONSTRAINT notify_deliveries_attempts_bounded CHECK (attempts <= max_attempts)
);

-- Deliveries.ForSource: a delivery-link download looks one up by source and recipient account.
CREATE INDEX notify_deliveries_source ON public.notify_deliveries (tenant_id, source_kind, source_id, recipient_account);
-- The dispatcher's scan for due work.
CREATE INDEX notify_deliveries_due ON public.notify_deliveries (tenant_id, next_attempt_at) WHERE state IN ('queued', 'failed');

ALTER TABLE public.notify_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.notify_deliveries FORCE ROW LEVEL SECURITY;
CREATE POLICY notify_deliveries_tenant ON public.notify_deliveries
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
REVOKE DELETE ON public.notify_deliveries FROM activediq_app;

-- Who was sent what is the authority for a delivery link (reports §7.2). Only the delivery's progress
-- changes after insert; its identity, recipient and source never do, and a finished delivery is final.
CREATE FUNCTION public.notify_deliveries_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $fn$
BEGIN
  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.id IS DISTINCT FROM OLD.id
     OR NEW.dedup_key IS DISTINCT FROM OLD.dedup_key OR NEW.channel IS DISTINCT FROM OLD.channel
     OR NEW.purpose IS DISTINCT FROM OLD.purpose OR NEW.template_version IS DISTINCT FROM OLD.template_version
     OR NEW.variables IS DISTINCT FROM OLD.variables OR NEW.recipient_kind IS DISTINCT FROM OLD.recipient_kind
     OR NEW.recipient_account IS DISTINCT FROM OLD.recipient_account OR NEW.recipient_address IS DISTINCT FROM OLD.recipient_address
     OR NEW.source_kind IS DISTINCT FROM OLD.source_kind OR NEW.source_id IS DISTINCT FROM OLD.source_id
     OR NEW.requested_by IS DISTINCT FROM OLD.requested_by OR NEW.require_internal IS DISTINCT FROM OLD.require_internal OR NEW.max_attempts IS DISTINCT FROM OLD.max_attempts
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'notify_deliveries: identity columns are immutable' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF OLD.state IN ('sent', 'given_up') THEN
    RAISE EXCEPTION 'notify_deliveries: a finished delivery is final' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF NEW.attempts < OLD.attempts THEN
    RAISE EXCEPTION 'notify_deliveries: attempts never decrease' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END
$fn$;

CREATE TRIGGER notify_deliveries_guard BEFORE UPDATE ON public.notify_deliveries
  FOR EACH ROW EXECUTE FUNCTION public.notify_deliveries_guard();

COMMENT ON TABLE public.notify_deliveries IS 'DM-84 Delivery: one message to one recipient, metadata only (tenant table, RLS). Only internal/platform/notify/delivery references it in SQL.';

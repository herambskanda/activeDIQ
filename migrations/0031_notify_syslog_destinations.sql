-- 0031_notify_syslog_destinations: SIEM syslog destinations (EP-9, TM-TB15-T7; T-0251).
-- Owner: internal/platform/notify/syslog. One tenant table.
--
-- A destination is where a tenant's notifications are forwarded over syslog. The table states the
-- transport rule itself, so no writer can store a plaintext destination without the opt-in flag:
--   transport tls  -> plaintext_opt_in is false (RFC 5425, verified; the default)
--   transport tcp  -> plaintext_opt_in is true  (plaintext; the opt-in is audited by the store)
-- UDP is not a transport. Rows are not deleted by the runtime role.

-- write-class: notify_syslog_destinations config
CREATE TABLE public.notify_syslog_destinations (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  host text NOT NULL CHECK (char_length(host) BETWEEN 1 AND 253),
  port integer NOT NULL CHECK (port BETWEEN 1 AND 65535),
  transport text NOT NULL CHECK (transport IN ('tls', 'tcp')),
  plaintext_opt_in boolean NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT notify_syslog_destinations_optin CHECK ((transport = 'tcp') = plaintext_opt_in)
);

CREATE INDEX notify_syslog_destinations_list ON public.notify_syslog_destinations (tenant_id, created_at, id);

ALTER TABLE public.notify_syslog_destinations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.notify_syslog_destinations FORCE ROW LEVEL SECURITY;
CREATE POLICY notify_syslog_destinations_tenant ON public.notify_syslog_destinations
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

REVOKE DELETE ON public.notify_syslog_destinations FROM activediq_app;

COMMENT ON TABLE public.notify_syslog_destinations IS 'EP-9 SIEM syslog destinations (tenant table, RLS). Only internal/platform/notify/syslog references it in SQL.';

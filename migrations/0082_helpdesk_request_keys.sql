-- 0082_helpdesk_request_keys: idempotency keys of the help-desk caller-verification routes (T-2145; ENH-09 §4a C1,
-- DM-38). Owner: internal/modules/helpdesk.
--
-- One row per (technician, operation, Idempotency-Key). It makes a retried POST safe: a retried issue never sends a second
-- code and a retried verify never charges a second attempt.
--   request_mac  keyed MAC of the request under the tenant MAC key, never a bare hash: a verify body holds a six-digit code,
--                and an unkeyed hash of it could be reversed by trying a million values. The code itself is never stored.
--   state        pending (claimed, work in flight), done (outcome recorded), abandoned (the work failed before an outcome
--                existed: the key may be claimed again). A pending claim older than a minute is treated as abandoned.
--   result_*     what a replay answers: for issue the challenge as the technician saw it, for verify whether it passed.

-- write-class: helpdesk_request_keys system
CREATE TABLE public.helpdesk_request_keys (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  technician_id text NOT NULL CHECK (technician_id <> ''),
  operation text NOT NULL,
  idem_key text NOT NULL CHECK (idem_key ~ '^[A-Za-z0-9._~-]{8,128}$'),
  request_mac bytea NOT NULL CHECK (octet_length(request_mac) = 32),
  state text NOT NULL DEFAULT 'pending',
  created_at timestamptz NOT NULL,
  completed_at timestamptz,
  result_challenge uuid,
  result_factor text,
  result_masked text,
  result_expires timestamptz,
  result_ok boolean,
  result_until timestamptz,
  PRIMARY KEY (tenant_id, technician_id, operation, idem_key),
  CONSTRAINT helpdesk_rk_operation CHECK (operation IN ('issue', 'verify')),
  CONSTRAINT helpdesk_rk_state CHECK (state IN ('pending', 'done', 'abandoned')),
  CONSTRAINT helpdesk_rk_done CHECK ((state = 'done') = (completed_at IS NOT NULL))
);

CREATE INDEX helpdesk_rk_created ON public.helpdesk_request_keys (tenant_id, created_at);

ALTER TABLE public.helpdesk_request_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.helpdesk_request_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY helpdesk_request_keys_tenant ON public.helpdesk_request_keys
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

COMMENT ON TABLE public.helpdesk_request_keys IS 'Idempotency keys of the caller-verification routes (tenant table, RLS): a keyed MAC of the request, never the code. Only internal/modules/helpdesk references it in SQL.';

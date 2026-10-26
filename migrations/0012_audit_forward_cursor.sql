-- 0012_audit_forward_cursor: where audit.forward has got to, per tenant and SIEM sink (T-0304; ADR-0005
-- rule 11, "SIEM forwarding"). Owner: internal/platform/audit.
--
-- Database-stated invariants:
--   I1  tenant_id with a foreign key to tenants and one fail-closed FORCE ROW LEVEL SECURITY policy.
--   I2  the cursor is a watermark over the chain, not evidence: it is mutable bookkeeping beside DM-80. The
--       forwarder moves it only after the sink acknowledged the batch and never backwards (GREATEST in the
--       statement), so a lost update re-sends at most one batch: delivery is at least once and seq
--       de-duplicates. DELETE is revoked so a sink's history of failures is not erased by the runtime role.
--   I3  failure state holds a snake_case code, never error text (a sink's reply can echo a credential).

CREATE TABLE public.audit_forward_cursor (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  sink_id text NOT NULL CHECK (sink_id ~ '^[a-z][a-z0-9_]{0,39}$'),
  event_seq bigint NOT NULL DEFAULT 0 CHECK (event_seq >= 0),
  checkpoint_seq bigint NOT NULL DEFAULT 0 CHECK (checkpoint_seq >= 0),
  consecutive_failures integer NOT NULL DEFAULT 0 CHECK (consecutive_failures >= 0),
  last_failure_code text CHECK (last_failure_code ~ '^[a-z][a-z0-9_]{0,63}$'),
  last_failure_at timestamptz,
  last_delivered_at timestamptz,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, sink_id),
  CONSTRAINT audit_forward_cursor_failure_coherent CHECK ((last_failure_code IS NULL) = (last_failure_at IS NULL))
);

ALTER TABLE public.audit_forward_cursor ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_forward_cursor FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_forward_cursor_tenant ON public.audit_forward_cursor
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

REVOKE DELETE ON public.audit_forward_cursor FROM activediq_app;

COMMENT ON TABLE public.audit_forward_cursor IS 'DM-80 forwarding watermark per tenant and SIEM sink (tenant table, RLS, mutable bookkeeping). Only internal/platform/audit references it in SQL.';

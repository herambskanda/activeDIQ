-- 0060_agentingest_events: the records an addc agent appended (T-0556; ADR-0007; contract
-- agent-host-addc-contract §2, §4). Owner: internal/platform/agentingest. Split out of the original
-- 0052 (T-0992: one owner key per file); it references only public.tenants, so its number is free.
--
--   agent_event           DM-89  records an addc agent appended. The identity columns are stamped by the
--                                server from the client certificate; nothing in the payload names them.
--                                Append-only; the agent's own gapless agent_seq makes redelivery idempotent.

-- write-class: agent_event system
CREATE TABLE public.agent_event (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  component_id uuid NOT NULL,
  agent_seq bigint NOT NULL CHECK (agent_seq > 0),
  record_type text NOT NULL CHECK (record_type IN ('event', 'gap', 'dropped')),
  channel text CHECK (channel IN ('security', 'directory_service')),
  event_record_id bigint CHECK (event_record_id IS NULL OR event_record_id >= 0),
  observed_at timestamptz NOT NULL,
  reported_dc_guid uuid,
  fields jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (octet_length(fields::text) <= 65536),
  -- sha256 of the agent-supplied content: a redelivery with the same hash is a duplicate, a different
  -- hash under the same agent_seq means the agent's state went backwards (divergence, never discarded).
  content_sha256 bytea NOT NULL CHECK (octet_length(content_sha256) = 32),
  received_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, component_id, agent_seq)
);

CREATE INDEX agent_event_time ON public.agent_event (tenant_id, observed_at);

ALTER TABLE public.agent_event ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.agent_event FORCE ROW LEVEL SECURITY;
CREATE POLICY agent_event_tenant ON public.agent_event
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
REVOKE DELETE, UPDATE ON public.agent_event FROM activediq_app;

COMMENT ON TABLE public.agent_event IS 'Records appended by addc agents, identity stamped from the client certificate (tenant table, RLS, append-only).';

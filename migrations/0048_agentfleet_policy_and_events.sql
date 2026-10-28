-- 0048_agentfleet_policy_and_events: server side of the addc agent module (T-0556; ADR-0007; contract
-- agent-host-addc-contract §2, §4). Owner: internal/platform/agentpolicy/signer (keys, keysets, policy
-- head) and internal/platform/agentpolicy/ingest (events). Four tenant tables, all FORCE ROW LEVEL SECURITY.
--
--   agent_policy_key      DM-86  the tenant's Ed25519 policy keys. The private key is AEAD-sealed under the
--                                tenant DEK (keys.Seal, bound to tenant, table, row, column, version); the
--                                public key and its ID sit beside it. A dropped key's sealed_key is erased.
--   agent_policy_keyset   DM-87  every signed keyset ever published, in order: the chain an agent that was
--                                offline replays. Append-only.
--   agent_policy_head     DM-88  the latest signed policy per tenant and agent kind, and the sequence floor:
--                                policy_seq only ever rises.
--   agent_event           DM-89  records an addc agent appended. The identity columns are stamped by the
--                                server from the client certificate; nothing in the payload names them.
--                                Append-only; the agent's own gapless agent_seq makes redelivery idempotent.

CREATE TABLE public.agent_policy_key (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  key_id text NOT NULL CHECK (key_id ~ '^k-[0-9a-f]{16}$'),
  public_key bytea NOT NULL CHECK (octet_length(public_key) = 32),
  sealed_key bytea CHECK (sealed_key IS NULL OR octet_length(sealed_key) BETWEEN 32 AND 4096),
  key_version integer CHECK (key_version IS NULL OR key_version > 0),
  state text NOT NULL CHECK (state IN ('active', 'retiring', 'dropped')),
  retire_after timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  dropped_at timestamptz,
  PRIMARY KEY (tenant_id, id),
  CONSTRAINT agent_policy_key_sealed_iff_live CHECK ((state = 'dropped') = (sealed_key IS NULL) AND (state = 'dropped') = (key_version IS NULL)),
  CONSTRAINT agent_policy_key_retire CHECK ((state = 'retiring') = (retire_after IS NOT NULL) OR state = 'dropped'),
  CONSTRAINT agent_policy_key_dropped CHECK ((state = 'dropped') = (dropped_at IS NOT NULL))
);

CREATE UNIQUE INDEX agent_policy_key_one_active ON public.agent_policy_key (tenant_id) WHERE state = 'active';
CREATE UNIQUE INDEX agent_policy_key_id ON public.agent_policy_key (tenant_id, key_id);

CREATE TABLE public.agent_policy_keyset (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  keyset_seq bigint NOT NULL CHECK (keyset_seq > 0),
  signed bytea NOT NULL CHECK (octet_length(signed) BETWEEN 64 AND 4096),
  issued_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, keyset_seq)
);

CREATE TABLE public.agent_policy_head (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  agent_kind text NOT NULL CHECK (agent_kind IN ('addc', 'fileserver')),
  policy_seq bigint NOT NULL CHECK (policy_seq > 0),
  signed bytea NOT NULL CHECK (octet_length(signed) BETWEEN 64 AND 1500000),
  issued_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, agent_kind)
);

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
  received_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, component_id, agent_seq)
);

CREATE INDEX agent_event_time ON public.agent_event (tenant_id, observed_at);

DO $do$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['agent_policy_key', 'agent_policy_keyset', 'agent_policy_head', 'agent_event'] LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format($p$CREATE POLICY %I ON public.%I
      USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
      WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)$p$, concat(t, '_tenant'), t);
    EXECUTE format('REVOKE DELETE ON public.%I FROM activediq_app', t);
  END LOOP;
END
$do$;

REVOKE UPDATE ON public.agent_policy_keyset, public.agent_event FROM activediq_app;

COMMENT ON TABLE public.agent_policy_key IS 'Policy signing keys of a tenant (tenant table, RLS). The private key is sealed (ADR-0007). Only internal/platform/agentpolicy/signer references it in SQL.';
COMMENT ON TABLE public.agent_policy_keyset IS 'Every signed keyset published, in order (tenant table, RLS, append-only).';
COMMENT ON TABLE public.agent_policy_head IS 'Latest signed policy and sequence floor per tenant and agent kind (tenant table, RLS).';
COMMENT ON TABLE public.agent_event IS 'Records appended by addc agents, identity stamped from the client certificate (tenant table, RLS, append-only).';

-- A key only moves forward: active -> retiring (retire_after set), retiring -> dropped (sealed material
-- erased). Identity columns never change and a dropped key is never revived. A live key's sealed bytes
-- may be rewritten, because a DEK re-seal (TM-D15) does exactly that without changing the key.
CREATE FUNCTION public.agent_policy_key_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $fn$
BEGIN
  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.id IS DISTINCT FROM OLD.id
     OR NEW.key_id IS DISTINCT FROM OLD.key_id OR NEW.public_key IS DISTINCT FROM OLD.public_key
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'agent_policy_key: identity columns are never written' USING ERRCODE = 'AD403';
  END IF;
  IF NEW.state IS DISTINCT FROM OLD.state
     AND NOT ((OLD.state = 'active' AND NEW.state = 'retiring') OR (OLD.state = 'retiring' AND NEW.state = 'dropped')) THEN
    RAISE EXCEPTION 'agent_policy_key: % -> % is not allowed', OLD.state, NEW.state USING ERRCODE = 'AD403';
  END IF;
  RETURN NEW;
END
$fn$;

CREATE TRIGGER agent_policy_key_guard BEFORE UPDATE ON public.agent_policy_key
  FOR EACH ROW EXECUTE FUNCTION public.agent_policy_key_guard();
ALTER TABLE public.agent_policy_key ENABLE ALWAYS TRIGGER agent_policy_key_guard;

-- The policy sequence floor only rises (ADR-0007 decision 2: strictly increasing per tenant and kind).
CREATE FUNCTION public.agent_policy_head_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $fn$
BEGIN
  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.agent_kind IS DISTINCT FROM OLD.agent_kind
     OR NEW.policy_seq <= OLD.policy_seq THEN
    RAISE EXCEPTION 'agent_policy_head: policy_seq must rise' USING ERRCODE = 'AD403';
  END IF;
  RETURN NEW;
END
$fn$;

CREATE TRIGGER agent_policy_head_guard BEFORE UPDATE ON public.agent_policy_head
  FOR EACH ROW EXECUTE FUNCTION public.agent_policy_head_guard();
ALTER TABLE public.agent_policy_head ENABLE ALWAYS TRIGGER agent_policy_head_guard;

-- 0097_operation_plan_chunks: durable record of the plan chunks of a bulk operation (ADR-0005 rule 6,
-- job kind operation.plan; T-2073). Owner: internal/platform/operation.
--
-- A bulk operation plans in chunk jobs of operations.chunk_size items. A chunk's rows (items, steps, this
-- record) commit in one transaction, so the primary key (operation, plan_revision, chunk_no) makes a
-- re-driven chunk a no-op once it is recorded, and a chunk planned for a superseded revision never counts.
-- chunk_hash is the chunk's hash chained onto the previous chunk's; the last chunk's value is the
-- operation's plan hash.

-- write-class: operation_plan_chunks system
CREATE TABLE public.operation_plan_chunks (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  operation_id uuid NOT NULL,
  plan_revision integer NOT NULL CHECK (plan_revision >= 1),
  chunk_no integer NOT NULL CHECK (chunk_no >= 0),
  items integer NOT NULL CHECK (items >= 0),
  chunk_hash text NOT NULL CHECK (chunk_hash ~ '^[0-9a-f]{64}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, operation_id, plan_revision, chunk_no),
  FOREIGN KEY (tenant_id, operation_id) REFERENCES public.operations (tenant_id, id)
);

-- Total items of a chunked plan, known when the plan starts; null for an inline plan.
ALTER TABLE public.operations
  ADD COLUMN plan_items integer CHECK (plan_items >= 0);

ALTER TABLE public.operation_plan_chunks ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.operation_plan_chunks FORCE ROW LEVEL SECURITY;
CREATE POLICY operation_plan_chunks_tenant ON public.operation_plan_chunks
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

COMMENT ON TABLE public.operation_plan_chunks IS 'ADR-0005 rule 6 plan chunks (tenant table, RLS): one row per planned chunk of a bulk operation, committed with the chunk''s items and steps.';

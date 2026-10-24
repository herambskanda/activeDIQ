-- 0010_operation_operations: the persisted operation pipeline (ADR-0005 rules 3, 6, 8, 9; DM-41, DM-42,
-- DM-43.I1). Owner: internal/platform/operation.
--
-- The OperationItem is the system of record; the job is only a driver. Every table is a tenant table
-- (tenant_id, a foreign key to tenants and one fail-closed FORCE ROW LEVEL SECURITY policy).
--
--   operations        DM-41. One intent, planned before it runs. Carries the plan hash the approval is bound
--                     to (approved_plan_hash), the pinned DCs (pins), and the plan revision that fences
--                     plan-chunk results.
--   operation_items   DM-42. One target of an operation, with its phase.
--   operation_steps   DM-42 steps[]. One planned write. `attempt` is the fencing number: a step is claimed
--                     planned -> applying with a new attempt and claimed_until on the database clock, and
--                     every recording UPDATE is predicated on state = 'applying' AND attempt = $n.
--   operation_secrets Rule 9: a transient secret input, sealed (TM-D7), with its own TTL. The runtime role
--                     can insert, read and delete, never update.
--
-- Only internal/platform/operation references these tables in SQL; the state columns are written only by its
-- transition functions (fitness-operation O4).

CREATE TABLE public.operations (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  id uuid NOT NULL,
  action_id text NOT NULL CHECK (action_id <> '' AND length(action_id) <= 200),
  action_version integer NOT NULL CHECK (action_version >= 1),
  origin text NOT NULL CHECK (origin IN ('console', 'api', 'csv', 'workflow', 'automation', 'report_results', 'undo', 'migration')),
  requester_id text NOT NULL CHECK (requester_id <> '' AND length(requester_id) <= 200),
  requester_kind text NOT NULL CHECK (requester_kind IN ('human', 'api_token', 'automation', 'system')),
  -- The principals the requester acted through, innermost last: [{"id": "...", "kind": "..."}].
  via jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(via) = 'array'),
  state text NOT NULL CHECK (state IN ('draft', 'planning', 'planned', 'no_change', 'plan_failed', 'awaiting_approval',
    'approved', 'rejected', 'queued', 'running', 'succeeded', 'partially_succeeded', 'failed', 'cancelling', 'cancelled')),
  plan_hash text CHECK (plan_hash ~ '^[0-9a-f]{64}$'),
  plan_revision integer NOT NULL DEFAULT 1 CHECK (plan_revision >= 1),
  plan_valid_until timestamptz,
  -- Not part of the plan hash (rule 5): the DC pin per naming context.
  pins jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(pins) = 'object'),
  -- The typed input, re-used by a re-plan. Null for an Action whose input carries a secret (rule 9).
  input bytea,
  -- Rule 8: why the kernel held it, and the registered gate's Request reference when a workflow matched.
  hold_reason text CHECK (hold_reason IN ('blast_radius', 'irreversible', 'step_up', 'undo_needed_approval', 'gate')),
  request_ref text CHECK (length(request_ref) <= 200),
  max_objects integer CHECK (max_objects >= 1),
  step_up_fresh boolean NOT NULL DEFAULT false,
  -- The kernel's single approval, bound to a plan hash (DM-65.I1): a re-plan with the same hash keeps it.
  approved_by text CHECK (approved_by <> '' AND length(approved_by) <= 200),
  approved_plan_hash text CHECK (approved_plan_hash ~ '^[0-9a-f]{64}$'),
  approved_at timestamptz,
  undo_of uuid,
  idempotency_key text CHECK (idempotency_key <> '' AND length(idempotency_key) <= 200),
  chunk_size integer NOT NULL DEFAULT 100 CHECK (chunk_size BETWEEN 1 AND 10000),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CHECK ((approved_by IS NULL) = (approved_plan_hash IS NULL) AND (approved_by IS NULL) = (approved_at IS NULL))
);

-- Rule 4, submission level: a retried submit returns the existing operation.
CREATE UNIQUE INDEX operations_idempotency ON public.operations (tenant_id, requester_id, idempotency_key)
  WHERE idempotency_key IS NOT NULL;
-- The sweeper: operations that are not terminal.
CREATE INDEX operations_live ON public.operations (tenant_id, state, updated_at)
  WHERE state IN ('planning', 'approved', 'queued', 'running', 'cancelling', 'awaiting_approval', 'planned', 'draft');

CREATE TABLE public.operation_items (
  tenant_id uuid NOT NULL,
  operation_id uuid NOT NULL,
  item_no integer NOT NULL CHECK (item_no >= 0),
  state text NOT NULL CHECK (state IN ('pending', 'planned', 'skipped', 'blocked', 'running', 'succeeded', 'failed', 'cancelled', 'undone')),
  -- Items of phase n+1 start only after phase n is terminal (rule 1).
  phase integer NOT NULL DEFAULT 0 CHECK (phase >= 0),
  target jsonb NOT NULL CHECK (jsonb_typeof(target) = 'object'),
  reason text CHECK (reason ~ '^[a-z][a-z0-9_]{0,63}$'),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, operation_id, item_no),
  FOREIGN KEY (tenant_id, operation_id) REFERENCES public.operations (tenant_id, id)
);

CREATE TABLE public.operation_steps (
  tenant_id uuid NOT NULL,
  operation_id uuid NOT NULL,
  item_no integer NOT NULL,
  step_no integer NOT NULL CHECK (step_no >= 0),
  state text NOT NULL CHECK (state IN ('planned', 'applying', 'applied', 'verified', 'verify_failed', 'failed', 'not_run', 'undone')),
  -- The fence. 0 until the first claim; every claim and every takeover by the reconciler bumps it.
  attempt integer NOT NULL DEFAULT 0 CHECK (attempt >= 0),
  claimed_at timestamptz,
  claimed_until timestamptz,
  -- The planned StepPlan (target, diff, preconditions, class, phase). No secret value is ever in it.
  plan jsonb NOT NULL CHECK (jsonb_typeof(plan) = 'object'),
  digest bytea NOT NULL CHECK (octet_length(digest) = 32),
  -- Where it runs: for the per-(connection, DC) concurrency slots (rule 5).
  connection_id text NOT NULL DEFAULT '',
  dc_host text NOT NULL DEFAULT '',
  naming_context text NOT NULL DEFAULT '',
  -- A step that sets a credential is never re-applied by reconciliation (rule 6).
  credential boolean NOT NULL DEFAULT false,
  reason text CHECK (reason ~ '^[a-z][a-z0-9_]{0,63}$'),
  recovered boolean NOT NULL DEFAULT false,
  outcome jsonb CHECK (jsonb_typeof(outcome) = 'object'),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, operation_id, item_no, step_no),
  FOREIGN KEY (tenant_id, operation_id, item_no) REFERENCES public.operation_items (tenant_id, operation_id, item_no),
  CHECK ((state = 'applying') = (claimed_until IS NOT NULL))
);

-- The claim and the reconciler.
CREATE INDEX operation_steps_claim ON public.operation_steps (tenant_id, operation_id, state, item_no, step_no);
CREATE INDEX operation_steps_lapsed ON public.operation_steps (tenant_id, claimed_until) WHERE state = 'applying';
CREATE INDEX operation_steps_slots ON public.operation_steps (tenant_id, connection_id, dc_host) WHERE state = 'applying';

CREATE TABLE public.operation_secrets (
  tenant_id uuid NOT NULL,
  operation_id uuid NOT NULL,
  item_no integer NOT NULL,
  step_no integer NOT NULL,
  -- Sealed with the TM-D7 primitive; associated data (tenant, table, row, column, key version).
  sealed_secret bytea NOT NULL,
  key_version integer NOT NULL CHECK (key_version >= 1),
  -- Its own TTL: the request's expiry, at most 72 hours, independent of plan_valid_until.
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, operation_id, item_no, step_no),
  FOREIGN KEY (tenant_id, operation_id, item_no, step_no) REFERENCES public.operation_steps (tenant_id, operation_id, item_no, step_no)
);

ALTER TABLE public.operations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.operations FORCE ROW LEVEL SECURITY;
CREATE POLICY operations_tenant ON public.operations
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

ALTER TABLE public.operation_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.operation_items FORCE ROW LEVEL SECURITY;
CREATE POLICY operation_items_tenant ON public.operation_items
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

ALTER TABLE public.operation_steps ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.operation_steps FORCE ROW LEVEL SECURITY;
CREATE POLICY operation_steps_tenant ON public.operation_steps
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

ALTER TABLE public.operation_secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.operation_secrets FORCE ROW LEVEL SECURITY;
CREATE POLICY operation_secrets_tenant ON public.operation_secrets
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

-- Rule 9: the runtime role holds no UPDATE on operation_secrets. A secret is never replaced after
-- submission; a new secret means a new operation.
REVOKE UPDATE ON public.operation_secrets FROM activediq_app;

COMMENT ON TABLE public.operations IS 'DM-41 Operation (tenant table, RLS). Its state column is written only by the operation package''s transition function (O4).';
COMMENT ON TABLE public.operation_items IS 'DM-42 OperationItem (tenant table, RLS). The system of record of a bulk change; the job is only a driver (DM-43.I1).';
COMMENT ON TABLE public.operation_steps IS 'DM-42 steps[] (tenant table, RLS). Claimed with a fencing attempt; recording is predicated on state and attempt (ADR-0005 rule 6).';
COMMENT ON TABLE public.operation_secrets IS 'ADR-0005 rule 9 transient secret input (tenant table, RLS): sealed, own TTL (at most 72 hours), deleted in the step''s recording transaction and on every terminal operation state. No UPDATE for the runtime role.';

-- 0084_migration_fidelity: the fidelity report and the inert proposal store (T-2062; spec e2-11 §6.2, §6.4,
-- §6.5, §3.1; DM-92, DM-93). Owner: internal/modules/migration. Two tenant tables with forced RLS.
--
--   migration_fidelity   exactly one row per parsed item of a job: exact, changed (with diff), manual or
--                        not_supported, with the reason. Insert-only.
--   migration_proposals  one stored, INERT description of intended configuration (and the grants it
--                        carries) per applicable item. Nothing reads this table for authorisation, jobs,
--                        schedules or notifications: a proposal grants nothing until a later, separate
--                        Action applies it. Insert-only here.
--
-- A proposal can exist only for an item classed exact or changed: its class is part of the foreign key to
-- the fidelity row and is CHECKed, so a manual or not_supported item cannot have one even by a buggy writer.

-- write-class: migration_fidelity config
CREATE TABLE public.migration_fidelity (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  job_id uuid NOT NULL,
  item_seq integer NOT NULL CHECK (item_seq >= 0),
  item_ref text NOT NULL CHECK (char_length(item_ref) BETWEEN 1 AND 500),
  item_kind text NOT NULL CHECK (item_kind ~ '^[a-z][a-z0-9_]{0,63}$'),
  item_name text NOT NULL CHECK (char_length(item_name) <= 500),
  class text NOT NULL CHECK (class IN ('exact', 'changed', 'manual', 'not_supported')),
  reason text NOT NULL CHECK (reason ~ '^[a-z][a-z0-9_]{0,63}$' OR reason = ''),
  diff jsonb NOT NULL DEFAULT '[]'::jsonb,
  detail text NOT NULL DEFAULT '' CHECK (char_length(detail) <= 32767),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, job_id, item_seq),
  UNIQUE (tenant_id, job_id, item_ref),
  UNIQUE (tenant_id, job_id, item_seq, class),
  FOREIGN KEY (tenant_id, job_id) REFERENCES public.migration_jobs (tenant_id, job_id),
  CHECK ((class = 'changed') = (jsonb_array_length(diff) > 0)),
  CHECK ((class IN ('manual', 'not_supported')) = (reason <> ''))
);

-- write-class: migration_proposals config
CREATE TABLE public.migration_proposals (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  proposal_id uuid NOT NULL DEFAULT gen_random_uuid(),
  job_id uuid NOT NULL,
  item_seq integer NOT NULL,
  class text NOT NULL CHECK (class IN ('exact', 'changed')),
  config jsonb NOT NULL CHECK (jsonb_typeof(config) = 'object'),
  grants jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(grants) = 'array'),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, proposal_id),
  UNIQUE (tenant_id, job_id, item_seq),
  FOREIGN KEY (tenant_id, job_id, item_seq, class)
    REFERENCES public.migration_fidelity (tenant_id, job_id, item_seq, class)
);

ALTER TABLE public.migration_fidelity ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.migration_fidelity FORCE ROW LEVEL SECURITY;
CREATE POLICY migration_fidelity_tenant ON public.migration_fidelity
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

ALTER TABLE public.migration_proposals ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.migration_proposals FORCE ROW LEVEL SECURITY;
CREATE POLICY migration_proposals_tenant ON public.migration_proposals
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

REVOKE UPDATE, DELETE ON public.migration_fidelity, public.migration_proposals FROM activediq_app;

COMMENT ON TABLE public.migration_fidelity IS 'DM-92: one fidelity row per parsed migration item (exact, changed, manual, not_supported). Tenant table, RLS; insert-only for the runtime role. Text is data, encoded on every output (T-0150). Only internal/modules/migration references it in SQL.';
COMMENT ON TABLE public.migration_proposals IS 'DM-93: a stored, inert proposal of intended configuration for an exact or changed item. Grants nothing; no authorisation path reads it. Tenant table, RLS; insert-only for the runtime role. Only internal/modules/migration references it in SQL.';

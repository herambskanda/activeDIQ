-- 0080_authz_assignment_constraints: additive constraints on a role assignment (T-1600, ADM-132, ADM-133).
-- Owner: internal/platform/rbac (authz). Both tables narrow or order what an assignment already grants;
-- neither adds a scope root kind, and a missing row means "no constraint".
--
--   authz_assignment_templates  the Templates the assignment's holder may create from or modify with.
--                               No row: every Template. Rows: only these (ADM-132).
--   authz_assignment_sites      the AD sites whose DCs are tried first for the holder's operations, in
--                               ordinal order (ADM-133). A hint only: ADR-0005 rule 5 still pins one DC.

-- write-class: authz_assignment_templates config
CREATE TABLE public.authz_assignment_templates (
  tenant_id uuid NOT NULL,
  assignment_id uuid NOT NULL,
  template_id uuid NOT NULL CHECK (template_id <> '00000000-0000-0000-0000-000000000000'),
  PRIMARY KEY (tenant_id, assignment_id, template_id),
  FOREIGN KEY (tenant_id, assignment_id) REFERENCES public.authz_assignments (tenant_id, id)
);

-- write-class: authz_assignment_sites config
CREATE TABLE public.authz_assignment_sites (
  tenant_id uuid NOT NULL,
  assignment_id uuid NOT NULL,
  ordinal integer NOT NULL CHECK (ordinal >= 0 AND ordinal < 8),
  site text NOT NULL CHECK (char_length(site) BETWEEN 1 AND 64),
  PRIMARY KEY (tenant_id, assignment_id, ordinal),
  FOREIGN KEY (tenant_id, assignment_id) REFERENCES public.authz_assignments (tenant_id, id)
);

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['authz_assignment_templates', 'authz_assignment_sites'] LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format($p$CREATE POLICY %I ON public.%I USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
      WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)$p$, t || '_tenant', t);
    EXECUTE format('REVOKE DELETE ON public.%I FROM activediq_app', t);
  END LOOP;
END
$$;

COMMENT ON TABLE public.authz_assignment_templates IS 'ADM-132 Templates an assignment is restricted to (tenant table, RLS). No row: unrestricted.';
COMMENT ON TABLE public.authz_assignment_sites IS 'ADM-133 ordered preferred AD sites of an assignment (tenant table, RLS). A DC-choice hint only.';

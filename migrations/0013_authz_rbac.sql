-- 0013_authz_rbac: RBAC persistence for the operation Authorizer (T-0324; DM-34 Role, DM-36
-- RoleAssignment; threat model §7.7). Owner: internal/platform/rbac. Four tenant tables.
--
--   authz_roles             a named set of permissions. tier says where the role sits: 0 holds Tier-0
--                           administration, 1 platform administration, 2 help desk. A role of tier 2 can
--                           never hold a permission that is only meaningful at Tier-0 scope (T-0173).
--   authz_role_permissions  the permissions of a role.
--   authz_assignments       role x subject. The subject is a console account only; group, automation and
--                           token subjects arrive with their own tickets and grant nothing until then.
--   authz_assignment_roots  the scope of an assignment: include or exclude roots, each a GUID.
--                           root_kind tier0_scope is the connection's Tier-0 scope (root_guid is the
--                           connection ID); it covers Tier-0 scope targets and nothing else, and no other
--                           kind ever covers a Tier-0 scope target.

CREATE TABLE public.authz_roles (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  role_name text NOT NULL CHECK (char_length(role_name) BETWEEN 1 AND 128),
  built_in boolean NOT NULL DEFAULT false,
  tier smallint NOT NULL CHECK (tier BETWEEN 0 AND 2),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, role_name)
);

CREATE TABLE public.authz_role_permissions (
  tenant_id uuid NOT NULL,
  role_id uuid NOT NULL,
  permission text NOT NULL CHECK (permission ~ '^[a-z][a-z0-9_.:-]{0,127}$'),
  PRIMARY KEY (tenant_id, role_id, permission),
  FOREIGN KEY (tenant_id, role_id) REFERENCES public.authz_roles (tenant_id, id)
);

CREATE TABLE public.authz_assignments (
  tenant_id uuid NOT NULL,
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  account_id uuid NOT NULL,
  role_id uuid NOT NULL,
  valid_from timestamptz NOT NULL DEFAULT now(),
  valid_until timestamptz,
  granted_by text NOT NULL CHECK (char_length(granted_by) BETWEEN 1 AND 128),
  assignment_state text NOT NULL DEFAULT 'active' CHECK (assignment_state IN ('active', 'revoked')),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, role_id) REFERENCES public.authz_roles (tenant_id, id),
  CHECK (valid_until IS NULL OR valid_until > valid_from)
);
CREATE INDEX authz_assignments_account ON public.authz_assignments (tenant_id, account_id) WHERE assignment_state = 'active';

CREATE TABLE public.authz_assignment_roots (
  tenant_id uuid NOT NULL,
  assignment_id uuid NOT NULL,
  ordinal integer NOT NULL CHECK (ordinal >= 0),
  is_exclude boolean NOT NULL DEFAULT false,
  root_kind text NOT NULL CHECK (root_kind IN ('naming_context', 'ou_subtree', 'entra_tenant', 'tier0_scope')),
  connection_id uuid NOT NULL,
  root_guid uuid NOT NULL CHECK (root_guid <> '00000000-0000-0000-0000-000000000000'),
  PRIMARY KEY (tenant_id, assignment_id, ordinal),
  FOREIGN KEY (tenant_id, assignment_id) REFERENCES public.authz_assignments (tenant_id, id),
  -- A connection-wide or Tier-0 root is identified by its connection: the GUID is that connection's.
  CHECK (root_kind NOT IN ('entra_tenant', 'tier0_scope') OR root_guid = connection_id),
  -- A Tier-0 scope root is only ever an include: there is nothing inside it to exclude.
  CHECK (root_kind <> 'tier0_scope' OR NOT is_exclude)
);

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['authz_roles', 'authz_role_permissions', 'authz_assignments', 'authz_assignment_roots'] LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format($p$CREATE POLICY %I ON public.%I USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
      WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)$p$, t || '_tenant', t);
    EXECUTE format('REVOKE DELETE ON public.%I FROM activediq_app', t);
  END LOOP;
END
$$;

COMMENT ON TABLE public.authz_roles IS 'DM-34 Role (tenant table, RLS). Only internal/platform/rbac references it in SQL.';
COMMENT ON TABLE public.authz_role_permissions IS 'DM-34 Role privileges (tenant table, RLS).';
COMMENT ON TABLE public.authz_assignments IS 'DM-36 RoleAssignment (tenant table, RLS). Account subjects only for now.';
COMMENT ON TABLE public.authz_assignment_roots IS 'DM-35 scope roots of an assignment (tenant table, RLS). tier0_scope covers Tier-0 scope targets only.';

-- A Tier-2 (help-desk) role never holds a permission that exists only at Tier-0 scope (T-0173). The check is
-- on the permission insert and on a tier change, so neither order of edits can slip past it.
CREATE FUNCTION public.authz_tier2_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $fn$
BEGIN
  IF TG_TABLE_NAME = 'authz_role_permissions' THEN
    IF NEW.permission LIKE '%.tier0_designation.%'
       AND (SELECT r.tier FROM public.authz_roles r WHERE r.tenant_id = NEW.tenant_id AND r.id = NEW.role_id) = 2 THEN
      RAISE EXCEPTION 'authz: a Tier-2 role cannot hold a Tier-0 scope permission' USING ERRCODE = 'AD403';
    END IF;
  ELSIF NEW.tier = 2 AND EXISTS (SELECT 1 FROM public.authz_role_permissions p
      WHERE p.tenant_id = NEW.tenant_id AND p.role_id = NEW.id AND p.permission LIKE '%.tier0_designation.%') THEN
    RAISE EXCEPTION 'authz: a role holding a Tier-0 scope permission cannot be Tier-2' USING ERRCODE = 'AD403';
  END IF;
  RETURN NEW;
END
$fn$;
CREATE TRIGGER authz_role_permissions_tier2 BEFORE INSERT ON public.authz_role_permissions
  FOR EACH ROW EXECUTE FUNCTION public.authz_tier2_guard();
CREATE TRIGGER authz_roles_tier2 BEFORE UPDATE OF tier ON public.authz_roles
  FOR EACH ROW EXECUTE FUNCTION public.authz_tier2_guard();
ALTER TABLE public.authz_role_permissions ENABLE ALWAYS TRIGGER authz_role_permissions_tier2;
ALTER TABLE public.authz_roles ENABLE ALWAYS TRIGGER authz_roles_tier2;

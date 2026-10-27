-- 0035_authz_subjects: group and automation-policy subjects, and the tenant-wide root for activeDIQ's
-- own store (T-0367; DM-36 subject, DM-35 root kinds, DM-36.I4). Owner: internal/platform/rbac.
--
--   * authz_assignments gains subject_kind. 'account' keeps account_id; 'group' is a directory group
--     (connection + objectGUID, DM-36.I2); 'automation' is an opaque reference to an automation policy
--     owned by modules/lifecycle (no foreign key across the layer). The columns of the other kinds are NULL.
--   * root_kind 'tenant' is the tenant-wide root: it covers targets in activeDIQ's own store (no
--     directory connection) and nothing else. Its connection_id and root_guid are the tenant's ID.
--   * Control-plane authority is personal (DM-36.I4, TM-D17 rule 5): the tenant-owner role, and any role
--     holding a permission in a control-plane family, can be assigned to an account subject only. The
--     trigger refuses it on the assignment and on a permission added to a role a non-account subject
--     holds, whoever writes. The prefixes are the same as authz.NeverCrosses (checked by a Go test).

ALTER TABLE public.authz_assignments
  ADD COLUMN subject_kind text NOT NULL DEFAULT 'account' CHECK (subject_kind IN ('account', 'group', 'automation')),
  ADD COLUMN group_connection_id uuid,
  ADD COLUMN group_guid uuid CHECK (group_guid IS NULL OR group_guid <> '00000000-0000-0000-0000-000000000000'),
  ADD COLUMN automation_policy_id uuid;
ALTER TABLE public.authz_assignments ALTER COLUMN account_id DROP NOT NULL;
ALTER TABLE public.authz_assignments ADD CONSTRAINT authz_assignments_subject_shape CHECK (
  (subject_kind = 'account' AND account_id IS NOT NULL AND group_connection_id IS NULL AND group_guid IS NULL AND automation_policy_id IS NULL) OR
  (subject_kind = 'group' AND account_id IS NULL AND group_connection_id IS NOT NULL AND group_guid IS NOT NULL AND automation_policy_id IS NULL) OR
  (subject_kind = 'automation' AND account_id IS NULL AND group_connection_id IS NULL AND group_guid IS NULL AND automation_policy_id IS NOT NULL));
CREATE INDEX authz_assignments_group ON public.authz_assignments (tenant_id, group_connection_id, group_guid)
  WHERE assignment_state = 'active' AND subject_kind = 'group';
CREATE INDEX authz_assignments_automation ON public.authz_assignments (tenant_id, automation_policy_id)
  WHERE assignment_state = 'active' AND subject_kind = 'automation';

ALTER TABLE public.authz_assignment_roots DROP CONSTRAINT authz_assignment_roots_root_kind_check;
ALTER TABLE public.authz_assignment_roots ADD CONSTRAINT authz_assignment_roots_root_kind_check
  CHECK (root_kind IN ('naming_context', 'ou_subtree', 'entra_tenant', 'tier0_scope', 'tenant'));
ALTER TABLE public.authz_assignment_roots ADD CONSTRAINT authz_assignment_roots_tenant_root CHECK (
  root_kind <> 'tenant' OR (root_guid = connection_id AND root_guid = tenant_id AND NOT is_exclude));

CREATE FUNCTION public.authz_control_plane_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $fn$
DECLARE
  prefixes text[] := ARRAY['rbac.', 'authz.', 'delegation.', 'scope.', 'connections.', 'tenant.', 'inventory.tier0_'];
  rid uuid;
  tid uuid;
BEGIN
  IF TG_TABLE_NAME = 'authz_assignments' THEN
    IF NEW.subject_kind = 'account' THEN
      RETURN NEW;
    END IF;
    rid := NEW.role_id; tid := NEW.tenant_id;
  ELSE -- authz_role_permissions: a permission added to a role some non-account subject holds
    rid := NEW.role_id; tid := NEW.tenant_id;
    IF NOT EXISTS (SELECT 1 FROM public.authz_assignments a WHERE a.tenant_id = tid AND a.role_id = rid
                   AND a.subject_kind <> 'account' AND a.assignment_state = 'active')
       OR NOT EXISTS (SELECT 1 FROM unnest(prefixes) p WHERE starts_with(NEW.permission, p)) THEN
      RETURN NEW;
    END IF;
    RAISE EXCEPTION 'authz: control-plane authority is personal; clone the role instead' USING ERRCODE = 'AD403';
  END IF;
  IF EXISTS (SELECT 1 FROM public.authz_roles r WHERE r.tenant_id = tid AND r.id = rid AND r.role_name = 'tenant-owner' AND r.built_in)
     OR EXISTS (SELECT 1 FROM public.authz_role_permissions p, unnest(prefixes) x
                WHERE p.tenant_id = tid AND p.role_id = rid AND starts_with(p.permission, x)) THEN
    RAISE EXCEPTION 'authz: control-plane authority is personal; it cannot be given to a group or automation subject' USING ERRCODE = 'AD403';
  END IF;
  RETURN NEW;
END
$fn$;
CREATE TRIGGER authz_assignments_control_plane BEFORE INSERT OR UPDATE ON public.authz_assignments
  FOR EACH ROW EXECUTE FUNCTION public.authz_control_plane_guard();
CREATE TRIGGER authz_role_permissions_control_plane BEFORE INSERT ON public.authz_role_permissions
  FOR EACH ROW EXECUTE FUNCTION public.authz_control_plane_guard();
ALTER TABLE public.authz_assignments ENABLE ALWAYS TRIGGER authz_assignments_control_plane;
ALTER TABLE public.authz_role_permissions ENABLE ALWAYS TRIGGER authz_role_permissions_control_plane;

COMMENT ON TABLE public.authz_assignments IS 'DM-36 RoleAssignment (tenant table, RLS). Subject: account, directory group or automation policy.';

-- Editing a custom role can remove one of its permissions (T-0367, rbac.Grants.SetRolePermissions); the
-- built-in roles are read-only (DM-34.I1) and rbac refuses to edit them. Removal only narrows.
GRANT DELETE ON public.authz_role_permissions TO activediq_app;

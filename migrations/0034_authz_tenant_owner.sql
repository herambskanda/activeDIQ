-- 0034_authz_tenant_owner: the built-in tenant-owner role is fixed and its assignments are unbounded
-- (T-0436; DM-30.I4, DM-36.I4, ADM-126). Owner: internal/platform/rbac.
--
-- A tenant must never lose its last owner. Revoke is guarded by the owner advisory lock in code
-- (rbac.OwnerAssignments); time is not a writer, so an owner assignment may carry no valid_until and
-- no future valid_from: the schema refuses it, whoever writes. Otherwise rbac.Owners.TenantOwners (which
-- counts in-window assignments only) would find an owner-less tenant with no lock ever taken.
--
--   * the name tenant-owner is reserved for the built-in role;
--   * a built-in tenant-owner role is read-only: it cannot be renamed, re-tiered, un-built-in'd, nor gain
--     permissions;
--   * an assignment of it has valid_until NULL and valid_from <= now(), on insert and on any update.

CREATE FUNCTION public.authz_tenant_owner_role_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $fn$
BEGIN
  IF TG_TABLE_NAME = 'authz_roles' THEN
    IF TG_OP = 'INSERT' THEN
      IF NEW.role_name = 'tenant-owner' AND NOT NEW.built_in THEN
        RAISE EXCEPTION 'authz: the name tenant-owner is reserved for the built-in role' USING ERRCODE = 'AD403';
      END IF;
    ELSIF OLD.role_name = 'tenant-owner' AND OLD.built_in
       AND (NEW.role_name IS DISTINCT FROM OLD.role_name OR NEW.built_in IS DISTINCT FROM OLD.built_in
            OR NEW.tier IS DISTINCT FROM OLD.tier OR NEW.id IS DISTINCT FROM OLD.id) THEN
      RAISE EXCEPTION 'authz: the built-in tenant-owner role is read-only' USING ERRCODE = 'AD403';
    ELSIF NEW.role_name = 'tenant-owner' AND NOT (OLD.role_name = 'tenant-owner') THEN
      RAISE EXCEPTION 'authz: the name tenant-owner is reserved for the built-in role' USING ERRCODE = 'AD403';
    END IF;
  ELSIF TG_TABLE_NAME = 'authz_role_permissions' THEN
    IF EXISTS (SELECT 1 FROM public.authz_roles r
               WHERE r.tenant_id = NEW.tenant_id AND r.id = NEW.role_id AND r.role_name = 'tenant-owner' AND r.built_in) THEN
      RAISE EXCEPTION 'authz: the built-in tenant-owner role is read-only' USING ERRCODE = 'AD403';
    END IF;
  ELSE -- authz_assignments
    IF EXISTS (SELECT 1 FROM public.authz_roles r
               WHERE r.tenant_id = NEW.tenant_id AND r.id = NEW.role_id AND r.role_name = 'tenant-owner' AND r.built_in)
       AND (NEW.valid_until IS NOT NULL OR NEW.valid_from > now()) THEN
      RAISE EXCEPTION 'authz: a tenant-owner assignment cannot expire or start later' USING ERRCODE = 'AD403';
    END IF;
  END IF;
  RETURN NEW;
END
$fn$;

CREATE TRIGGER authz_roles_tenant_owner BEFORE INSERT OR UPDATE ON public.authz_roles
  FOR EACH ROW EXECUTE FUNCTION public.authz_tenant_owner_role_guard();
CREATE TRIGGER authz_role_permissions_tenant_owner BEFORE INSERT ON public.authz_role_permissions
  FOR EACH ROW EXECUTE FUNCTION public.authz_tenant_owner_role_guard();
CREATE TRIGGER authz_assignments_tenant_owner BEFORE INSERT OR UPDATE ON public.authz_assignments
  FOR EACH ROW EXECUTE FUNCTION public.authz_tenant_owner_role_guard();
ALTER TABLE public.authz_roles ENABLE ALWAYS TRIGGER authz_roles_tenant_owner;
ALTER TABLE public.authz_role_permissions ENABLE ALWAYS TRIGGER authz_role_permissions_tenant_owner;
ALTER TABLE public.authz_assignments ENABLE ALWAYS TRIGGER authz_assignments_tenant_owner;

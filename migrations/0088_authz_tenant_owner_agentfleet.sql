-- 0088_authz_tenant_owner_agentfleet: the built-in tenant-owner role may also hold the two agentfleet
-- permissions (T-0599): agentfleet.policy.edit (sign a new addc password and event policy) and
-- agentfleet.keyset.rotate (rotate the policy key ahead of schedule, ADR-0007 decision 6). Same
-- mechanism as migration 0043: the allow-list below and rbac.BuiltInRoles change together and a test
-- pins them equal. Existing tenants receive the rows the next time rbac.SeedBuiltIns runs for them.

CREATE OR REPLACE FUNCTION public.authz_tenant_owner_role_guard() RETURNS trigger
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
    IF NEW.permission <> ALL (ARRAY['connections.correlation.reconfirm', 'agentfleet.policy.edit', 'agentfleet.keyset.rotate'])
       AND EXISTS (SELECT 1 FROM public.authz_roles r
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

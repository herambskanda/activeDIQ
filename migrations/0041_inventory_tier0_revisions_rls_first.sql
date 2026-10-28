-- 0041_inventory_tier0_revisions_rls_first: let row security, not a trigger, refuse a tenant re-assignment
-- (T-0500; fitness-tenancy T4). Owner: internal/directory/inventory.
--
-- 0036's BEFORE UPDATE guard also rejected a changed tenant_id, and a BEFORE trigger runs before the
-- WITH CHECK of the RLS policy, so the fitness probe "tenant A re-assigns its row to tenant B" was refused
-- by the trigger and never showed that row security refuses it. The BEFORE guard now only keeps the
-- revision monotone within a tenant; an AFTER trigger (which runs after the policy's WITH CHECK) still
-- forbids moving a row between tenants for any writer that bypasses RLS.

CREATE OR REPLACE FUNCTION public.inventory_tier0_revision_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.tenant_id = OLD.tenant_id AND NEW.revision <= OLD.revision THEN
    RAISE EXCEPTION 'inventory_tier0_revisions only moves forward' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;

CREATE FUNCTION public.inventory_tier0_revision_tenant_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.tenant_id <> OLD.tenant_id THEN
    RAISE EXCEPTION 'inventory_tier0_revisions rows never change tenant' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NULL;
END $$;

CREATE TRIGGER inventory_tier0_revisions_tenant_guard AFTER UPDATE ON public.inventory_tier0_revisions
  FOR EACH ROW EXECUTE FUNCTION public.inventory_tier0_revision_tenant_guard();

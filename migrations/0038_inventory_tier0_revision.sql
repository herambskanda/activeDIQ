-- 0038_inventory_tier0_revision: the per-tenant tier0-set revision (client.RevisionSource, T-0376).
-- Owner: internal/directory/inventory.
--
-- The connector echoes this number in audit and in errors (connector-contract §8.3) so an operator can
-- tell which tier0 set a decision rested on. It is a counter, not a hash or a timestamp: it must never
-- decrease, and it must change exactly when the tier0 set can have changed. Triggers bump it in the
-- same transaction as the change, so no writer can forget to and no reader can see the change without it:
--  * tier0_designations: a designation added, re-activated or removed;
--  * correlations: the tier0 bases of either side change, or a correlation that carries tier0 facts is
--    created, removed or revived. A refresh that re-states the same facts (facts_as_of, updated_at)
--    leaves it alone.
-- (Group membership under a designated group is read live at statement time, contract §8.3 F2, and is not
-- part of this number.)

-- write-class: inventory_tier0_revisions system
CREATE TABLE public.inventory_tier0_revisions (
  tenant_id uuid PRIMARY KEY REFERENCES public.tenants (id),
  revision bigint NOT NULL CHECK (revision > 0)
);

ALTER TABLE public.inventory_tier0_revisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.inventory_tier0_revisions FORCE ROW LEVEL SECURITY;
CREATE POLICY inventory_tier0_revisions_tenant ON public.inventory_tier0_revisions
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
REVOKE DELETE ON public.inventory_tier0_revisions FROM activediq_app;

COMMENT ON TABLE public.inventory_tier0_revisions IS 'Per-tenant monotone tier0-set revision (directory table, RLS), bumped by triggers. Only internal/directory/inventory references it in SQL.';

-- A revision never decreases, whoever writes it.
CREATE FUNCTION public.inventory_tier0_revision_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.tenant_id <> OLD.tenant_id OR NEW.revision <= OLD.revision THEN
    RAISE EXCEPTION 'inventory_tier0_revisions only moves forward' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER inventory_tier0_revisions_guard BEFORE UPDATE ON public.inventory_tier0_revisions
  FOR EACH ROW EXECUTE FUNCTION public.inventory_tier0_revision_guard();

CREATE FUNCTION public.inventory_tier0_revision_bump() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  tid uuid := COALESCE(NEW.tenant_id, OLD.tenant_id);
  changed boolean;
BEGIN
  IF TG_TABLE_NAME = 'tier0_designations' THEN
    changed := TG_OP = 'INSERT' AND NEW.removed_at IS NULL
      OR TG_OP = 'UPDATE' AND (OLD.removed_at IS NULL) IS DISTINCT FROM (NEW.removed_at IS NULL);
  ELSE
    changed := TG_OP = 'INSERT' AND (NEW.ad_tier0 OR NEW.entra_tier0)
      OR TG_OP = 'UPDATE' AND (
        OLD.ad_tier0_bases IS DISTINCT FROM NEW.ad_tier0_bases
        OR OLD.entra_tier0_bases IS DISTINCT FROM NEW.entra_tier0_bases
        OR ((OLD.state = 'removed') IS DISTINCT FROM (NEW.state = 'removed') AND (OLD.ad_tier0 OR OLD.entra_tier0 OR NEW.ad_tier0 OR NEW.entra_tier0)));
  END IF;
  IF changed THEN
    INSERT INTO public.inventory_tier0_revisions (tenant_id, revision) VALUES (tid, 1)
      ON CONFLICT (tenant_id) DO UPDATE SET revision = public.inventory_tier0_revisions.revision + 1;
  END IF;
  RETURN NULL;
END $$;

CREATE TRIGGER tier0_designations_revision AFTER INSERT OR UPDATE ON public.tier0_designations
  FOR EACH ROW EXECUTE FUNCTION public.inventory_tier0_revision_bump();
CREATE TRIGGER correlations_tier0_revision AFTER INSERT OR UPDATE ON public.correlations
  FOR EACH ROW EXECUTE FUNCTION public.inventory_tier0_revision_bump();

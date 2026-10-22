-- 0005_connection_hybrid_links: DM-21 HybridLink (domain-model DM-21, ADR-0003 F1). Owner:
-- internal/directory/connection.
--
-- A hybrid link declares which AD domain (ad_connection_id + nc_guid) syncs into which Entra tenant
-- (entra_connection_id). Many-to-many, so the identity of a link is the triple, unique among links
-- that are not removed (a removed link can be declared again; the old row stays for audit).
--
-- Database-stated invariants:
--   I2  a link enters the lifecycle by one of two doors only: declared -> confirmed, or
--       discovered -> proposed. Discovery can never insert a confirmed link, so it cannot bootstrap
--       its own trust (insert trigger).
--   Lifecycle: proposed -> confirmed, confirmed -> removed, proposed -> removed (update trigger; SQL
--       twin of edges in internal/directory/connection/hybrid_link.go, kept in step by
--       TestHybridLinkMigrationEdgesMatchTheGoTable). removed is terminal.
--   Sides: the AD side is an ad_forest connection and the Entra side an entra_tenant connection of
--       the same tenant (composite foreign keys + insert trigger).
-- Who may confirm (connections.hybrid_link.confirm over both scopes) and the audited Operation are
-- the caller's: this table only records the result.

CREATE TABLE public.hybrid_links (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  ad_connection_id uuid NOT NULL,
  -- objectGUID of the domain naming context, canonical lower-case UUID text.
  nc_guid text NOT NULL CHECK (nc_guid ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
  entra_connection_id uuid NOT NULL,
  origin text NOT NULL CHECK (origin IN ('declared', 'discovered')),
  state text NOT NULL CHECK (state IN ('proposed', 'confirmed', 'removed')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, ad_connection_id) REFERENCES public.connections (tenant_id, id),
  FOREIGN KEY (tenant_id, entra_connection_id) REFERENCES public.connections (tenant_id, id)
);

CREATE UNIQUE INDEX hybrid_links_live ON public.hybrid_links (tenant_id, ad_connection_id, nc_guid, entra_connection_id)
  WHERE state <> 'removed';
-- HasHybridLink and the per-side reads.
CREATE INDEX hybrid_links_ad ON public.hybrid_links (tenant_id, ad_connection_id, state);
CREATE INDEX hybrid_links_entra ON public.hybrid_links (tenant_id, entra_connection_id, state);

ALTER TABLE public.hybrid_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.hybrid_links FORCE ROW LEVEL SECURITY;
CREATE POLICY hybrid_links_tenant ON public.hybrid_links
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

-- Removal is a state, never a delete: audit references keep resolving.
REVOKE DELETE ON public.hybrid_links FROM activediq_app;

COMMENT ON TABLE public.hybrid_links IS 'DM-21 HybridLink (tenant table, RLS). Only internal/directory/connection references it in SQL.';

CREATE FUNCTION public.hybrid_links_guard_insert() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $fn$
BEGIN
  IF NOT ((NEW.origin = 'declared' AND NEW.state = 'confirmed') OR (NEW.origin = 'discovered' AND NEW.state = 'proposed')) THEN
    RAISE EXCEPTION 'hybrid_links: a link is born declared+confirmed or discovered+proposed (DM-21.I2)' USING ERRCODE = 'AD403';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM public.connections c WHERE c.tenant_id = NEW.tenant_id AND c.id = NEW.ad_connection_id AND c.kind = 'ad_forest')
     OR NOT EXISTS (SELECT 1 FROM public.connections c WHERE c.tenant_id = NEW.tenant_id AND c.id = NEW.entra_connection_id AND c.kind = 'entra_tenant') THEN
    RAISE EXCEPTION 'hybrid_links: sides must be an ad_forest and an entra_tenant connection (DM-21)' USING ERRCODE = 'AD403';
  END IF;
  RETURN NEW;
END
$fn$;

CREATE TRIGGER hybrid_links_guard_insert BEFORE INSERT ON public.hybrid_links
  FOR EACH ROW EXECUTE FUNCTION public.hybrid_links_guard_insert();
ALTER TABLE public.hybrid_links ENABLE ALWAYS TRIGGER hybrid_links_guard_insert;

CREATE FUNCTION public.hybrid_links_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $fn$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id OR NEW.ad_connection_id IS DISTINCT FROM OLD.ad_connection_id
     OR NEW.nc_guid IS DISTINCT FROM OLD.nc_guid OR NEW.entra_connection_id IS DISTINCT FROM OLD.entra_connection_id
     OR NEW.origin IS DISTINCT FROM OLD.origin THEN
    RAISE EXCEPTION 'hybrid_links: identity and origin never change (DM-21)' USING ERRCODE = 'AD403';
  END IF;
  IF NEW.state IS DISTINCT FROM OLD.state AND (OLD.state, NEW.state) NOT IN (
    ('proposed', 'confirmed'),
    ('confirmed', 'removed'),
    ('proposed', 'removed')
  ) THEN
    RAISE EXCEPTION 'hybrid_links: % -> % is not a DM-21 transition', OLD.state, NEW.state USING ERRCODE = 'AD403';
  END IF;
  RETURN NEW;
END
$fn$;

CREATE TRIGGER hybrid_links_guard BEFORE UPDATE ON public.hybrid_links
  FOR EACH ROW EXECUTE FUNCTION public.hybrid_links_guard();
ALTER TABLE public.hybrid_links ENABLE ALWAYS TRIGGER hybrid_links_guard;

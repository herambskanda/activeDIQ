-- 0010_inventory_writer: what the inventory WRITER (T-0173) needs on top of the read slice of 0005.
-- Owner: internal/directory/inventory.
--
--  * correlations: the two connection references become real foreign keys (security review of T-0167:
--    a row must not name another tenant's connection). The reader still joins the connections and
--    checks their kind, because a foreign key cannot say ad_forest / entra_tenant.
--  * tier0_designations: removal is a state, never a delete. Taking a designation off silently drops
--    Tier-0 protection from an object, so the runtime role loses DELETE (as on correlations) and the
--    row keeps who removed it and when. The audit event is the Operation's; this is the data trail.
--    designated_by is the requester's pseudonymous principal ID (text), not a uuid.
--  * links: DM-17 Link, the membership slice the GroupSource walks: 'member' edges and 'primary_group'
--    edges (DM-17.I2; a user whose primaryGroupID names a group is in it without a member value).
--    Only forward edges are stored (I1). Edges are never deleted, only marked removed/deactivated,
--    so the runtime role loses DELETE (a silent delete would drop Tier-0 protection from members).

ALTER TABLE public.correlations
  ADD CONSTRAINT correlations_ad_connection_fk FOREIGN KEY (tenant_id, ad_connection_id) REFERENCES public.connections (tenant_id, id),
  ADD CONSTRAINT correlations_entra_connection_fk FOREIGN KEY (tenant_id, entra_connection_id) REFERENCES public.connections (tenant_id, id);

ALTER TABLE public.tier0_designations
  ALTER COLUMN designated_by TYPE text USING designated_by::text,
  ADD COLUMN removed_at timestamptz,
  ADD COLUMN removed_by text,
  ADD CONSTRAINT tier0_designations_by_set CHECK (designated_by IS NULL OR designated_by <> ''),
  ADD CONSTRAINT tier0_designations_removal_coherent CHECK ((removed_at IS NULL) = (removed_by IS NULL) AND (removed_by IS NULL OR removed_by <> ''));

REVOKE DELETE ON public.tier0_designations FROM activediq_app;

CREATE TABLE public.links (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  connection_id uuid NOT NULL,
  source_guid uuid NOT NULL,
  link_attr text NOT NULL CHECK (link_attr IN ('member', 'primary_group')),
  target_guid uuid NOT NULL,
  state text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'deactivated', 'removed')),
  observed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, connection_id, source_guid, link_attr, target_guid),
  FOREIGN KEY (tenant_id, connection_id) REFERENCES public.connections (tenant_id, id)
);
REVOKE DELETE ON public.links FROM activediq_app;

-- GroupsOf walks from a member up to the groups that contain it.
CREATE INDEX links_by_target ON public.links (tenant_id, connection_id, link_attr, target_guid) WHERE state = 'active';

ALTER TABLE public.links ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.links FORCE ROW LEVEL SECURITY;
CREATE POLICY links_tenant ON public.links
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

COMMENT ON TABLE public.links IS 'DM-17 Link (directory table, RLS). Only internal/directory/inventory references it in SQL.';

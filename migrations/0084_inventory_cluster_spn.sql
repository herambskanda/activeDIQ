-- 0084_inventory_cluster_spn: CMP-02 cluster input and the manager lookup key (T-1477, spec reports-2a 6.4).
-- cluster_spn is true when a servicePrincipalName value has the class MSClusterVirtualServer or
-- MSServerCluster (ad-expert consult, T-1477); NULL = servicePrincipalName was not read. The values
-- themselves are not stored. Owner: internal/directory/inventory.
ALTER TABLE public.directory_objects ADD COLUMN cluster_spn boolean;

-- dn_key / manager_key: the DN and the manager DN as lower-cased md5 uuids, GUID-typed so a report can match a
-- user's manager DN to the manager row without exposing the manager's DN outside the caller's scope (a
-- MaskAnchor may project only non-text columns; a fragment may not call md5). manager_key is NULL when the
-- row has no manager. Used by inventory.users manager_guid.
-- manager_key reflects the manager DN as last synced; it goes stale until the manager object is resynced after a DN change.
ALTER TABLE public.directory_objects
  ADD COLUMN dn_key uuid GENERATED ALWAYS AS (CASE WHEN dn <> '' THEN md5(lower(dn))::uuid END) STORED,
  ADD COLUMN manager_key uuid GENERATED ALWAYS AS (
    CASE WHEN jsonb_typeof(attributes -> 'manager') = 'string' THEN md5(lower(attributes ->> 'manager'))::uuid END) STORED;
CREATE INDEX directory_objects_by_dn_key ON public.directory_objects (tenant_id, connection_id, dn_key) WHERE dn_key IS NOT NULL;

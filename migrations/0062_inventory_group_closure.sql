-- 0062_inventory_group_closure: the effective group membership the datasets inventory.groups and
-- inventory.group_members read (T-0961; reports.md §3.3, spec reports-2a §6.6, FR-15). Owner:
-- internal/directory/inventory.
--
--  * inventory_group_members: one row per (group, effective member), derived from the DM-17 links
--    (member edges and primary-group edges). edge_kind says how the member got there:
--      direct         a member value of the group (depth 1)
--      primary_group  the member's primaryGroupID names the group (depth 1; no member value)
--      nested         reached through one or more nested groups (depth > 1)
--      cycle          the group reaches itself through nested groups: a finding row, not a member
--    via lists the groups between the group and the member, nearest the group first (empty at depth
--    1); for a cycle row it is the groups of the loop, so A -> B -> A is group A, via {B}. A member
--    reachable by several paths has one row, with the shortest path (lowest GUID breaks a tie), so a
--    report names each member once. Rows exist for every member the links name; whether the member or
--    the group is live and in scope is decided by the report query, never by this table.
--  * inventory_group_closure_dirty: groups whose own edges or state changed since the closure was
--    last refreshed. RefreshClosure recomputes those groups and every group that contains them, then
--    clears the set, all in the writer's transaction. A row here at read time means the closure is
--    behind the links.
--
-- The closure is derived data: unlike links it may be deleted, so the runtime role keeps DELETE.

CREATE TABLE public.inventory_group_members (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  connection_id uuid NOT NULL,
  group_guid uuid NOT NULL,
  member_guid uuid NOT NULL,
  edge_kind text NOT NULL CHECK (edge_kind IN ('direct', 'primary_group', 'nested', 'cycle')),
  depth integer NOT NULL CHECK (depth BETWEEN 1 AND 128),
  via uuid[] NOT NULL DEFAULT '{}' CHECK (cardinality(via) BETWEEN 0 AND 127),
  PRIMARY KEY (tenant_id, connection_id, group_guid, member_guid),
  FOREIGN KEY (tenant_id, connection_id) REFERENCES public.connections (tenant_id, id),
  CHECK ((edge_kind = 'cycle') = (group_guid = member_guid)),
  CHECK (cardinality(via) = depth - 1)
);
-- The groups one object belongs to (the tokenGroups question), and the groups that contain a group.
CREATE INDEX inventory_group_members_by_member ON public.inventory_group_members (tenant_id, connection_id, member_guid);

CREATE TABLE public.inventory_group_closure_dirty (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  connection_id uuid NOT NULL,
  group_guid uuid NOT NULL,
  PRIMARY KEY (tenant_id, connection_id, group_guid),
  FOREIGN KEY (tenant_id, connection_id) REFERENCES public.connections (tenant_id, id)
);

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['inventory_group_members', 'inventory_group_closure_dirty'] LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY %I ON public.%I USING (tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid) WITH CHECK (tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid)', t || '_tenant', t);
  END LOOP;
END $$;

COMMENT ON TABLE public.inventory_group_members IS 'Effective group membership closure with primary-group edges, shortest via path and cycle findings (directory table, RLS, derived). Only internal/directory/inventory references it in SQL.';
COMMENT ON TABLE public.inventory_group_closure_dirty IS 'Groups whose closure rows are stale (directory table, RLS, derived). Only internal/directory/inventory references it in SQL.';

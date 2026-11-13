-- 0074_inventory_object_changes: DM-18 ChangeRecord at object level (T-1109; reports-2-second-slice
-- §4.1 and D10). Owner: internal/directory/inventory.
--
--  * One row per observed change of one AD object: created, edited, moved, renamed or deleted. It is
--    observation-based (DM-18.I2): two changes between two observations are one row, and the time is
--    observed_at, the as-of of the sync cycle that saw it. whenChanged is per DC and is never used.
--  * attributes_changed holds attribute NAMES only, never values (spec §4.1 rule 3; DM-18.I4 secrets
--    cannot get in because directory_objects refuses them). automatic_only is true when every changed
--    attribute is in the noise set of the writer (spec §4.1 rule 2), so the report can hide it.
--  * name, sam_account_name and dn are snapshots taken at the change. A deleted row carries the last
--    observation (spec §4.1 rule 7). They are only ever shown through the object's current scope
--    anchor, so an object outside the runner's scope has no row to read.
--  * Rows are written by the inventory populator in the same statement as the object upsert, and only
--    after the connection has completed a sync pass: the first full pass is the baseline, not a
--    flood of "created". Append-only (DM-18.I1): the runtime role can neither update nor delete.
--    Partitioned retention (ADM-206) is not built yet.
--  * No actor column (DM-18.I3) and no origin time: v1 delivers no replication metadata, so every row
--    is an observation. A later ticket adds origin when it has a source.

-- write-class: directory_object_changes system
CREATE TABLE public.directory_object_changes (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  connection_id uuid NOT NULL,
  change_id uuid NOT NULL DEFAULT gen_random_uuid(),
  object_guid uuid NOT NULL,
  change_kind text NOT NULL CHECK (change_kind IN ('created', 'edited', 'moved', 'renamed', 'deleted')),
  object_kind text NOT NULL CHECK (object_kind IN ('user', 'inetorgperson', 'group', 'computer', 'contact', 'ou', 'container', 'gmsa', 'fsp', 'other')),
  attributes_changed text[] NOT NULL DEFAULT '{}' CHECK (cardinality(attributes_changed) <= 256),
  automatic_only boolean NOT NULL DEFAULT false,
  name text NOT NULL DEFAULT '' CHECK (length(name) <= 1024),
  sam_account_name text NOT NULL DEFAULT '' CHECK (length(sam_account_name) <= 256),
  dn text NOT NULL DEFAULT '' CHECK (length(dn) <= 4096),
  observed_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, change_id),
  FOREIGN KEY (tenant_id, connection_id) REFERENCES public.connections (tenant_id, id),
  FOREIGN KEY (tenant_id, connection_id, object_guid) REFERENCES public.directory_objects (tenant_id, connection_id, object_guid),
  CHECK (NOT automatic_only OR change_kind = 'edited'),
  CHECK (change_kind <> 'deleted' OR cardinality(attributes_changed) = 0)
);
-- A period read per connection, newest first; and everything about one object (DM-18.I5).
CREATE INDEX directory_object_changes_by_time ON public.directory_object_changes (tenant_id, connection_id, observed_at DESC);
CREATE INDEX directory_object_changes_by_object ON public.directory_object_changes (tenant_id, connection_id, object_guid, observed_at DESC);

ALTER TABLE public.directory_object_changes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.directory_object_changes FORCE ROW LEVEL SECURITY;
CREATE POLICY directory_object_changes_tenant ON public.directory_object_changes
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

REVOKE UPDATE, DELETE, TRUNCATE ON public.directory_object_changes FROM activediq_app;

COMMENT ON TABLE public.directory_object_changes IS 'DM-18 observed object changes: kind, attribute names, observed time, last-known name and DN (directory table, RLS, append-only). Only internal/directory/inventory references it in SQL.';

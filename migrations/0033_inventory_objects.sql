-- 0033_inventory_objects: DM-16 DirectoryObject, the current last-observed state of one AD or Entra
-- object (T-0431). Owner: internal/directory/inventory.
--
--  * Identity is (tenant_id, connection_id, object_guid) (DM-16.I1, X3). dn, sam_account_name and upn are
--    display snapshots, refreshed on every observation (I2), never keys. One current row per identity
--    (I4); past values live in ChangeRecord (DM-18, not built yet).
--  * Secret attributes have no column and the populator refuses them in `attributes` (I3).
--  * Time-dependent state is stored as its INPUTS only (lockout_time, pwd_last_set, account_expires); locked_out,
--    password_expired and the rest are computed at read time (I5a). Never a flag here.
--  * cloud_seen_at (I9) is Entra users and groups only and is only ever moved forward: the CHECK and
--    the trigger make that true whichever writer holds the pen, so DM-20.I4(g) cannot be reset.
--  * consistency_guid is ms-DS-ConsistencyGuid (16 bytes, LDAP wire order): the DM-20.I1a anchor lookup
--    matches it first, then object_guid.
--  * Rows are never deleted by the runtime role: a delete is a state (deleted/recycled/purged/soft_deleted).
--  * nc_guid names the AD naming context the object lives in (DM-14); there is none for Entra.
--  * tier0 is NOT a column: the classifiers (T-0326) compute it from these rows.

-- write-class: directory_objects system
CREATE TABLE public.directory_objects (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  connection_id uuid NOT NULL,
  object_guid uuid NOT NULL,
  nc_guid uuid,
  kind text NOT NULL CHECK (kind IN ('user', 'inetorgperson', 'group', 'computer', 'contact', 'ou', 'container', 'gmsa', 'fsp', 'other')),
  object_class text NOT NULL CHECK (object_class <> '' AND length(object_class) <= 100),
  parent_guid uuid,
  ancestry uuid[] NOT NULL DEFAULT '{}' CHECK (cardinality(ancestry) <= 128),
  dn text NOT NULL DEFAULT '' CHECK (length(dn) <= 4096),
  rdn text NOT NULL DEFAULT '' CHECK (length(rdn) <= 1024),
  sid bytea CHECK (sid IS NULL OR length(sid) BETWEEN 8 AND 68),
  sam_account_name text NOT NULL DEFAULT '' CHECK (length(sam_account_name) <= 256),
  upn text NOT NULL DEFAULT '' CHECK (length(upn) <= 1024),
  display_name text NOT NULL DEFAULT '' CHECK (length(display_name) <= 1024),
  enabled boolean,
  lockout_time timestamptz,
  pwd_last_set timestamptz,
  account_expires timestamptz,
  consistency_guid bytea CHECK (consistency_guid IS NULL OR length(consistency_guid) = 16),
  attributes jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(attributes) = 'object' AND pg_column_size(attributes) <= 131072),
  when_created timestamptz,
  when_changed timestamptz,
  observed_at timestamptz NOT NULL,
  observed_dsa text NOT NULL DEFAULT '' CHECK (length(observed_dsa) <= 256),
  cloud_seen_at timestamptz,
  state text NOT NULL DEFAULT 'live' CHECK (state IN ('live', 'deleted', 'recycled', 'purged', 'out_of_scope', 'active', 'soft_deleted')),
  PRIMARY KEY (tenant_id, connection_id, object_guid),
  FOREIGN KEY (tenant_id, connection_id) REFERENCES public.connections (tenant_id, id),
  CHECK (parent_guid IS NULL OR parent_guid <> object_guid),
  -- I9: Entra users and groups only.
  CHECK (cloud_seen_at IS NULL OR (nc_guid IS NULL AND kind IN ('user', 'group'))),
  CHECK (consistency_guid IS NULL OR nc_guid IS NOT NULL)
);

-- DM-20.I1a: the anchor is looked up by objectGUID and by ms-DS-ConsistencyGuid across AD connections.
CREATE INDEX directory_objects_by_consistency_guid ON public.directory_objects (tenant_id, consistency_guid)
  WHERE consistency_guid IS NOT NULL;
CREATE INDEX directory_objects_by_guid ON public.directory_objects (tenant_id, object_guid);
CREATE INDEX directory_objects_by_sid ON public.directory_objects (tenant_id, connection_id, sid) WHERE sid IS NOT NULL;

-- I9 and I5 monotonicity, in the database whichever writer holds the pen: cloud_seen_at never goes
-- backwards or back to NULL, and an older observation never overwrites a newer one.
CREATE FUNCTION public.directory_objects_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  -- tenant_id is left to row-level security, whose WITH CHECK rejects a re-assignment.
  IF NEW.connection_id IS DISTINCT FROM OLD.connection_id
     OR NEW.object_guid IS DISTINCT FROM OLD.object_guid THEN
    RAISE EXCEPTION 'directory_objects: identity never changes' USING ERRCODE = 'AD403';
  END IF;
  IF OLD.cloud_seen_at IS NOT NULL AND (NEW.cloud_seen_at IS NULL OR NEW.cloud_seen_at < OLD.cloud_seen_at) THEN
    RAISE EXCEPTION 'directory_objects: cloud_seen_at is never cleared or moved back' USING ERRCODE = 'AD403';
  END IF;
  IF NEW.observed_at < OLD.observed_at THEN
    RAISE EXCEPTION 'directory_objects: observed_at never moves back' USING ERRCODE = 'AD403';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER directory_objects_guard BEFORE UPDATE ON public.directory_objects
  FOR EACH ROW EXECUTE FUNCTION public.directory_objects_guard();

ALTER TABLE public.directory_objects ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.directory_objects FORCE ROW LEVEL SECURITY;
CREATE POLICY directory_objects_tenant ON public.directory_objects
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

-- A delete is a state; history is DM-18's.
REVOKE DELETE ON public.directory_objects FROM activediq_app;

COMMENT ON TABLE public.directory_objects IS 'DM-16 DirectoryObject (directory table, RLS). Only internal/directory/inventory references it in SQL.';

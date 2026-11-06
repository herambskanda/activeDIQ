-- 0070_sync_cursors: DM-19 SyncCursor, the change-feed position of one partition (T-1190, under T-1188).
-- Owner: internal/directory/sync (owner key `sync`). The store in that package is the ONLY writer.
--
--  * One row per (tenant, connection, partition): an AD naming context (partition = the NC's objectGUID)
--    or one Graph resource of an Entra tenant (partition = a lower-case resource token such as `users`).
--  * cookie is opaque: DirSync cookie or Graph delta token. Nothing in the database or in Go parses it,
--    and no list or diagnostic method returns it. issuing_dsa_guid is the DC that issued an AD cookie
--    (DM-19.I4: a cookie is reused only on the DC that issued it).
--  * lease_fencing_token is the platform lease's fencing token (DM-06.I2) of the newest holder that wrote
--    here. It only rises. The store writes with a compare-and-set that refuses a lower token, so a
--    holder whose lease was taken over cannot commit (DM-19.I2). Claim at lease acquisition raises it at
--    once, so the deposed holder is fenced before the new holder has advanced anything.
--  * state follows the DM-19 lifecycle initial_sync -> incremental <-> resync_required, and `paused`
--    while the connection is suspended (resumption sets resync_required). The trigger below enforces the
--    same transition matrix as the store, so a writer that is not the store cannot skip a step.
--  * Written in the same transaction as the inventory rows it covers (DM-19.I1): the store takes the
--    caller's transaction and never opens one.
--  * A cookie exists only while the feed is usable: initial_sync and resync_required carry none (an
--    invalid or expired cookie forces a full resync, DM-19.I3), and incremental carries a full sync time.

-- write-class: sync_cursors system
CREATE TABLE public.sync_cursors (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  connection_id uuid NOT NULL,
  partition text NOT NULL,
  state text NOT NULL DEFAULT 'initial_sync',
  cookie bytea,
  issuing_dsa_guid uuid,
  last_full_sync_at timestamptz,
  last_change_at timestamptz,
  lease_fencing_token bigint NOT NULL,
  state_changed_at timestamptz NOT NULL DEFAULT now(),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, connection_id, partition),
  FOREIGN KEY (tenant_id, connection_id) REFERENCES public.connections (tenant_id, id),
  CONSTRAINT sync_cursors_partition_shape CHECK (
    partition ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' OR partition ~ '^[a-z][a-z0-9_]{0,39}$'),
  CONSTRAINT sync_cursors_partition_not_nil CHECK (partition <> '00000000-0000-0000-0000-000000000000'),
  CONSTRAINT sync_cursors_state_check CHECK (state IN ('initial_sync', 'incremental', 'resync_required', 'paused')),
  CONSTRAINT sync_cursors_token_positive CHECK (lease_fencing_token >= 1),
  CONSTRAINT sync_cursors_cookie_size CHECK (cookie IS NULL OR octet_length(cookie) BETWEEN 1 AND 65536),
  CONSTRAINT sync_cursors_cookie_state CHECK (cookie IS NULL OR state IN ('incremental', 'paused')),
  CONSTRAINT sync_cursors_dsa_needs_cookie CHECK (issuing_dsa_guid IS NULL OR cookie IS NOT NULL),
  CONSTRAINT sync_cursors_incremental_synced CHECK (state <> 'incremental' OR last_full_sync_at IS NOT NULL)
);

-- The transition matrix (DM-19 lifecycle). A state may stay as it is; the pairs below are the only moves.
CREATE FUNCTION public.sync_cursors_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  -- tenant_id is not checked here: moving a row to another tenant is refused by row security first.
  IF NEW.connection_id IS DISTINCT FROM OLD.connection_id OR NEW.partition IS DISTINCT FROM OLD.partition THEN
    RAISE EXCEPTION 'sync_cursors: identity never changes' USING ERRCODE = 'AD403';
  END IF;
  IF NEW.lease_fencing_token < OLD.lease_fencing_token THEN
    RAISE EXCEPTION 'sync_cursors: the fencing token never moves back' USING ERRCODE = 'AD403';
  END IF;
  IF OLD.last_full_sync_at IS NOT NULL AND (NEW.last_full_sync_at IS NULL OR NEW.last_full_sync_at < OLD.last_full_sync_at) THEN
    RAISE EXCEPTION 'sync_cursors: last_full_sync_at is never cleared or moved back' USING ERRCODE = 'AD403';
  END IF;
  IF OLD.last_change_at IS NOT NULL AND (NEW.last_change_at IS NULL OR NEW.last_change_at < OLD.last_change_at) THEN
    RAISE EXCEPTION 'sync_cursors: last_change_at is never cleared or moved back' USING ERRCODE = 'AD403';
  END IF;
  IF NEW.state IS DISTINCT FROM OLD.state AND NOT (
       (OLD.state = 'initial_sync'    AND NEW.state IN ('incremental', 'paused'))
    OR (OLD.state = 'incremental'     AND NEW.state IN ('resync_required', 'paused'))
    OR (OLD.state = 'resync_required' AND NEW.state IN ('incremental', 'paused'))
    OR (OLD.state = 'paused'          AND NEW.state = 'resync_required')) THEN
    RAISE EXCEPTION 'sync_cursors: % to % is not a legal transition', OLD.state, NEW.state USING ERRCODE = 'AD403';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER sync_cursors_guard BEFORE UPDATE ON public.sync_cursors
  FOR EACH ROW EXECUTE FUNCTION public.sync_cursors_guard();

ALTER TABLE public.sync_cursors ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sync_cursors FORCE ROW LEVEL SECURITY;
CREATE POLICY sync_cursors_tenant ON public.sync_cursors
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

REVOKE DELETE ON public.sync_cursors FROM activediq_app;

COMMENT ON TABLE public.sync_cursors IS 'DM-19 SyncCursor (tenant table, RLS): change-feed position per partition, fenced by the platform lease token. Only internal/directory/sync references it in SQL.';
COMMENT ON COLUMN public.sync_cursors.cookie IS 'Opaque DirSync cookie or Graph delta token. Never parsed, never logged, never listed.';

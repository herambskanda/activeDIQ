-- 0061_inventory_nc_sync_passes: the last successful sync pass of each naming context (T-0949; spec
-- reports-2a D6, reports.md §6.4, row P1). Owner: internal/directory/inventory (DM-14 NamingContext).
--
--  * last_pass_at is the as-of of the newest sync pass that completed for the NC: the start of the read,
--    not its completion, so a report never claims fresher data than it holds. It is NOT the time of the
--    last change (DM-19 last_change_at): a quiet domain has no changes and is still fresh.
--  * state is what the sync last told inventory about the NC's feed: ok (the pass completed),
--    resync_required (DM-19.I3/I4: the cookie is unusable) or paused. A pause that comes from a
--    suspended connection is derived from connections.state at read time, so it needs no write here.
--  * A row can exist before the first pass (state set, last_pass_at NULL): that NC has never synced.
--    ok requires a pass; last_pass_at never moves back or to NULL, whichever writer holds the pen.
--  * Written in the same transaction as the inventory rows the pass covers (DM-19.I1).

CREATE TABLE public.nc_sync_passes (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  connection_id uuid NOT NULL,
  nc_guid uuid NOT NULL,
  last_pass_at timestamptz,
  state text NOT NULL CHECK (state IN ('ok', 'resync_required', 'paused')),
  state_changed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, connection_id, nc_guid),
  FOREIGN KEY (tenant_id, connection_id) REFERENCES public.connections (tenant_id, id),
  CHECK (nc_guid <> '00000000-0000-0000-0000-000000000000'),
  CHECK (state <> 'ok' OR last_pass_at IS NOT NULL)
);

CREATE FUNCTION public.nc_sync_passes_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.connection_id IS DISTINCT FROM OLD.connection_id OR NEW.nc_guid IS DISTINCT FROM OLD.nc_guid THEN
    RAISE EXCEPTION 'nc_sync_passes: identity never changes' USING ERRCODE = 'AD403';
  END IF;
  IF OLD.last_pass_at IS NOT NULL AND (NEW.last_pass_at IS NULL OR NEW.last_pass_at < OLD.last_pass_at) THEN
    RAISE EXCEPTION 'nc_sync_passes: last_pass_at is never cleared or moved back' USING ERRCODE = 'AD403';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER nc_sync_passes_guard BEFORE UPDATE ON public.nc_sync_passes
  FOR EACH ROW EXECUTE FUNCTION public.nc_sync_passes_guard();

ALTER TABLE public.nc_sync_passes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.nc_sync_passes FORCE ROW LEVEL SECURITY;
CREATE POLICY nc_sync_passes_tenant ON public.nc_sync_passes
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

REVOKE DELETE ON public.nc_sync_passes FROM activediq_app;

COMMENT ON TABLE public.nc_sync_passes IS 'DM-14 per-NC last successful sync pass (directory table, RLS). Only internal/directory/inventory references it in SQL.';

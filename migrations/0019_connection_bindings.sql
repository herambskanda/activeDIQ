-- 0019_connection_bindings: DM-13 ConnectorBinding (domain-model DM-13, ADR-0003 F1). Owner:
-- internal/directory/connection (T-0249).
--
-- A binding routes a connection to the connector that serves it. In v1 the only target is the
-- embedded connector; a remote component target is the column shape for T-0167 and is not written yet.
--   DM-13.I1 target and connection share the tenant (composite foreign keys).
--   DM-10.I3 an `active` connection has at least one binding: the activation trigger below refuses a
--            draft|verifying -> active move when no live binding exists. Store.Activate inserts the
--            embedded binding in the same transaction, immediately before the transition.
-- Lifecycle `active <-> disabled -> removed` is state data; removal is a state, never a delete.

CREATE TABLE public.connector_bindings (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  connection_id uuid NOT NULL,
  target text NOT NULL CHECK (target IN ('embedded', 'component')),
  component_id uuid,
  priority integer NOT NULL DEFAULT 0 CHECK (priority >= 0),
  state text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'disabled', 'removed')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, connection_id) REFERENCES public.connections (tenant_id, id),
  FOREIGN KEY (tenant_id, component_id) REFERENCES public.components (tenant_id, id),
  CHECK ((target = 'component') = (component_id IS NOT NULL))
);
-- One embedded binding per connection; remote bindings are unique per component.
CREATE UNIQUE INDEX connector_bindings_embedded ON public.connector_bindings (tenant_id, connection_id)
  WHERE target = 'embedded' AND state <> 'removed';
CREATE UNIQUE INDEX connector_bindings_component ON public.connector_bindings (tenant_id, connection_id, component_id)
  WHERE target = 'component' AND state <> 'removed';
CREATE INDEX connector_bindings_conn ON public.connector_bindings (tenant_id, connection_id, priority, id);

ALTER TABLE public.connector_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.connector_bindings FORCE ROW LEVEL SECURITY;
CREATE POLICY connector_bindings_tenant ON public.connector_bindings
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
REVOKE DELETE ON public.connector_bindings FROM activediq_app;

COMMENT ON TABLE public.connector_bindings IS 'DM-13 ConnectorBinding (tenant table, RLS). Only internal/directory/connection references it in SQL. The binding is data, not configuration (ADR-0002 rule 3).';

-- DM-10.I3 in the database. SECURITY INVOKER with a pinned search_path, as connections_guard.
CREATE FUNCTION public.connections_guard_binding() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $fn$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM public.connector_bindings b
                 WHERE b.tenant_id = NEW.tenant_id AND b.connection_id = NEW.id AND b.state = 'active') THEN
    RAISE EXCEPTION 'connections: an active connection needs a connector binding (DM-10.I3)' USING ERRCODE = 'AD403';
  END IF;
  RETURN NEW;
END
$fn$;

CREATE TRIGGER connections_guard_binding BEFORE UPDATE ON public.connections
  FOR EACH ROW WHEN (OLD.state IN ('draft', 'verifying') AND NEW.state = 'active')
  EXECUTE FUNCTION public.connections_guard_binding();
ALTER TABLE public.connections ENABLE ALWAYS TRIGGER connections_guard_binding;

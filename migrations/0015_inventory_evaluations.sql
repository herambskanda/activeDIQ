-- 0015_inventory_evaluations: when the correlation job last finished evaluating a connection
-- (connector-contract §8.3 F3, T-0378). Owner: internal/directory/inventory.
--
-- An object with no correlation has no row to carry a time, yet "this object has no peers" is a
-- fact with an as-of: the statement's computed_at is the minimum of the correlation evaluation's
-- time and the tier0 facts' times. One row per connection: the as-of of the last COMPLETED
-- evaluation run covering every object of that connection. It only moves forward.

CREATE TABLE public.correlation_evaluations (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  connection_id uuid NOT NULL,
  evaluated_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, connection_id),
  FOREIGN KEY (tenant_id, connection_id) REFERENCES public.connections (tenant_id, id)
);

ALTER TABLE public.correlation_evaluations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.correlation_evaluations FORCE ROW LEVEL SECURITY;
CREATE POLICY correlation_evaluations_tenant ON public.correlation_evaluations
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

-- A run's time is history that tier0 protection leans on; the runtime role cannot delete it.
REVOKE DELETE ON public.correlation_evaluations FROM activediq_app;

COMMENT ON TABLE public.correlation_evaluations IS 'Per-connection as-of of the last completed correlation evaluation (directory table, RLS). Only internal/directory/inventory references it in SQL.';

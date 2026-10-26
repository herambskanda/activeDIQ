-- 0014_connection_c13_pins: the C13 group pins (TM-D26 rule 10). Owner: internal/directory/connection.
--
-- DnsAdmins and the Exchange groups have no well-known RID, so the classifier keeps them by
-- objectGUID, pinned at first discovery, and passes the pins on every Classify. A renamed group stays
-- Tier 0 only while its pin survives, so pins are append-only: no UPDATE, no DELETE for the app role.

CREATE TABLE public.connection_c13_pins (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  connection_id uuid NOT NULL,
  -- objectGUID of the group, canonical lower-case UUID text.
  group_guid text NOT NULL CHECK (group_guid ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
  pinned_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, connection_id, group_guid),
  FOREIGN KEY (tenant_id, connection_id) REFERENCES public.connections (tenant_id, id)
);

ALTER TABLE public.connection_c13_pins ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.connection_c13_pins FORCE ROW LEVEL SECURITY;
CREATE POLICY connection_c13_pins_tenant ON public.connection_c13_pins
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

REVOKE UPDATE, DELETE ON public.connection_c13_pins FROM activediq_app;

-- 0050_invhost_servers: admin-registered servers (safe-primitives §6.3 InventoryHost, T-0584).
-- Owner: internal/directory/invhost.
--
-- A file server (home folders, ADM-023) or any non-DC host we may connect to is a row here, put there by an
-- audited admin action. Nothing read from the directory (homeDirectory, dNSHostName, gPCFileSysPath) is ever
-- inserted by code; the only writer is invhost.Service.Register. The name is stored lower-case, with no
-- trailing dot (the same normalisation the Go side applies), and is unique per tenant.

-- write-class: inventory_servers config
CREATE TABLE public.inventory_servers (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  fqdn text NOT NULL CHECK (char_length(fqdn) BETWEEN 3 AND 253 AND fqdn = lower(fqdn) AND fqdn ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$'),
  registered_by text NOT NULL CHECK (char_length(registered_by) BETWEEN 1 AND 200),
  registered_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, fqdn)
);

ALTER TABLE public.inventory_servers ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.inventory_servers FORCE ROW LEVEL SECURITY;
CREATE POLICY inventory_servers_tenant ON public.inventory_servers
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

-- A registration is never edited. Unregistering is a later, audited action and is not built here.
REVOKE UPDATE, DELETE ON public.inventory_servers FROM activediq_app;

COMMENT ON TABLE public.inventory_servers IS 'Admin-registered servers (InventoryHost, safe-primitives 6.3). Tenant table, RLS; no UPDATE or DELETE. Only internal/directory/invhost references it in SQL.';

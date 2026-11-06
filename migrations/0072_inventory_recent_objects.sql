-- 0072_inventory_recent_objects: the objects an account opened recently (T-1130, ADR-0011 rule 8, IA 5.1/5.3).
-- Owner: internal/directory/inventory, the only code that writes it; only the reportsql search template
-- reads it (the empty palette, and the rank step after exact).
--
--  * One row per (account, object), keyed by (connection_id, object_guid), never a DN. opened_at is the last
--    time the account opened the object page; opening it again moves it to the front.
--  * Bounded: the writer keeps the newest 20 rows per account in the same transaction as the upsert.
--  * Not a permission: a row says "this account looked at it once". Every read trims by the account's
--    current ReadScope in the same statement, so an object that has left the scope is never listed.
--  * Deleting the object (or the account's row going, which it never does) takes the recents with it.
--
-- The runtime role keeps DELETE: the trim removes the oldest rows.

-- write-class: inventory_recent_objects system
CREATE TABLE public.inventory_recent_objects (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  account_id uuid NOT NULL,
  connection_id uuid NOT NULL,
  object_guid uuid NOT NULL,
  opened_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, account_id, connection_id, object_guid),
  FOREIGN KEY (tenant_id, account_id) REFERENCES public.authn_accounts (tenant_id, id),
  FOREIGN KEY (tenant_id, connection_id, object_guid) REFERENCES public.directory_objects (tenant_id, connection_id, object_guid) ON DELETE CASCADE
);

CREATE INDEX inventory_recent_objects_by_account ON public.inventory_recent_objects (tenant_id, account_id, opened_at DESC);
-- The cascade from directory_objects finds its rows by object.
CREATE INDEX inventory_recent_objects_by_object ON public.inventory_recent_objects (tenant_id, connection_id, object_guid);

ALTER TABLE public.inventory_recent_objects ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.inventory_recent_objects FORCE ROW LEVEL SECURITY;
CREATE POLICY inventory_recent_objects_tenant ON public.inventory_recent_objects
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

COMMENT ON TABLE public.inventory_recent_objects IS 'Objects an account opened recently, newest 20 per account (directory table, RLS, derived). Written by internal/directory/inventory; read only by the reportsql search template, always trimmed by the account''s current ReadScope.';

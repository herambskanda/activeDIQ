-- 0004_connection_connections: DM-10 Connection (domain-model DM-10, ADR-0003 F1). Owner:
-- internal/directory/connection.
--
-- A connection is one managed directory: an AD forest or an Entra tenant. This is the first
-- tenant-scoped table, so it also sets the pattern: tenant_id first in every key, a foreign key to
-- tenants, and one FORCE ROW LEVEL SECURITY policy of the canonical fail-closed shape.
--
-- This migration holds the lifecycle columns and the invariants the database can state itself:
--   I1  directory_identity never changes once set (trigger below).
--   I2  (kind, directory_identity) is unique per tenant among connections that are neither
--       discarded nor removed (partial unique index; it is what makes the V5 duplicate check race-free).
--   I13 retired_at is set on entering decommissioning or discarded, and never otherwise.
-- The legal transitions are a declared table in Go (internal/directory/connection); the store
-- changes state only with a compare-and-set on the previous state.
--
-- credential_id names a DM-11 row. DM-11 lands with the credential port, so there is no foreign key
-- yet; the secret material never touches this table. Later attributes (deletion settings, DC
-- affinity, sync attribute set, takeover attestation, last_verification_id's DM-24 foreign key)
-- arrive with the tickets that write them.

-- write-class: connections config
CREATE TABLE public.connections (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  kind text NOT NULL CHECK (kind IN ('ad_forest', 'entra_tenant')),
  display_name text NOT NULL CHECK (display_name <> '' AND length(display_name) <= 200),
  -- AD: objectGUID of the forest root domain NC. Entra: the tenant ID. Empty until the V5 identity
  -- check of a verification sets it. Canonical lower-case UUID text.
  directory_identity text NOT NULL DEFAULT ''
    CHECK (directory_identity = '' OR directory_identity ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
  credential_id uuid NOT NULL,
  state text NOT NULL DEFAULT 'draft'
    CHECK (state IN ('draft', 'verifying', 'active', 'suspended', 'decommissioning', 'removed', 'discarded')),
  last_verification_id uuid,
  verified_at timestamptz,
  retired_at timestamptz,
  last_stamp_at timestamptz,
  -- AD only (I4: the floor is TLS either way, so the choice is only the mechanism).
  transport_security text CHECK (transport_security IN ('ldaps', 'starttls')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  CHECK ((kind = 'ad_forest') = (transport_security IS NOT NULL)),
  -- A connection that was ever verified into use has an identity (I1, V5).
  CHECK (state IN ('draft', 'verifying', 'discarded') OR directory_identity <> ''),
  -- I13: retired_at is written on entering decommissioning or discarded and kept after.
  CHECK ((state IN ('decommissioning', 'removed', 'discarded')) = (retired_at IS NOT NULL)),
  CHECK (retired_at IS NULL OR last_stamp_at IS NOT NULL)
);

-- I2. Discarded and removed connections do not hold their identity, so the forest can be connected again.
CREATE UNIQUE INDEX connections_live_identity ON public.connections (tenant_id, kind, directory_identity)
  WHERE directory_identity <> '' AND state NOT IN ('discarded', 'removed');
CREATE INDEX connections_tenant_state ON public.connections (tenant_id, state, created_at, id);

ALTER TABLE public.connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.connections FORCE ROW LEVEL SECURITY;
CREATE POLICY connections_tenant ON public.connections
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

-- Removal is a state, never a delete (DM-10 L9, I5): audit and verification references must keep
-- resolving, and a delete would free the I2 identity without passing through decommissioning.
REVOKE DELETE ON public.connections FROM activediq_app;

COMMENT ON TABLE public.connections IS 'DM-10 Connection (tenant table, RLS). Only internal/directory/connection references it in SQL. Never holds secret material: credential_id names a DM-11 row.';

-- connections_guard backs up the Go store for the invariants that must hold whatever writes the row.
-- SECURITY INVOKER with a pinned search_path, as jobs_guard.
CREATE FUNCTION public.connections_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $fn$
BEGIN
  -- tenant_id is guarded by the row-level-security WITH CHECK, which must be what refuses a move
  -- to another tenant (fitness-tenancy T4), so it is not repeated here.
  IF NEW.id IS DISTINCT FROM OLD.id OR NEW.kind IS DISTINCT FROM OLD.kind THEN
    RAISE EXCEPTION 'connections: id and kind never change' USING ERRCODE = 'AD403';
  END IF;
  -- I1.
  IF OLD.directory_identity <> '' AND NEW.directory_identity IS DISTINCT FROM OLD.directory_identity THEN
    RAISE EXCEPTION 'connections: directory_identity is fixed once set (DM-10.I1)' USING ERRCODE = 'AD403';
  END IF;
  -- I13: retired_at is written once and last_stamp_at only rises.
  IF OLD.retired_at IS NOT NULL AND NEW.retired_at IS DISTINCT FROM OLD.retired_at THEN
    RAISE EXCEPTION 'connections: retired_at is written once (DM-10.I13)' USING ERRCODE = 'AD403';
  END IF;
  IF OLD.last_stamp_at IS NOT NULL AND (NEW.last_stamp_at IS NULL OR NEW.last_stamp_at <= OLD.last_stamp_at)
     AND NEW.last_stamp_at IS DISTINCT FROM OLD.last_stamp_at THEN
    RAISE EXCEPTION 'connections: last_stamp_at only rises (DM-10.I13)' USING ERRCODE = 'AD403';
  END IF;
  -- The DM-10 lifecycle. This list is the SQL twin of edges in internal/directory/connection/transitions.go;
  -- TestMigrationEdgesMatchTheGoTable fails if the two drift. Terminal states have no outgoing edge.
  IF NEW.state IS DISTINCT FROM OLD.state AND (OLD.state, NEW.state) NOT IN (
    ('draft', 'verifying'),
    ('verifying', 'draft'),
    ('draft', 'active'),
    ('verifying', 'active'),
    ('active', 'suspended'),
    ('suspended', 'active'),
    ('active', 'decommissioning'),
    ('suspended', 'decommissioning'),
    ('decommissioning', 'removed'),
    ('draft', 'discarded')
  ) THEN
    RAISE EXCEPTION 'connections: % -> % is not a DM-10 transition', OLD.state, NEW.state USING ERRCODE = 'AD403';
  END IF;
  RETURN NEW;
END
$fn$;

CREATE TRIGGER connections_guard BEFORE UPDATE ON public.connections
  FOR EACH ROW EXECUTE FUNCTION public.connections_guard();
ALTER TABLE public.connections ENABLE ALWAYS TRIGGER connections_guard;

-- Creation is the only way into the lifecycle (DM-10 L1): a row is born draft, unverified, with no
-- identity, so no writer can insert a connection past the V5 identity check or the activation gate.
CREATE FUNCTION public.connections_guard_insert() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $fn$
BEGIN
  IF NEW.state <> 'draft' OR NEW.directory_identity <> ''
     OR NEW.last_verification_id IS NOT NULL OR NEW.verified_at IS NOT NULL
     OR NEW.retired_at IS NOT NULL OR NEW.last_stamp_at IS NOT NULL THEN
    RAISE EXCEPTION 'connections: a connection is created draft and unverified (DM-10 L1)' USING ERRCODE = 'AD403';
  END IF;
  RETURN NEW;
END
$fn$;

CREATE TRIGGER connections_guard_insert BEFORE INSERT ON public.connections
  FOR EACH ROW EXECUTE FUNCTION public.connections_guard_insert();
ALTER TABLE public.connections ENABLE ALWAYS TRIGGER connections_guard_insert;

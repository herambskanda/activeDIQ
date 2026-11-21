-- T-2195: DB-side synthetic user candidates for the large per-DC read calibration (T-1500, USR-04).
-- LAB / CI ONLY. Never part of a migration, never shipped, never run against a customer database.
--
-- Installs lab_synth.load_users(), which bulk-inserts n synthetic 'user' rows into public.directory_objects with
-- generate_series (no directory round trip; 500k rows take seconds). The rows are fake by construction:
-- sam 'synth<seed>-<i>', upn @lab.activediq.test, dn under OU=Synthetic,<nc dn>. Object GUIDs are derived from
-- (seed, i) so a rerun with the same arguments inserts nothing new (idempotent) and the set is reproducible.
-- They exist only in Postgres; the lab DC does not know them. Reading them from a DC needs the bufconn
-- connector with a fixed per-read latency (runbook: knowledge/development/runbooks/ad-lab.md, "Large tier").
--
-- Run as the table owner (RLS is FORCEd; the function sets app.tenant_id for its own transaction).
-- The tenant and the connection must already exist (directory_objects has a foreign key to connections).
CREATE SCHEMA IF NOT EXISTS lab_synth;

CREATE OR REPLACE FUNCTION lab_synth.load_users(p_tenant uuid, p_connection uuid, p_nc uuid, p_n bigint,
                                                p_seed text DEFAULT 'a', p_nc_dn text DEFAULT 'DC=lab,DC=activediq,DC=test')
RETURNS bigint LANGUAGE plpgsql AS $$
DECLARE
  inserted bigint;
BEGIN
  IF p_n < 1 THEN RAISE EXCEPTION 'lab_synth.load_users: n must be >= 1'; END IF;
  IF p_seed !~ '^[a-z0-9]{1,16}$' THEN RAISE EXCEPTION 'lab_synth.load_users: seed must match [a-z0-9]{1,16}'; END IF;
  PERFORM set_config('app.tenant_id', p_tenant::text, true);
  INSERT INTO public.directory_objects
    (tenant_id, connection_id, object_guid, nc_guid, kind, object_class, parent_guid, ancestry, ancestry_complete,
     dn, rdn, sam_account_name, upn, display_name, enabled, pwd_last_set, when_created, when_changed, observed_at, observed_dsa)
  SELECT p_tenant, p_connection,
         md5('activediq-lab-synth/' || p_seed || '/' || g)::uuid,
         p_nc, 'user', 'user', p_nc, ARRAY[p_nc], true,
         'CN=Synth ' || p_seed || ' ' || g || ',OU=Synthetic,' || p_nc_dn, 'CN=Synth ' || p_seed || ' ' || g,
         'synth' || p_seed || '-' || g, 'synth' || p_seed || '-' || g || '@lab.activediq.test',
         'Synth ' || p_seed || ' ' || g,
         (g % 25) <> 0,                                             -- 4% disabled
         timestamptz '2026-01-01 00:00:00+00' - ((g % 400) || ' days')::interval,
         timestamptz '2025-01-01 00:00:00+00', timestamptz '2026-01-01 00:00:00+00', now(), 'lab-synthetic'
  FROM generate_series(1, p_n) AS g
  ON CONFLICT (tenant_id, connection_id, object_guid) DO NOTHING;
  GET DIAGNOSTICS inserted = ROW_COUNT;
  RETURN inserted;
END $$;

COMMENT ON FUNCTION lab_synth.load_users IS 'Lab/CI only (T-2195): synthetic user candidates for per-DC read calibration. Not a migration.';

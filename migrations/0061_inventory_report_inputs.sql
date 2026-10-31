-- 0061_inventory_report_inputs: the inputs of the derived states in inventory.users and
-- inventory.computers (T-0958; reports.md §3.3, spec reports-2a §6.4, D4 and D7). Owner:
-- internal/directory/inventory.
--
--  * directory_objects gains the typed D7 inputs: user_account_control (NULL = not read),
--    primary_group_id, last_logon_timestamp, spn_present (NULL = not read) and inputs_read, a bitmask of
--    which time inputs the sync actually read (1 lockoutTime, 2 pwdLastSet, 4 accountExpires,
--    8 lastLogonTimestamp). A time input is NULL both when the attribute is absent or zero ("not
--    locked", "must change", "never") and when it was not read; only the bit tells them apart, so a
--    row written before this migration (bits 0) is "unknown", never "not locked" (FR-09).
--  * inventory_domain_policies: the domain password and lockout policy per naming context (D4).
--    max_pwd_age_secs 0 = passwords never expire; lockout_duration_secs 0 = locked until an admin
--    unlocks; NULL = not read. psos_read_at says the PSO set of the domain was read: without it a
--    report cannot know no PSO applies and the state is unknown (never a fall back to the domain).
--  * inventory_psos / inventory_pso_applies: Password Settings Objects and msDS-PSOAppliesTo (D4). The
--    effective policy of a user is resolved in the report query from these rows, so a PSO edit or a
--    group change shows without any write to the user (AC-14). Rows are marked removed, never deleted.
--  * directory_objects_by_ancestry: GIN index serving the descendant walk (`ancestry @>`) of the
--    move rewrite and the scope renderer.

ALTER TABLE public.directory_objects
  ADD COLUMN user_account_control bigint CHECK (user_account_control IS NULL OR user_account_control BETWEEN 0 AND 4294967295),
  ADD COLUMN primary_group_id bigint CHECK (primary_group_id IS NULL OR primary_group_id BETWEEN 0 AND 4294967295),
  ADD COLUMN last_logon_timestamp timestamptz,
  ADD COLUMN spn_present boolean,
  ADD COLUMN inputs_read smallint NOT NULL DEFAULT 0 CHECK (inputs_read BETWEEN 0 AND 15);

CREATE INDEX directory_objects_by_ancestry ON public.directory_objects USING gin (ancestry);

-- write-class: inventory_domain_policies system
CREATE TABLE public.inventory_domain_policies (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  connection_id uuid NOT NULL,
  nc_guid uuid NOT NULL,
  max_pwd_age_secs bigint CHECK (max_pwd_age_secs IS NULL OR max_pwd_age_secs >= 0),
  lockout_duration_secs bigint CHECK (lockout_duration_secs IS NULL OR lockout_duration_secs >= 0),
  logon_sync_interval_days integer CHECK (logon_sync_interval_days IS NULL OR logon_sync_interval_days BETWEEN 0 AND 3650),
  psos_read_at timestamptz,
  observed_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, connection_id, nc_guid),
  FOREIGN KEY (tenant_id, connection_id) REFERENCES public.connections (tenant_id, id)
);

-- write-class: inventory_psos system
CREATE TABLE public.inventory_psos (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  connection_id uuid NOT NULL,
  pso_guid uuid NOT NULL,
  nc_guid uuid NOT NULL,
  precedence bigint CHECK (precedence IS NULL OR precedence >= 1),
  max_pwd_age_secs bigint CHECK (max_pwd_age_secs IS NULL OR max_pwd_age_secs >= 0),
  lockout_duration_secs bigint CHECK (lockout_duration_secs IS NULL OR lockout_duration_secs >= 0),
  observed_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, connection_id, pso_guid),
  FOREIGN KEY (tenant_id, connection_id) REFERENCES public.connections (tenant_id, id)
);

-- write-class: inventory_pso_applies system
CREATE TABLE public.inventory_pso_applies (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  connection_id uuid NOT NULL,
  pso_guid uuid NOT NULL,
  target_guid uuid NOT NULL,
  state text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'removed')),
  observed_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, connection_id, pso_guid, target_guid),
  FOREIGN KEY (tenant_id, connection_id) REFERENCES public.connections (tenant_id, id)
);
CREATE INDEX inventory_pso_applies_by_target ON public.inventory_pso_applies (tenant_id, connection_id, target_guid) WHERE state = 'active';

REVOKE DELETE ON public.inventory_psos, public.inventory_pso_applies FROM activediq_app;

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['inventory_domain_policies', 'inventory_psos', 'inventory_pso_applies'] LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY %I ON public.%I USING (tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid) WITH CHECK (tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid)', t || '_tenant', t);
  END LOOP;
END $$;

COMMENT ON TABLE public.inventory_domain_policies IS 'D4 domain password and lockout policy per naming context (directory table, RLS). Only internal/directory/inventory references it in SQL.';
COMMENT ON TABLE public.inventory_psos IS 'D4 Password Settings Object values (directory table, RLS). Only internal/directory/inventory references it in SQL.';
COMMENT ON TABLE public.inventory_pso_applies IS 'D4 msDS-PSOAppliesTo edges, PSO to user or group (directory table, RLS). Only internal/directory/inventory references it in SQL.';

-- 0042_inventory_entra_hybrid_inputs: the Entra-side facts the DM-20.I4 gate reads, stored as the
-- sync cycle saw them (T-0326). Owner: internal/directory/inventory.
--
-- The gate runs again whenever the AD side, the link or the attestation changes, not only when the
-- Entra object is re-read, so its Entra inputs must be in the inventory and not only in the cycle's
-- memory. Entra users and groups only (nc_guid IS NULL); NULL means "not observed" and the gate
-- treats it as a failed check, never a pass.
--   on_prem_sync_enabled      onPremisesSyncEnabled (I4(a)); NULL is null.
--   on_prem_cloud_managed     onPremisesSyncBehavior.isCloudManaged (I4(b)).
--   on_prem_sid               onPremisesSecurityIdentifier, binary (I4(c)).
--   on_prem_domain_name       onPremisesDomainName (I4(d)); '' when not populated.
--   on_prem_immutable_id      onPremisesImmutableId decoded: the 16-byte anchor (I1a), LDAP wire order.

ALTER TABLE public.directory_objects
  ADD COLUMN on_prem_sync_enabled boolean,
  ADD COLUMN on_prem_cloud_managed boolean,
  ADD COLUMN on_prem_sid bytea CHECK (on_prem_sid IS NULL OR length(on_prem_sid) BETWEEN 8 AND 68),
  ADD COLUMN on_prem_domain_name text NOT NULL DEFAULT '' CHECK (length(on_prem_domain_name) <= 255),
  ADD COLUMN on_prem_immutable_id bytea CHECK (on_prem_immutable_id IS NULL OR length(on_prem_immutable_id) BETWEEN 1 AND 64),
  ADD CONSTRAINT directory_objects_on_prem_entra_only CHECK (nc_guid IS NULL OR
    (on_prem_sync_enabled IS NULL AND on_prem_cloud_managed IS NULL AND on_prem_sid IS NULL
     AND on_prem_domain_name = '' AND on_prem_immutable_id IS NULL));

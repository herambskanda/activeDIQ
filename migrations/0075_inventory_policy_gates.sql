-- 0075_inventory_policy_gates: two more inputs of the effective-policy resolution (T-1134; T-1016 lab rows
-- LAB-PS-10 and LAB-PS-13; domain-model DM-16 "Report-engine inputs"). Owner: internal/directory/inventory.
--
--  * inventory_domain_policies.functional_level: msDS-Behavior-Version of the domain head (NULL = not read).
--    Below 3 (Windows Server 2008) a PSO has no effect, so the domain policy applies. NULL fails closed:
--    the policy-dependent states are Unknown (domain_level_not_read), never a PSO the DC may ignore.
--  * directory_objects.rodc_krbtgt: msDS-SecondaryKrbTgtNumber has a value (the RODC krbtgt_nnnnn account;
--    NULL = not read). The value itself is not stored.

ALTER TABLE public.inventory_domain_policies
  ADD COLUMN functional_level smallint CHECK (functional_level IS NULL OR functional_level BETWEEN 0 AND 10);

ALTER TABLE public.directory_objects
  ADD COLUMN rodc_krbtgt boolean;

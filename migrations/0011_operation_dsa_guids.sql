-- The DSA GUID (NTDS Settings objectGUID, canonical text) of the DC pinned per naming context, beside
-- `pins` (host). It is what the connector's DcSelection.pinned_dsa_guid carries (ADR-0005 rule 5).
-- Not part of the plan hash, like `pins`. Forward-only; existing rows get {} and are re-pinned on re-plan.
ALTER TABLE public.operations
  ADD COLUMN dsa_guids jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(dsa_guids) = 'object');

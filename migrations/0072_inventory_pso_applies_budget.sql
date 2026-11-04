-- 0072_inventory_pso_applies_budget: row budget of inventory_pso_applies (T-1528; threat-model §5.4a, TM-D32).
-- Owner: internal/directory/inventory.
--
--  * applies_count: the active msDS-PSOAppliesTo rows stored for the PSO, kept by PolicyWriter so a write
--    needs no scan (the decision work stays O(1) per value).
--  * applies_over_budget: the PSO named more targets than the per-PSO or per-connection cap; the rows past the
--    cap were not stored. The users dataset reads it and answers Unknown (pso_applies_over_budget) for every
--    account of the PSO's naming context, never a fall back to the domain policy.
-- Existing rows: no edge rows exist outside tests (no connector writes them yet), so 0 is exact.

ALTER TABLE public.inventory_psos
  ADD COLUMN applies_count integer NOT NULL DEFAULT 0 CHECK (applies_count >= 0),
  ADD COLUMN applies_over_budget boolean NOT NULL DEFAULT false;

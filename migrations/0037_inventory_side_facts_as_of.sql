-- 0037_inventory_side_facts_as_of: per-side as-of of a correlation's tier0 facts (T-0480; DM-20.I5,
-- connector-contract §8.3 F3). Owner: internal/directory/inventory.
--
-- facts_as_of vouches for BOTH tier0 facts as the correlation job last computed them. A live read of
-- one object can vouch for that object's fact only, so it moves that side's as-of and nothing else.
-- NULL means "as of facts_as_of". The as-of of the pair is the older of the two sides (LEAST), so a
-- one-sided live read never makes the peer's fact look fresher than it is. The correlation job, which
-- recomputes both facts, resets both to NULL.

ALTER TABLE public.correlations
  ADD COLUMN ad_facts_as_of timestamptz,
  ADD COLUMN entra_facts_as_of timestamptz,
  ADD CONSTRAINT correlations_side_as_of_needs_facts CHECK
    ((ad_facts_as_of IS NULL AND entra_facts_as_of IS NULL) OR facts_as_of IS NOT NULL);

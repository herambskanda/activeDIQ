-- 0059_inventory_ancestry_complete: ancestry_complete on DM-16 rows (T-0948; reports.md §4.5, row P2).
-- Owner: internal/directory/inventory.
--
--  * ancestry_complete says the stored `ancestry` chain (nearest parent first) is known to be the whole,
--    current chain: the parent is the NC head, or the parent row exists, is itself complete, and the
--    chain equals the parent's chain plus the parent. The writer sets it on every observation and
--    repairs it when a parent arrives or an OU moves. A reader that scopes by ancestry (the reports
--    compiler) treats false as out of scope.
--  * Default false: a row written before this column is "unknown" and fails closed. The next
--    observation of the row, or of an ancestor, recomputes it; there is no backfill here because the
--    runtime role is bound by row-level security and a migration has no tenant.
--  * directory_objects_by_parent serves the descendant walk by parent_guid (the move rewrite and the
--    completeness repair); it is not the GIN index on `ancestry`, which is another ticket (B3).

ALTER TABLE public.directory_objects ADD COLUMN ancestry_complete boolean NOT NULL DEFAULT false;

CREATE INDEX directory_objects_by_parent ON public.directory_objects (tenant_id, connection_id, parent_guid)
  WHERE parent_guid IS NOT NULL;

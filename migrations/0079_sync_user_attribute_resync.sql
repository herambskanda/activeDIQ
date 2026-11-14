-- 0079_sync_user_attribute_resync (T-1111; reports-2-second-slice D11): the sync set gained the
-- user-attribute report attributes (msNPAllowDialin, msRTCSIP-UserEnabled, logonHours, scriptPath,
-- telephoneNumber, mobile, manager, and the presence of thumbnailPhoto and jpegPhoto). An incremental
-- feed delivers only what changed, so an object that never changes would never gain them. Every cursor
-- that is incremental therefore goes to resync_required (cookie dropped, the DM-19 transition the sync
-- store itself makes): the next cycle runs a full read that upserts the new keys into the attribute bag.
--
--  * No inventory row is touched here, so existing columns are unchanged and every dataset keeps
--    answering from the stored rows while the resync runs; a full read removes nothing until it completes.
--  * Cursors in initial_sync (no cookie yet, they will read the new set anyway) and paused (resumption
--    already resyncs) are left alone. Re-running the file changes nothing: a resync_required cursor
--    stays as it is.
--  * The attribute bag is JSONB, so no column or table is added.

-- Under FORCE row security with no tenant set the migration owner sees no rows, and an UPDATE would
-- change none without an error. As in 0021, 0047 and 0074, FORCE is lifted for the one statement, inside
-- this migration's single transaction, and put back; the rows are matched by state alone, every tenant's.
ALTER TABLE public.sync_cursors NO FORCE ROW LEVEL SECURITY;

UPDATE public.sync_cursors
   SET state = 'resync_required', cookie = NULL, issuing_dsa_guid = NULL, state_changed_at = now(), updated_at = now()
 WHERE state = 'incremental';

ALTER TABLE public.sync_cursors FORCE ROW LEVEL SECURITY;

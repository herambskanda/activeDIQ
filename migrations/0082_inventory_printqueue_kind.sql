-- 0082_inventory_printqueue_kind (T-1719; reports-2-second-slice 7.2 and D13): published printers.
--
--  * directory_objects.kind and directory_object_changes.object_kind gain 'printqueue'. A printQueue
--    object was stored as 'other' until now; the mapper classifies it from objectClass, so the kind
--    changes on the next full read. No table is added: inventory.printers is a dataset over
--    directory_objects (kind = 'printqueue'), scoped by the same ancestry anchor as every other dataset.
--  * The sync set gained the printQueue attributes. They live in the JSONB attribute bag, so no column is
--    added. An incremental feed delivers only what changed, so every incremental cursor goes to
--    resync_required (cookie dropped, as 0081 did): the next cycle is a full read that reclassifies the
--    printQueue rows and fills the bag. Nothing is deleted before that read completes.
--  * Cursors in initial_sync and paused are left alone, as in 0081.

ALTER TABLE public.directory_objects DROP CONSTRAINT directory_objects_kind_check;
ALTER TABLE public.directory_objects ADD CONSTRAINT directory_objects_kind_check
  CHECK (kind IN ('user', 'inetorgperson', 'group', 'computer', 'contact', 'ou', 'container', 'gmsa', 'fsp', 'printqueue', 'other'));

ALTER TABLE public.directory_object_changes DROP CONSTRAINT directory_object_changes_object_kind_check;
ALTER TABLE public.directory_object_changes ADD CONSTRAINT directory_object_changes_object_kind_check
  CHECK (object_kind IN ('user', 'inetorgperson', 'group', 'computer', 'contact', 'ou', 'container', 'gmsa', 'fsp', 'printqueue', 'other'));

-- As in 0081: under FORCE row security with no tenant set the owner sees no rows, so FORCE is lifted for the
-- one statement inside this migration's transaction and put back.
ALTER TABLE public.sync_cursors NO FORCE ROW LEVEL SECURITY;

UPDATE public.sync_cursors
   SET state = 'resync_required', cookie = NULL, issuing_dsa_guid = NULL, state_changed_at = now(), updated_at = now()
 WHERE state = 'incremental';

ALTER TABLE public.sync_cursors FORCE ROW LEVEL SECURITY;

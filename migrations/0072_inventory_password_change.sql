-- T-1472: the four-valued Cannot Change Password state on inventory.users (reports-2-second-slice
-- §4.2 rule 1, D15). The sync computes it from the DACL read path (sd.ClassifyPasswordChange) and
-- stores the classified state with the time of the read. Descriptor bytes are never stored.
--
--  * password_change_state: blocked | blocked_one_ace | no_deny_ace | not_confirmed. NULL means the
--    sync did not attempt a read for this row; the dataset reports it as not_confirmed too, never
--    as no_deny_ace.
--  * password_change_at: when the descriptor was read ("Descriptor as of"). NULL exactly when the
--    state is NULL.
ALTER TABLE public.directory_objects
  ADD COLUMN password_change_state text CHECK (password_change_state IS NULL OR
    password_change_state IN ('blocked', 'blocked_one_ace', 'no_deny_ace', 'not_confirmed')),
  ADD COLUMN password_change_at timestamptz,
  ADD CONSTRAINT directory_objects_password_change_pair CHECK ((password_change_state IS NULL) = (password_change_at IS NULL));

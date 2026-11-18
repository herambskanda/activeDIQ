-- 0083_operation_steps_credential_id: the DM-11 credential a directory-write step was transported by (T-1629).
-- Owner: internal/platform/operation.
--
-- The runner resolves the connection's credential once, at claim time and BEFORE the write, and stores its
-- id here. Recording, the reconciler and the deferred read-back read this column and never look the
-- credential up again, so (a) a lookup that fails after the DC write cannot leave the write unaudited and
-- (b) a credential rotated between the write and a later verification cannot be misattributed in the
-- tamper-evident event. The id is metadata only: never the bind account name or SID (T-1601 section 5).
-- '' = not a directory-write step, or the step has not been claimed yet.

ALTER TABLE public.operation_steps ADD COLUMN credential_id text NOT NULL DEFAULT '';

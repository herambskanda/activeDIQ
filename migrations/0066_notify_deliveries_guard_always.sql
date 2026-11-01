-- T-1089: the notify_deliveries identity/finality guard (0062) fires in every session, including one running with
-- session_replication_role = replica, like the other row guards of this schema (authn_pending_signins,
-- update_verifier_floor, ...). Until now it fired only for origin sessions, and as an ordinary BEFORE UPDATE trigger it
-- ran ahead of the row-security check, so the T4 cross-tenant re-assign probe saw the trigger's refusal instead of the
-- policy's. ENABLE ALWAYS is what the T4 harness recognises: it switches such guards off on its throwaway database for
-- the probe run and restores them exactly. Nothing else changes: same function, same trigger, same table.
ALTER TABLE public.notify_deliveries ENABLE ALWAYS TRIGGER notify_deliveries_guard;

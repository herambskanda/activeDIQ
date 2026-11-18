-- 0087_audit_event_at_index: time-range search of the audit chain (T-2300, listAuditEvents). Owner: internal/platform/audit.
--
-- The admin read filters by a time window. Without this index the window is a scan of the tenant's whole
-- chain. The index adds no column and no privilege: audit_event stays add-only for the runtime role (0008 I2).

CREATE INDEX audit_event_tenant_at ON public.audit_event (tenant_id, at, seq);

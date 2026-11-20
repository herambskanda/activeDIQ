-- T-2230: authz_assignment_templates and authz_assignment_sites (0080) were created without the
-- tenant_id -> tenants(id) foreign key that ADR-0002 requires of every tenant table (fitness-tenancy
-- T2 tenant-fk), as 0029 did for their siblings. State the rule on the tables themselves.
--
-- Forward-only and safe on a populated database: every row was written under a tenant context whose
-- tenant_id exists in tenants, and the composite FK to authz_assignments already pins it.
ALTER TABLE public.authz_assignment_templates ADD CONSTRAINT authz_assignment_templates_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants (id);
ALTER TABLE public.authz_assignment_sites     ADD CONSTRAINT authz_assignment_sites_tenant_id_fkey     FOREIGN KEY (tenant_id) REFERENCES public.tenants (id);

-- T-0414: six tenant tables were created without the tenant_id -> tenants(id) foreign key that
-- ADR-0002 requires of every tenant table (fitness-tenancy T2 tenant-fk). Their composite foreign keys
-- to a parent already pin tenant_id to the parent's tenant, but only the root tables reference
-- tenants, so a child row could name a tenant that does not exist if its parent were ever deleted
-- under a replica role. State the rule on the table itself.
--
-- Forward-only and safe on a populated database: every existing row was written under a tenant context
-- whose tenant_id exists in tenants, so validation cannot fail on real data.
ALTER TABLE public.authz_assignment_roots  ADD CONSTRAINT authz_assignment_roots_tenant_id_fkey  FOREIGN KEY (tenant_id) REFERENCES public.tenants (id);
ALTER TABLE public.authz_assignments       ADD CONSTRAINT authz_assignments_tenant_id_fkey       FOREIGN KEY (tenant_id) REFERENCES public.tenants (id);
ALTER TABLE public.authz_role_permissions  ADD CONSTRAINT authz_role_permissions_tenant_id_fkey  FOREIGN KEY (tenant_id) REFERENCES public.tenants (id);
ALTER TABLE public.operation_items         ADD CONSTRAINT operation_items_tenant_id_fkey         FOREIGN KEY (tenant_id) REFERENCES public.tenants (id);
ALTER TABLE public.operation_secrets       ADD CONSTRAINT operation_secrets_tenant_id_fkey       FOREIGN KEY (tenant_id) REFERENCES public.tenants (id);
ALTER TABLE public.operation_steps         ADD CONSTRAINT operation_steps_tenant_id_fkey         FOREIGN KEY (tenant_id) REFERENCES public.tenants (id);

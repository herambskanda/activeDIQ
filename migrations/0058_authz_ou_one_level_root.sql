-- 0058_authz_ou_one_level_root: the ou_one_level assignment root kind (T-0881; DM-35 root kinds, part 2
-- of T-0872). Owner: internal/platform/rbac.
--
--   * root_kind 'ou_one_level' reaches the direct children of an OU and nothing else: not the OU itself,
--     not a deeper descendant. rbac and authz match it on the target's nearest parent only.
--   * It is an include root only, and its GUID is an OU's, never the connection's. An exclude of "the children of an OU" is not a v1 shape, and a reader
--     that took it for a subtree would widen the exclusion in the grant-containment check.
--   * The tenant-root rule from 0037 (root_kind 'tenant': root_guid = connection_id = tenant_id, never an
--     exclude) is unchanged.
-- Widening the CHECK only admits one more value; no existing row changes.

ALTER TABLE public.authz_assignment_roots DROP CONSTRAINT authz_assignment_roots_root_kind_check;
ALTER TABLE public.authz_assignment_roots ADD CONSTRAINT authz_assignment_roots_root_kind_check
  CHECK (root_kind IN ('naming_context', 'ou_subtree', 'ou_one_level', 'entra_tenant', 'tier0_scope', 'tenant'));
ALTER TABLE public.authz_assignment_roots ADD CONSTRAINT authz_assignment_roots_one_level_include
  CHECK (root_kind <> 'ou_one_level' OR NOT is_exclude);
-- An OU's GUID is never its connection's: the target chain ends in the connection, so a one-level root
-- carrying it could be matched as the "parent" of a parentless object.
ALTER TABLE public.authz_assignment_roots ADD CONSTRAINT authz_assignment_roots_one_level_ou
  CHECK (root_kind <> 'ou_one_level' OR root_guid <> connection_id);

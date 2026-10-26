-- T-0289 (TM-D24 A1, TM-TB12-T16): the component kind is the module, so the certificate SAN can pick
-- the bound contract. 'agent' was one kind for every agent module and could bind only one contract.
-- The vocabulary is now connector, addc, fileserver. 'agent' stays in the CHECK only so rows enrolled
-- before this change remain updatable (revocation); issuance and IdentityOf refuse it, so such a
-- certificate opens no tunnel. Forward-only: kind is immutable (trigger in 0006), so no row is rewritten.
ALTER TABLE public.components DROP CONSTRAINT components_kind_check;
ALTER TABLE public.components ADD CONSTRAINT components_kind_check
  CHECK (kind IN ('connector', 'addc', 'fileserver', 'agent'));

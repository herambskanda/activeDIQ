-- 0045_authn_saml_replay_policy_shape (T-0532): bring authn_saml_replay's policies to the tenancy fitness
-- shape (ADR-0002 Fitness function, T2). Owner: internal/platform/authn (sso/saml).
--
-- 0044 gave the table three permissive per-command policies, the DELETE one also testing expires_at. T2
-- requires every permissive policy to be exactly the fail-closed tenant predicate and one of them to be
-- FOR ALL with USING and WITH CHECK. The "delete only expired rows" rule is a narrowing, so it moves to a
-- RESTRICTIVE policy, which is ANDed with the permissive one and so cannot widen access.
--
-- Effect is unchanged for the runtime role: SELECT and INSERT stay tenant-scoped, DELETE stays tenant-scoped
-- and expired-only. UPDATE and TRUNCATE stay revoked (0044), so the FOR ALL policy grants no update.

DROP POLICY authn_saml_replay_select ON public.authn_saml_replay;
DROP POLICY authn_saml_replay_insert ON public.authn_saml_replay;
DROP POLICY authn_saml_replay_delete_expired ON public.authn_saml_replay;

CREATE POLICY authn_saml_replay_tenant ON public.authn_saml_replay AS PERMISSIVE FOR ALL
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

CREATE POLICY authn_saml_replay_delete_expired ON public.authn_saml_replay AS RESTRICTIVE FOR DELETE
  USING (expires_at <= clock_timestamp());

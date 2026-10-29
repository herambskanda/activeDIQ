-- 0009_connection_verifications: DM-24 ConnectionVerification (+ Finding) and DM-25 Tier0Override
-- (domain-model DM-24, DM-25, ADR-0003 F1). Owner: internal/directory/connection.
--
-- A verification is one completed run of a connection's rights checks. It is the evidence behind
-- the activation gate (DM-10.I9), the Tier-0 override (DM-25) and the write gate (DM-10.I11).
-- A Tier0Override is the operator's acknowledgement that activeDIQ may run as Tier 0 despite the
-- over-privilege findings shown (TM-D1).
--
-- Database-stated invariants:
--   DM-24.I1 append-only: no UPDATE, DELETE or TRUNCATE for the runtime role, and a trigger that
--            refuses them for anyone else; findings are inserted with their run.
--   DM-24.I4 (tenant, verification, fingerprint) is unique.
--   DM-24.I3 a finding holds identifiers only: object_guid, object_domain_sid and qualifier are
--            constrained to GUID / SID shapes, so a DN or a name cannot be stored.
--   DM-25.I2 insert-only, the same way. acknowledged_fingerprints is never empty: an override with
--            nothing to acknowledge is meaningless.
--   An override names a verification of the same connection and credential (composite foreign key
--   on the run, check through the insert trigger).
-- Who may acknowledge (platform scope, step-up, typed text) and the 15-minute and last-run rules of
-- DM-25.I1 are the Action's and the store's: this file records the result.

CREATE TABLE public.connection_verifications (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  connection_id uuid NOT NULL,
  credential_id uuid NOT NULL,
  kind text NOT NULL CHECK (kind IN ('onboarding', 'activation', 'resume', 'credential_change', 'scheduled', 'manual')),
  -- Pseudonymous principal ID of the human who requested the run; empty only for a scheduled run.
  requested_by text NOT NULL DEFAULT '' CHECK ((kind = 'scheduled') = (requested_by = '')),
  started_at timestamptz NOT NULL,
  -- The connection's ordering stamp (DM-10.I13) at insert.
  completed_at timestamptz NOT NULL,
  observed_identity text NOT NULL DEFAULT ''
    CHECK (observed_identity = '' OR observed_identity ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
  check_list_version integer NOT NULL CHECK (check_list_version > 0),
  -- check name -> pass | warn | fail | could_not_verify | not_run
  outcomes jsonb NOT NULL CHECK (jsonb_typeof(outcomes) = 'object'),
  verdict text NOT NULL CHECK (verdict IN ('pass', 'refused', 'could_not_verify', 'failed')),
  digest_salt bytea NOT NULL CHECK (length(digest_salt) = 16),
  findings_digest bytea NOT NULL CHECK (length(findings_digest) = 32),
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, connection_id) REFERENCES public.connections (tenant_id, id),
  UNIQUE (tenant_id, id, connection_id, credential_id),
  CHECK (completed_at >= started_at)
);
CREATE INDEX connection_verifications_conn ON public.connection_verifications (tenant_id, connection_id, completed_at DESC);

CREATE TABLE public.connection_verification_findings (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  verification_id uuid NOT NULL,
  ordinal integer NOT NULL CHECK (ordinal >= 0),
  -- AD V1..V9, Entra EV1..EV5.
  check_name text NOT NULL CHECK (check_name ~ '^(V[1-9]|EV[1-5])$'),
  code text NOT NULL CHECK (code ~ '^[a-z0-9_.]{1,64}$'),
  -- excessive_right | missing_right | tier0_group_membership | ... (connector FindingKind, lower case).
  kind text NOT NULL CHECK (kind ~ '^[a-z0-9_]{1,64}$'),
  severity text NOT NULL CHECK (severity IN ('block', 'warn', 'info')),
  object_guid text NOT NULL DEFAULT '' CHECK (object_guid = '' OR object_guid ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
  object_domain_sid text NOT NULL DEFAULT '' CHECK (object_domain_sid = '' OR object_domain_sid ~ '^S-1-[0-9]+(-[0-9]+)+$'),
  qualifier text NOT NULL DEFAULT '' CHECK (qualifier = '' OR qualifier ~ '^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|S-1-[0-9]+(-[0-9]+)+)$'),
  -- Lower-case hex SHA-256, computed by the connector (DM-24.I4).
  fingerprint text NOT NULL CHECK (fingerprint ~ '^[0-9a-f]{64}$'),
  PRIMARY KEY (tenant_id, verification_id, ordinal),
  FOREIGN KEY (tenant_id, verification_id) REFERENCES public.connection_verifications (tenant_id, id),
  UNIQUE (tenant_id, verification_id, fingerprint)
);

CREATE TABLE public.connection_tier0_overrides (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  connection_id uuid NOT NULL,
  credential_id uuid NOT NULL,
  verification_id uuid NOT NULL,
  acknowledged_by text NOT NULL CHECK (acknowledged_by <> ''),
  -- The connection's ordering stamp (DM-10.I13).
  acknowledged_at timestamptz NOT NULL,
  acknowledged_fingerprints text[] NOT NULL CHECK (cardinality(acknowledged_fingerprints) > 0),
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, connection_id) REFERENCES public.connections (tenant_id, id),
  -- DM-25.I1: the evidence run belongs to the same connection and credential.
  FOREIGN KEY (tenant_id, verification_id, connection_id, credential_id)
    REFERENCES public.connection_verifications (tenant_id, id, connection_id, credential_id)
);
CREATE INDEX connection_tier0_overrides_conn ON public.connection_tier0_overrides (tenant_id, connection_id, acknowledged_at DESC);

-- DM-10.I8: the pointer names a run of the same connection.
ALTER TABLE public.connections
  ADD FOREIGN KEY (tenant_id, last_verification_id) REFERENCES public.connection_verifications (tenant_id, id);

ALTER TABLE public.connection_verifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.connection_verifications FORCE ROW LEVEL SECURITY;
CREATE POLICY connection_verifications_tenant ON public.connection_verifications
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
REVOKE UPDATE, DELETE, TRUNCATE ON public.connection_verifications FROM activediq_app;

ALTER TABLE public.connection_verification_findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.connection_verification_findings FORCE ROW LEVEL SECURITY;
CREATE POLICY connection_verification_findings_tenant ON public.connection_verification_findings
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
REVOKE UPDATE, DELETE, TRUNCATE ON public.connection_verification_findings FROM activediq_app;

ALTER TABLE public.connection_tier0_overrides ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.connection_tier0_overrides FORCE ROW LEVEL SECURITY;
CREATE POLICY connection_tier0_overrides_tenant ON public.connection_tier0_overrides
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
REVOKE UPDATE, DELETE, TRUNCATE ON public.connection_tier0_overrides FROM activediq_app;

COMMENT ON TABLE public.connection_verifications IS 'DM-24 ConnectionVerification (tenant table, RLS, append-only). Only internal/directory/connection references it in SQL. Findings enumerate Tier-0 exposure: read under FR-16 only.';
COMMENT ON TABLE public.connection_verification_findings IS 'DM-24 Finding (tenant table, RLS, append-only). Identifiers only, never a DN or a name (DM-24.I3).';
COMMENT ON TABLE public.connection_tier0_overrides IS 'DM-25 Tier0Override (tenant table, RLS, insert-only). Derived states are never stored.';

-- connections_append_only backs the REVOKE for any role that still holds the privilege (an owner
-- running a repair by hand, a future grant). SECURITY INVOKER with a pinned search_path.
CREATE FUNCTION public.connections_append_only() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $fn$
BEGIN
  RAISE EXCEPTION '%: append-only (DM-24.I1, DM-25.I2)', TG_TABLE_NAME USING ERRCODE = 'AD403';
END
$fn$;

CREATE TRIGGER connection_verifications_append_only BEFORE UPDATE OR DELETE ON public.connection_verifications
  FOR EACH ROW EXECUTE FUNCTION public.connections_append_only();
CREATE TRIGGER connection_verification_findings_append_only BEFORE UPDATE OR DELETE ON public.connection_verification_findings
  FOR EACH ROW EXECUTE FUNCTION public.connections_append_only();
CREATE TRIGGER connection_tier0_overrides_append_only BEFORE UPDATE OR DELETE ON public.connection_tier0_overrides
  FOR EACH ROW EXECUTE FUNCTION public.connections_append_only();
ALTER TABLE public.connection_verifications ENABLE TRIGGER connection_verifications_append_only;
ALTER TABLE public.connection_verification_findings ENABLE TRIGGER connection_verification_findings_append_only;
ALTER TABLE public.connection_tier0_overrides ENABLE TRIGGER connection_tier0_overrides_append_only;


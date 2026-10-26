-- 0017_authn_accounts: DM-30 Account (T-0400; domain model DM-30 I1, I5; console-sso.md §7).
-- Owner: internal/platform/authn. One tenant table.
--
-- An account is a human who signs in to the console or API.
--   kind                 local (credentials here, MFA always required, I1), sso (issuer + subject
--                        from the IdP), directory (an AD user, connection + objectGUID).
--   directory_*          directory_ref: connection + objectGUID, never a DN. Required for directory,
--                        optional for sso, null for local. For sso it is set only by a binding.
--   anchor_kind/_value/_tid  DM-30.I5: the anchor claim that produced the binding, kept so a later
--                        sign-in can be checked against it: oid (+ tid, the Entra tenant) or
--                        onprem_sid. UPN, email and name never bind. The SID is resolved once and the
--                        GUID stored in directory_ref (a SID changes on a cross-domain move).
--                        An sso account has an anchor if and only if it has a directory_ref.
--   created_by           'system' (a system-created account, ADR-0005 sock-puppet rule) or the id of
--                        the creating account.
--   state                invited -> active <-> disabled -> deleted; deleted is final. Rows are kept
--                        (audit refers to them); the runtime role cannot delete them.
-- A binding is never rewritten here; rebinding is an audited administrative action of its own ticket.

CREATE TABLE public.authn_accounts (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  kind text NOT NULL CHECK (kind IN ('local', 'sso', 'directory')),
  display_name text NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 200),
  email text CHECK (email IS NULL OR char_length(email) BETWEEN 3 AND 320),
  mfa_required boolean NOT NULL DEFAULT true,
  state text NOT NULL DEFAULT 'invited' CHECK (state IN ('invited', 'active', 'disabled', 'deleted')),
  created_by text NOT NULL CHECK (created_by = 'system'
    OR created_by ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
  sso_issuer text CHECK (sso_issuer IS NULL OR char_length(sso_issuer) BETWEEN 1 AND 2048),
  sso_subject text CHECK (sso_subject IS NULL OR char_length(sso_subject) BETWEEN 1 AND 512),
  directory_connection_id uuid,
  directory_object_guid uuid,
  anchor_kind text CHECK (anchor_kind IN ('oid', 'onprem_sid')),
  anchor_value text CHECK (anchor_value IS NULL OR char_length(anchor_value) BETWEEN 1 AND 256),
  anchor_tid uuid,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, directory_connection_id) REFERENCES public.connections (tenant_id, id),
  -- directory_ref is both halves or neither.
  CONSTRAINT authn_accounts_ref_pair CHECK ((directory_connection_id IS NULL) = (directory_object_guid IS NULL)),
  -- Kind ties to the fields it may carry.
  CONSTRAINT authn_accounts_local CHECK (kind <> 'local' OR (sso_issuer IS NULL AND sso_subject IS NULL
    AND directory_connection_id IS NULL AND anchor_kind IS NULL AND mfa_required)),
  CONSTRAINT authn_accounts_sso CHECK (kind <> 'sso' OR (sso_issuer IS NOT NULL AND sso_subject IS NOT NULL)),
  CONSTRAINT authn_accounts_directory CHECK (kind <> 'directory' OR (sso_issuer IS NULL AND sso_subject IS NULL
    AND directory_connection_id IS NOT NULL AND anchor_kind IS NULL)),
  -- I5: bound if and only if there is an anchor; the anchor's fields fit its kind.
  CONSTRAINT authn_accounts_anchor CHECK ((anchor_kind IS NULL) = (anchor_value IS NULL)
    AND (kind <> 'sso' OR (anchor_kind IS NULL) = (directory_connection_id IS NULL))
    AND (anchor_kind IS NOT NULL OR anchor_tid IS NULL)
    AND (anchor_kind IS DISTINCT FROM 'oid' OR (anchor_tid IS NOT NULL
      AND anchor_value ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'))
    AND (anchor_kind IS DISTINCT FROM 'onprem_sid' OR (anchor_tid IS NULL
      AND anchor_value ~ '^S-1-[0-9]+(-[0-9]+){1,15}$')))
);

-- One live account per IdP subject and per directory object, so a sign-in or a grant finds one account.
CREATE UNIQUE INDEX authn_accounts_sso_subject ON public.authn_accounts (tenant_id, sso_issuer, sso_subject)
  WHERE kind = 'sso' AND state <> 'deleted';
CREATE UNIQUE INDEX authn_accounts_directory_ref ON public.authn_accounts (tenant_id, kind, directory_connection_id, directory_object_guid)
  WHERE directory_connection_id IS NOT NULL AND state <> 'deleted';
CREATE INDEX authn_accounts_state ON public.authn_accounts (tenant_id, state, created_at, id);

ALTER TABLE public.authn_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.authn_accounts FORCE ROW LEVEL SECURITY;
CREATE POLICY authn_accounts_tenant ON public.authn_accounts
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

REVOKE DELETE ON public.authn_accounts FROM activediq_app;

COMMENT ON TABLE public.authn_accounts IS 'DM-30 console accounts (tenant table, RLS). directory_ref is connection + objectGUID, never a DN. Only internal/platform/authn references it in SQL.';

-- Identity never changes; a binding may be set once (from none) but never rewritten; deleted is final.
CREATE FUNCTION public.authn_accounts_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $fn$
BEGIN
  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.id IS DISTINCT FROM OLD.id
     OR NEW.kind IS DISTINCT FROM OLD.kind OR NEW.created_by IS DISTINCT FROM OLD.created_by
     OR NEW.created_at IS DISTINCT FROM OLD.created_at OR NEW.sso_issuer IS DISTINCT FROM OLD.sso_issuer
     OR NEW.sso_subject IS DISTINCT FROM OLD.sso_subject THEN
    RAISE EXCEPTION 'authn_accounts: identity is never rewritten' USING ERRCODE = 'AD403';
  END IF;
  IF OLD.directory_connection_id IS NOT NULL AND (NEW.directory_connection_id IS DISTINCT FROM OLD.directory_connection_id
     OR NEW.directory_object_guid IS DISTINCT FROM OLD.directory_object_guid) THEN
    RAISE EXCEPTION 'authn_accounts: a directory reference is never rewritten' USING ERRCODE = 'AD403';
  END IF;
  IF OLD.anchor_kind IS NOT NULL AND (NEW.anchor_kind IS DISTINCT FROM OLD.anchor_kind
     OR NEW.anchor_value IS DISTINCT FROM OLD.anchor_value OR NEW.anchor_tid IS DISTINCT FROM OLD.anchor_tid) THEN
    RAISE EXCEPTION 'authn_accounts: an anchor binding is never rewritten silently' USING ERRCODE = 'AD403';
  END IF;
  IF OLD.state = 'deleted' THEN
    RAISE EXCEPTION 'authn_accounts: a deleted account is final' USING ERRCODE = 'AD403';
  END IF;
  RETURN NEW;
END
$fn$;

CREATE TRIGGER authn_accounts_guard BEFORE UPDATE ON public.authn_accounts
  FOR EACH ROW EXECUTE FUNCTION public.authn_accounts_guard();
ALTER TABLE public.authn_accounts ENABLE ALWAYS TRIGGER authn_accounts_guard;

-- 0073_objects_templates_naming: Template (DM-50) and NamingFormat (DM-51) definitions (T-1582).
-- Owner: internal/modules/objects. Two tenant tables; a row is one VERSION of a definition.
--
-- Lifecycle (domain-model.md DM-50/DM-51):
--   template      draft -> published -> archived     (DM-50.I1: a published version is immutable)
--   naming format draft -> active    -> archived     (Template versions pin the version they use)
-- A definition has at most one draft; saving it again replaces the draft's body, publishing it freezes
-- the row, and the next save opens version n+1. The guard trigger states the immutability itself, so no
-- writer can edit a version an Operation has pinned. Rows are never deleted by the runtime role.

-- write-class: objects_templates config
CREATE TABLE public.objects_templates (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  id uuid NOT NULL,
  version integer NOT NULL CHECK (version >= 1),
  state text NOT NULL CHECK (state IN ('draft', 'published', 'archived')),
  object_kind text NOT NULL CHECK (object_kind IN ('user', 'group', 'computer', 'contact', 'ou')),
  provider text NOT NULL CHECK (provider IN ('ad', 'entra', 'hybrid')),
  purpose text NOT NULL CHECK (purpose IN ('create', 'modify')),
  name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 120),
  definition jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  published_at timestamptz,
  archived_at timestamptz,
  PRIMARY KEY (tenant_id, id, version),
  CONSTRAINT objects_templates_published_at CHECK ((state = 'draft') = (published_at IS NULL)),
  CONSTRAINT objects_templates_archived_at CHECK ((state = 'archived') = (archived_at IS NOT NULL))
);

CREATE UNIQUE INDEX objects_templates_one_draft ON public.objects_templates (tenant_id, id) WHERE state = 'draft';
CREATE INDEX objects_templates_list ON public.objects_templates (tenant_id, object_kind, purpose, id, version);

-- write-class: objects_naming_formats config
CREATE TABLE public.objects_naming_formats (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  id uuid NOT NULL,
  version integer NOT NULL CHECK (version >= 1),
  state text NOT NULL CHECK (state IN ('draft', 'active', 'archived')),
  purpose text NOT NULL CHECK (purpose IN ('sAMAccountName', 'upnPrefix', 'cn', 'displayName', 'mailAlias')),
  name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 120),
  definition jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  published_at timestamptz,
  archived_at timestamptz,
  PRIMARY KEY (tenant_id, id, version),
  CONSTRAINT objects_naming_formats_published_at CHECK ((state = 'draft') = (published_at IS NULL)),
  CONSTRAINT objects_naming_formats_archived_at CHECK ((state = 'archived') = (archived_at IS NOT NULL))
);

CREATE UNIQUE INDEX objects_naming_formats_one_draft ON public.objects_naming_formats (tenant_id, id) WHERE state = 'draft';
CREATE INDEX objects_naming_formats_list ON public.objects_naming_formats (tenant_id, purpose, id, version);

-- The guard: identity columns never change; a non-draft row's body never changes; the only moves are
-- draft -> (published|active) and (published|active) -> archived. SQLSTATE AD403 matches the other guards.
CREATE FUNCTION public.objects_version_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE live text := CASE TG_TABLE_NAME WHEN 'objects_templates' THEN 'published' ELSE 'active' END;
BEGIN
  -- tenant_id is not judged here: re-assigning a row to another tenant is refused by the table's row-security
  -- WITH CHECK, which the tenancy probe (ADR-0002 T4) expects to be the layer that says no.
  IF NEW.id <> OLD.id OR NEW.version <> OLD.version
     OR NEW.purpose <> OLD.purpose OR NEW.created_at <> OLD.created_at THEN
    RAISE EXCEPTION 'objects: a version''s identity cannot change' USING ERRCODE = 'AD403';
  END IF;
  -- Template-only columns are read inside their own statements: PL/pgSQL resolves NEW.<column> when the
  -- statement runs, so the naming-format table (which has none of them) never reaches these.
  IF TG_TABLE_NAME = 'objects_templates' THEN
    IF NEW.object_kind <> OLD.object_kind THEN
      RAISE EXCEPTION 'objects: a template''s object kind cannot change' USING ERRCODE = 'AD403';
    END IF;
    IF OLD.state <> 'draft' AND NEW.provider <> OLD.provider THEN
      RAISE EXCEPTION 'objects: a published version is immutable' USING ERRCODE = 'AD403';
    END IF;
  END IF;
  IF OLD.state = 'draft' AND NEW.state IN ('draft', live) THEN
    RETURN NEW;
  END IF;
  IF OLD.state = live AND NEW.state IN (live, 'archived')
     AND NEW.definition = OLD.definition AND NEW.name = OLD.name THEN
    RETURN NEW;
  END IF;
  IF OLD.state = 'archived' AND NEW.state = 'archived' AND NEW.definition = OLD.definition THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'objects: a published version is immutable and moves only to archived' USING ERRCODE = 'AD403';
END $$;

CREATE TRIGGER objects_templates_version_guard BEFORE UPDATE ON public.objects_templates
  FOR EACH ROW EXECUTE FUNCTION public.objects_version_guard();
CREATE TRIGGER objects_naming_formats_version_guard BEFORE UPDATE ON public.objects_naming_formats
  FOR EACH ROW EXECUTE FUNCTION public.objects_version_guard();

ALTER TABLE public.objects_templates ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.objects_templates FORCE ROW LEVEL SECURITY;
CREATE POLICY objects_templates_tenant ON public.objects_templates
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

ALTER TABLE public.objects_naming_formats ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.objects_naming_formats FORCE ROW LEVEL SECURITY;
CREATE POLICY objects_naming_formats_tenant ON public.objects_naming_formats
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

REVOKE DELETE ON public.objects_templates FROM activediq_app;
REVOKE DELETE ON public.objects_naming_formats FROM activediq_app;

COMMENT ON TABLE public.objects_templates IS 'DM-50 Template versions (tenant table, RLS). Only internal/modules/objects references it in SQL.';
COMMENT ON TABLE public.objects_naming_formats IS 'DM-51 NamingFormat versions (tenant table, RLS). Only internal/modules/objects references it in SQL.';

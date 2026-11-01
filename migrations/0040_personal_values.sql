-- 0040_personal_values: erasable personal values (T-0357; ADR-0005 rule 12, domain model X11).
-- Owner: internal/platform/personal. Two tenant tables.
--
--   personal_subject  one row per person a value is about: the 256-bit secret salt that keys every
--                     commitment for that subject, and the legal hold. Erasure deletes the row.
--   personal_value    the clear value, held outside the record that refers to it. value_id belongs to
--                     exactly one record. Erasure deletes the subject's rows.
-- The runtime role can INSERT, SELECT and DELETE and cannot UPDATE either table: only erasure and the
-- retention purge delete. A hold is therefore set when the subject row is created; changing it is the
-- compliance PRD's work.

-- write-class: personal_subject system
CREATE TABLE public.personal_subject (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  subject_ref text NOT NULL CHECK (char_length(subject_ref) BETWEEN 3 AND 300),
  salt bytea NOT NULL CHECK (octet_length(salt) = 32),
  hold boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, subject_ref)
);

-- write-class: personal_value system
CREATE TABLE public.personal_value (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  value_id uuid NOT NULL,
  subject_ref text NOT NULL,
  record_kind text NOT NULL CHECK (char_length(record_kind) BETWEEN 1 AND 64),
  field text NOT NULL CHECK (char_length(field) BETWEEN 1 AND 128),
  value text NOT NULL CHECK (char_length(value) <= 65536),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, value_id),
  FOREIGN KEY (tenant_id, subject_ref) REFERENCES public.personal_subject (tenant_id, subject_ref)
);
CREATE INDEX personal_value_subject ON public.personal_value (tenant_id, subject_ref);

ALTER TABLE public.personal_subject ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.personal_subject FORCE ROW LEVEL SECURITY;
CREATE POLICY personal_subject_tenant ON public.personal_subject
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

ALTER TABLE public.personal_value ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.personal_value FORCE ROW LEVEL SECURITY;
CREATE POLICY personal_value_tenant ON public.personal_value
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

REVOKE UPDATE ON public.personal_subject, public.personal_value FROM activediq_app;

COMMENT ON TABLE public.personal_subject IS 'Per-subject secret salt and legal hold for personal-value commitments (ADR-0005 rule 12). Tenant table, RLS; no UPDATE for the runtime role. Only internal/platform/personal references it in SQL.';
COMMENT ON TABLE public.personal_value IS 'Clear personal values held by reference (ADR-0005 rule 12). Tenant table, RLS; no UPDATE for the runtime role; erasure and retention purge delete. Only internal/platform/personal references it in SQL.';

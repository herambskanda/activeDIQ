-- 0049_personal_hold_registry: legal holds independent of the salt row (T-0587; ADR-0005 rule 11 amendment, T-0515).
-- Owner: internal/platform/personal.
--
-- A hold lived on personal_subject.hold, so a person with no salt row (salt purged earlier, or only secret or
-- count-only events) could not be held, and a hold created by INSERT was invisible to the purge's FOR SHARE
-- on the salt rows. The hold is now a row of its own, keyed by the subject reference alone. Setting a hold and
-- the retention purge serialise on a tenant advisory lock taken in personal (SetHold shared, LockHolds
-- exclusive), not on row locks. The runtime role can INSERT, SELECT and DELETE (release); nobody UPDATEs.

-- write-class: personal_hold config
CREATE TABLE public.personal_hold (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  subject_ref text NOT NULL CHECK (char_length(subject_ref) BETWEEN 3 AND 300),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, subject_ref)
);

ALTER TABLE public.personal_hold ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.personal_hold FORCE ROW LEVEL SECURITY;
CREATE POLICY personal_hold_tenant ON public.personal_hold
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
REVOKE UPDATE ON public.personal_hold FROM activediq_app;

-- Carry existing holds over. The owner is bound by FORCE ROW LEVEL SECURITY and no tenant is set here, so lift
-- FORCE on both tables for the copy, inside this migration's transaction, and put it back.
ALTER TABLE public.personal_subject NO FORCE ROW LEVEL SECURITY;
ALTER TABLE public.personal_hold NO FORCE ROW LEVEL SECURITY;
INSERT INTO public.personal_hold (tenant_id, subject_ref, created_at)
  SELECT tenant_id, subject_ref, created_at FROM public.personal_subject WHERE hold;
ALTER TABLE public.personal_hold FORCE ROW LEVEL SECURITY;
ALTER TABLE public.personal_subject FORCE ROW LEVEL SECURITY;

ALTER TABLE public.personal_subject DROP COLUMN hold;

COMMENT ON TABLE public.personal_hold IS 'Legal holds on personal subjects (ADR-0005 rule 11), independent of the salt row. Tenant table, RLS; no UPDATE. Only internal/platform/personal references it in SQL.';

-- Every INSERT into personal_hold takes the locks the retention purge serialises on, so the guarantee is the
-- database's and holds for any writer (bulk hold, import, tool, migration), not only personal.SetHold.
-- Keys match internal/platform/personal: tenant shared (holds do not block each other; the purge takes it
-- exclusive) and the subject. Locks are re-entrant, so SetHold taking them first is harmless.
CREATE FUNCTION public.personal_hold_insert_lock() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $fn$
BEGIN
  PERFORM pg_catalog.pg_advisory_xact_lock_shared(pg_catalog.hashtextextended('personal_hold:' || NEW.tenant_id::text, 0));
  PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('personal_subject:' || NEW.tenant_id::text || ':' || NEW.subject_ref, 0));
  RETURN NEW;
END
$fn$;

CREATE TRIGGER personal_hold_insert_lock BEFORE INSERT ON public.personal_hold
  FOR EACH ROW EXECUTE FUNCTION public.personal_hold_insert_lock();

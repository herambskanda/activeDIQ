-- 0054_updateverify_floor: the database half of the update verifier's rollback floor (T-0653; spec
-- enh-07-signed-update-protocol §3 rules 2 and 3, TM-D12). Owner: internal/platform/updateverify/floorpg.
--
-- One install-level row: the highest TUF metadata versions seen, the newest signing time verified and
-- the highest committed product version. It has no tenant_id and no RLS: the verifier runs for the whole
-- installation (server, connector and agent updates) before and outside any tenant transaction. It is the
-- second of two independent halves (the first is a file on the host), so a restore of the database alone
-- cannot rewind the floor: updateverify.Dual takes the field-wise maximum and heals the lower half.
--
-- Every field only rises. The store raises with GREATEST in one upsert; the guard trigger below is the
-- database's own refusal of any other statement that would lower a number, and it holds for the owner
-- role too (a deliberate reset is a restore, which the host half outvotes). The runtime role can neither
-- DELETE nor TRUNCATE the row, because deleting it would reset the floor to zero.
--
--   newest_signing  NULL = no metadata verified yet. Microsecond precision (timestamptz).
--   committed       dotted numeric product version of the newest release the apply step committed;
--                   '' = none yet. Compared as a version by the verifier, not by SQL, so the guard only
--                   refuses clearing it.

CREATE TABLE public.update_verifier_floor (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  root_version bigint NOT NULL DEFAULT 0 CHECK (root_version >= 0),
  timestamp_version bigint NOT NULL DEFAULT 0 CHECK (timestamp_version >= 0),
  snapshot_version bigint NOT NULL DEFAULT 0 CHECK (snapshot_version >= 0),
  targets_version bigint NOT NULL DEFAULT 0 CHECK (targets_version >= 0),
  newest_signing timestamptz,
  committed text NOT NULL DEFAULT '' CHECK (char_length(committed) <= 64)
);

REVOKE DELETE, TRUNCATE ON public.update_verifier_floor FROM activediq_app;

COMMENT ON TABLE public.update_verifier_floor IS 'Registered global table: the database half of the update verifier rollback floor (ENH-07, TM-D12). One row, monotone. Only internal/platform/updateverify/floorpg references it in SQL.';

CREATE FUNCTION public.update_verifier_floor_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $fn$
BEGIN
  IF NEW.root_version < OLD.root_version OR NEW.timestamp_version < OLD.timestamp_version
     OR NEW.snapshot_version < OLD.snapshot_version OR NEW.targets_version < OLD.targets_version
     OR (OLD.newest_signing IS NOT NULL AND (NEW.newest_signing IS NULL OR NEW.newest_signing < OLD.newest_signing))
     OR (OLD.committed <> '' AND NEW.committed = '') THEN
    RAISE EXCEPTION 'update_verifier_floor: the floor never decreases' USING ERRCODE = 'AD403';
  END IF;
  RETURN NEW;
END
$fn$;

CREATE TRIGGER update_verifier_floor_guard BEFORE UPDATE ON public.update_verifier_floor
  FOR EACH ROW EXECUTE FUNCTION public.update_verifier_floor_guard();
ALTER TABLE public.update_verifier_floor ENABLE ALWAYS TRIGGER update_verifier_floor_guard;

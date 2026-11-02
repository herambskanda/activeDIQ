-- 0069_inventory_search_keys: the search keys universal search matches against (T-1095, ADR-0011 rules
-- 4-9, 12-13). Owner: internal/directory/inventory, the only code that writes it; only the reportsql
-- search template reads it (SE1).
--
--  * pg_trgm is the only extension: it is trusted on PostgreSQL 16 and 18, so the migration owner needs
--    no superuser. Diacritics are folded in Go (internal/platform/searchkey), not by unaccent.
--  * inventory_search_keys: one row per (object, key kind, key). key is the normalised text
--    (searchkey.NormName / NormIdent) in code point order (COLLATE "C"), so a prefix is the bound range
--    key >= $lo AND key < $hi and never a LIKE. norm_version is the searchkey.Version the key was
--    built with: the backfill rewrites a row whose version is older. The table carries none of the scope
--    anchor columns: the search statement joins directory_objects and trims there.
--      key_kind  1 name  2 name_word  3 sam  4 upn  5 mail  6 dns_host  7 sid  8 guid  9 consistency_guid  10 dn
--  * Keys are written by the sync writer in the same transaction as the object row, from an allow-list
--    of attributes the console already shows; a secret attribute never yields a key (T-1095 AC5).
--  * (tenant_id, key_kind, key) serves exact and prefix matching. The partial GIN index serves fuzzy
--    matching for the kinds that are fuzzy-eligible (searchkey.Kind.FuzzyEligible: 1-5). It cannot lead
--    with tenant_id, so ADR-0011 rule 16 withholds fuzzy search from a database holding several tenants.
--    The statement must repeat the predicate key_kind IN (1, 2, 3, 4, 5) as literals for the planner to use it.
--
-- The keys are derived data: the runtime role keeps DELETE.

CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- write-class: inventory_search_keys system
CREATE TABLE public.inventory_search_keys (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  connection_id uuid NOT NULL,
  object_guid uuid NOT NULL,
  key_kind smallint NOT NULL CHECK (key_kind BETWEEN 1 AND 10),
  key text COLLATE "C" NOT NULL CHECK (char_length(key) BETWEEN 1 AND 256),
  norm_version smallint NOT NULL CHECK (norm_version >= 1),
  PRIMARY KEY (tenant_id, connection_id, object_guid, key_kind, key),
  FOREIGN KEY (tenant_id, connection_id, object_guid) REFERENCES public.directory_objects (tenant_id, connection_id, object_guid)
);

CREATE INDEX inventory_search_keys_by_key ON public.inventory_search_keys (tenant_id, key_kind, key);
CREATE INDEX inventory_search_keys_fuzzy ON public.inventory_search_keys USING gin (key gin_trgm_ops) WHERE key_kind IN (1, 2, 3, 4, 5);
-- The backfill reads the stale rows of one tenant.
CREATE INDEX inventory_search_keys_by_version ON public.inventory_search_keys (tenant_id, norm_version);

ALTER TABLE public.inventory_search_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.inventory_search_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY inventory_search_keys_tenant ON public.inventory_search_keys
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

COMMENT ON TABLE public.inventory_search_keys IS 'Normalised search keys of directory objects for exact, prefix and fuzzy search (directory table, RLS, derived). Written by internal/directory/inventory with the object; read only by the reportsql search template.';

-- 0074_inventory_search_trigrams: a tenant-led B-tree of trigram postings, so that the fuzzy probe of
-- universal search is index-usable under FORCE row security (T-1335, ADR-0011 revision 3, rule 5a).
--
--  * Why: pg_trgm's %, <% and %> are not leakproof, so under FORCE RLS the planner never uses a trigram
--    GIN on inventory_search_keys, and the fuzzy probe was a seq scan of the tenant's fuzzy keys (372 of 389
--    ms at 50,000 objects, T-1102). A GIN also cannot lead with tenant_id. The postings are plain B-tree
--    rows (tenant_id, trgm, key_id) read through the policy's own tenant_id qual, which is always usable,
--    and each candidate is rechecked with <% as an ordinary filter over rows the policy already admitted.
--  * inventory_search_keys gains key_id, a table-wide identity that the postings refer to. It never leaves
--    the statement: no hit, cursor, API field or log carries it (it reveals the database-wide insert rate).
--  * inventory_search_trigrams holds one row per (key, trigram of show_trgm(key)) for the fuzzy-eligible
--    kinds name (1) and sam (3) only. It has no key text, no scope column and no foreign key: the three
--    statement-level triggers below keep it equal to the keys, for every writer, without the writer knowing
--    that it exists.
--  * The function is SECURITY INVOKER with a fixed search_path and calls show_trgm schema-qualified: on
--    PostgreSQL 18 an AFTER trigger queued by a cascade runs as the role that queued it, which may be the
--    table owner. FORCE still binds the owner to the policy.
--  * PostgreSQL refuses transition tables on a trigger with a column list or with more than one event, so
--    there are three triggers. UPDATE has no column list: a key_kind change is an update too.
--  * Backfill: under FORCE with no tenant set the migration owner sees no rows and an INSERT ... SELECT builds
--    zero postings without an error. As in 0021 and 0047, FORCE is lifted for the one statement, inside this
--    migration's single transaction, with tenant_id taken from the same source row, and put back.
--  * VACUUM (ANALYZE) of the postings cannot run inside a transaction: the migration runner does it after
--    this file (the "-- after:" line at the end, run by migrations.After's callers), so an Index Only Scan does not fetch heap pages.
--  * The GIN inventory_search_keys_fuzzy of 0069 is dropped.
--
-- Postings are derived data: the runtime role keeps SELECT, INSERT and DELETE, and has no UPDATE and no
-- TRUNCATE (TRUNCATE ignores row security).

ALTER TABLE public.inventory_search_keys ADD COLUMN key_id bigint GENERATED ALWAYS AS IDENTITY;
ALTER TABLE public.inventory_search_keys ADD CONSTRAINT inventory_search_keys_tenant_key_id_key UNIQUE (tenant_id, key_id);

-- write-class: inventory_search_trigrams system
CREATE TABLE public.inventory_search_trigrams (
  tenant_id uuid NOT NULL REFERENCES public.tenants (id),
  trgm text COLLATE "C" NOT NULL,
  key_id bigint NOT NULL,
  PRIMARY KEY (tenant_id, trgm, key_id)
);

ALTER TABLE public.inventory_search_trigrams ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.inventory_search_trigrams FORCE ROW LEVEL SECURITY;
CREATE POLICY inventory_search_trigrams_tenant ON public.inventory_search_trigrams
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

REVOKE UPDATE, TRUNCATE ON public.inventory_search_trigrams FROM activediq_app;

COMMENT ON TABLE public.inventory_search_trigrams IS 'Trigram postings (tenant_id, trgm, key_id) of the name and sam search keys, so the fuzzy probe of universal search reads a tenant-led B-tree under row security (directory table, RLS, derived). Maintained by the triggers of inventory_search_keys; read only by the reportsql search template.';
COMMENT ON COLUMN public.inventory_search_keys.key_id IS 'Table-wide identity the trigram postings refer to. Never leaves a statement: no hit, cursor, API field or log carries it.';

CREATE FUNCTION public.inventory_search_trigrams_sync() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, public AS $sync$
BEGIN
  IF TG_OP = 'INSERT' THEN
    INSERT INTO public.inventory_search_trigrams (tenant_id, trgm, key_id)
    SELECT n.tenant_id, g.trgm, n.key_id
    FROM new_keys n CROSS JOIN LATERAL unnest(public.show_trgm(n.key)) AS g(trgm)
    WHERE n.key_kind IN (1, 3);
  ELSIF TG_OP = 'DELETE' THEN
    DELETE FROM public.inventory_search_trigrams p
    USING (SELECT o.tenant_id, g.trgm, o.key_id
           FROM old_keys o CROSS JOIN LATERAL unnest(public.show_trgm(o.key)) AS g(trgm)
           WHERE o.key_kind IN (1, 3)) d
    WHERE p.tenant_id = d.tenant_id AND p.trgm = d.trgm AND p.key_id = d.key_id;
  ELSIF TG_OP = 'UPDATE' THEN
    -- key_id is GENERATED ALWAYS and never changes: it joins the two images of a row. A row whose tenant,
    -- kind and key are unchanged keeps its postings.
    DELETE FROM public.inventory_search_trigrams p
    USING (SELECT o.tenant_id, g.trgm, o.key_id
           FROM old_keys o JOIN new_keys n ON n.key_id = o.key_id
           CROSS JOIN LATERAL unnest(public.show_trgm(o.key)) AS g(trgm)
           WHERE o.key_kind IN (1, 3)
           AND (o.tenant_id, o.key_kind, o.key) IS DISTINCT FROM (n.tenant_id, n.key_kind, n.key)) d
    WHERE p.tenant_id = d.tenant_id AND p.trgm = d.trgm AND p.key_id = d.key_id;
    INSERT INTO public.inventory_search_trigrams (tenant_id, trgm, key_id)
    SELECT n.tenant_id, g.trgm, n.key_id
    FROM new_keys n JOIN old_keys o ON o.key_id = n.key_id
    CROSS JOIN LATERAL unnest(public.show_trgm(n.key)) AS g(trgm)
    WHERE n.key_kind IN (1, 3)
    AND (o.tenant_id, o.key_kind, o.key) IS DISTINCT FROM (n.tenant_id, n.key_kind, n.key);
  END IF;
  RETURN NULL;
END
$sync$;

-- Backfill the postings of the keys that exist (see the header for the NO FORCE window).
ALTER TABLE public.inventory_search_keys NO FORCE ROW LEVEL SECURITY;
ALTER TABLE public.inventory_search_trigrams NO FORCE ROW LEVEL SECURITY;
INSERT INTO public.inventory_search_trigrams (tenant_id, trgm, key_id)
SELECT k.tenant_id, g.trgm, k.key_id
FROM public.inventory_search_keys k CROSS JOIN LATERAL unnest(public.show_trgm(k.key)) AS g(trgm)
WHERE k.key_kind IN (1, 3);
ALTER TABLE public.inventory_search_keys FORCE ROW LEVEL SECURITY;
ALTER TABLE public.inventory_search_trigrams FORCE ROW LEVEL SECURITY;

CREATE TRIGGER inventory_search_keys_trgm_insert AFTER INSERT ON public.inventory_search_keys
  REFERENCING NEW TABLE AS new_keys FOR EACH STATEMENT EXECUTE FUNCTION public.inventory_search_trigrams_sync();
CREATE TRIGGER inventory_search_keys_trgm_delete AFTER DELETE ON public.inventory_search_keys
  REFERENCING OLD TABLE AS old_keys FOR EACH STATEMENT EXECUTE FUNCTION public.inventory_search_trigrams_sync();
CREATE TRIGGER inventory_search_keys_trgm_update AFTER UPDATE ON public.inventory_search_keys
  REFERENCING OLD TABLE AS old_keys NEW TABLE AS new_keys FOR EACH STATEMENT EXECUTE FUNCTION public.inventory_search_trigrams_sync();

DROP INDEX public.inventory_search_keys_fuzzy;

-- after: VACUUM (ANALYZE) public.inventory_search_trigrams

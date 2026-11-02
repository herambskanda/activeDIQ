\timing off
CREATE EXTENSION pg_trgm;
CREATE ROLE app LOGIN NOBYPASSRLS;
CREATE TABLE tenants(id uuid primary key);
INSERT INTO tenants VALUES ('00000000-0000-0000-0000-000000000001'),('00000000-0000-0000-0000-000000000002');
CREATE TABLE keys(
  tenant_id uuid not null references tenants(id),
  key_id bigint generated always as identity,
  key_kind smallint not null,
  key text collate "C" not null,
  primary key (tenant_id, key_id));
CREATE INDEX keys_gin ON keys USING gin (key gin_trgm_ops) WHERE key_kind IN (1,2,3,4,5);
CREATE TABLE trg(
  tenant_id uuid not null,
  trgm text collate "C" not null,
  key_id bigint not null,
  primary key (tenant_id, trgm, key_id),
  foreign key (tenant_id, key_id) references keys(tenant_id, key_id) on delete cascade);
-- synthetic name-like vocabulary
CREATE TEMP TABLE syl(s text);
INSERT INTO syl SELECT unnest(string_to_array('ra,man,pri,ya,jo,han,ne,son,smi,th,ka,ren,li,sa,mar,tin,el,la,an,dre,os,ter,mi,chel,da,vid,ro,bert,sk,ror,zo,rn,pe,tra,lu,ka,no,vak,ber,ger,fi,sch,er,mu,ller,wa,gn,et,ta,ki',','));
CREATE TEMP TABLE w AS SELECT (SELECT string_agg(s,'') FROM (SELECT s FROM syl ORDER BY random() LIMIT 2 + (g % 2)) x) || CASE WHEN g%3=0 THEN '' ELSE '' END AS word, g FROM generate_series(1,40000) g;
CREATE INDEX ON w(g); ANALYZE w;
INSERT INTO keys(tenant_id,key_kind,key)
SELECT t, kind, k FROM (
 SELECT '00000000-0000-0000-0000-000000000001'::uuid t,
        (1 + (g % 5))::smallint kind,
        CASE g % 5
          WHEN 0 THEN (SELECT word FROM w WHERE w.g = 1 + (h1 % 40000)) || ' ' || (SELECT word FROM w WHERE w.g = 1 + (h2 % 40000))
          WHEN 1 THEN (SELECT word FROM w WHERE w.g = 1 + (h1 % 40000))
          WHEN 2 THEN left((SELECT word FROM w WHERE w.g = 1 + (h1 % 40000)),1) || (SELECT word FROM w WHERE w.g = 1 + (h2 % 40000)) || (g % 100)::text
          ELSE (SELECT word FROM w WHERE w.g = 1 + (h1 % 40000)) || '.' || (SELECT word FROM w WHERE w.g = 1 + (h2 % 40000)) || '@corp.example.com'
        END k
 FROM (SELECT g, abs(hashint4(g)) h1, abs(hashint4(g+7777777)) h2 FROM generate_series(1,416000) g) s) z;
-- tenant 2: same volume, to test cross-tenant reads
INSERT INTO keys(tenant_id,key_kind,key) SELECT '00000000-0000-0000-0000-000000000002', key_kind, key FROM keys WHERE tenant_id='00000000-0000-0000-0000-000000000001';
INSERT INTO trg SELECT tenant_id, t, key_id FROM keys, unnest(show_trgm(key)) t WHERE key_kind IN (1,2,3,4,5);
ANALYZE keys; ANALYZE trg;
ALTER TABLE keys ENABLE ROW LEVEL SECURITY; ALTER TABLE keys FORCE ROW LEVEL SECURITY;
ALTER TABLE trg ENABLE ROW LEVEL SECURITY; ALTER TABLE trg FORCE ROW LEVEL SECURITY;
CREATE POLICY p ON keys USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid) WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
CREATE POLICY p ON trg USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid) WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
GRANT SELECT ON keys, trg TO app;
SELECT count(*) keys FROM keys; SELECT count(*) postings FROM trg;
SELECT pg_size_pretty(pg_total_relation_size('keys')) keys_total, pg_size_pretty(pg_relation_size('keys_gin')) gin, pg_size_pretty(pg_total_relation_size('trg')) trg_total, pg_size_pretty(pg_relation_size('trg')) trg_heap;
BEGIN;
SET LOCAL ROLE app;
SELECT set_config('app.tenant_id','00000000-0000-0000-0000-000000000001',true) \g /dev/null
SELECT set_config('pg_trgm.word_similarity_threshold','0.5',true) \g /dev/null
SET LOCAL work_mem = '16MB';
PREPARE f(text) AS
WITH qt AS MATERIALIZED (SELECT show_trgm($1) a),
cand AS MATERIALIZED (
  SELECT p.key_id FROM trg p
  WHERE p.tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND p.trgm = ANY ((SELECT a FROM qt)::text[])
  GROUP BY p.key_id
  HAVING count(*) >= ceil(0.5 * (SELECT cardinality(a) FROM qt)))
SELECT count(*) FROM (SELECT k.key_id FROM cand c CROSS JOIN LATERAL (
  SELECT k.key_id, k.key, k.key_kind FROM keys k WHERE k.tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND k.key_id = c.key_id OFFSET 0) k
WHERE k.key_kind IN (1,2,3,4,5) AND $1 <% k.key LIMIT 10001) z;
PREPARE g(text) AS SELECT count(*) FROM (SELECT key_id FROM keys k WHERE key_kind IN (1,2,3,4,5) AND $1 <% key LIMIT 10001) z;
\timing on
EXECUTE f('skrorsors10'); EXECUTE f('skrorsors10'); EXECUTE f('skrorsors10');
EXECUTE f('pryia ramn'); EXECUTE f('pryia ramn');
EXECUTE f('johanson'); EXECUTE f('johanson');
EXECUTE f('zx0946z'); EXECUTE f('zx0946z');
EXECUTE f('mullerberger'); EXECUTE f('mullerberger');
\echo seq-scan route (current)
EXECUTE g('skrorsors10'); EXECUTE g('johanson'); EXECUTE g('zx0946z');
SELECT p.trgm, count(*) FROM trg p WHERE p.trgm = ANY (show_trgm('johanson')) GROUP BY 1 ORDER BY 2 DESC;
ROLLBACK;
BEGIN;
SET LOCAL ROLE app;
SELECT set_config('app.tenant_id','00000000-0000-0000-0000-000000000001',true) \g /dev/null
SELECT set_config('pg_trgm.word_similarity_threshold','0.5',true) \g /dev/null
SET LOCAL work_mem = '16MB';
-- pigeonhole: a key with >= m of the n query trigrams holds at least one of any r = n-m+1 of them; read the r rarest lists (counted up to a cap)
PREPARE h(text, int) AS
WITH qt AS MATERIALIZED (SELECT t, cardinality(show_trgm($1)) n FROM unnest(show_trgm($1)) t),
df AS MATERIALIZED (SELECT qt.t, (SELECT count(*) FROM (SELECT 1 FROM trg p WHERE p.tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND p.trgm = qt.t LIMIT $2) x) c, qt.n FROM qt),
rare AS MATERIALIZED (SELECT t FROM df ORDER BY c, t LIMIT (SELECT max(n) - ceil(0.5 * max(n))::int + 1 FROM df)),
cand AS MATERIALIZED (SELECT DISTINCT p.key_id FROM trg p WHERE p.tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND p.trgm = ANY (ARRAY(SELECT t FROM rare)))
SELECT count(*) FROM (SELECT c.key_id FROM cand c CROSS JOIN LATERAL (
  SELECT k.key, k.key_kind FROM keys k WHERE k.tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND k.key_id = c.key_id OFFSET 0) k
WHERE k.key_kind IN (1,2,3,4,5) AND $1 <% k.key LIMIT 10001) z;
\timing on
EXECUTE h('skrorsors10', 20000); EXECUTE h('skrorsors10', 20000);
EXECUTE h('pryia ramn', 20000); EXECUTE h('pryia ramn', 20000);
EXECUTE h('johanson', 20000); EXECUTE h('johanson', 20000);
EXECUTE h('zx0946z', 20000);
EXECUTE h('mullerberger', 20000); EXECUTE h('mullerberger', 20000);
EXECUTE h('raman', 20000); EXECUTE h('raman', 20000);
\timing off
\echo oracle: count of <% matches with no index (owner, RLS still on) vs pigeonhole route
RESET ROLE;
SET LOCAL ROLE app;
SELECT q, (SELECT count(*) FROM (SELECT 1 FROM keys k WHERE key_kind IN (1,2,3,4,5) AND q <% key LIMIT 10001) z) seq FROM unnest(array['skrorsors10','pryia ramn','johanson','mullerberger','raman']) q;
ROLLBACK;
BEGIN;
SELECT set_config('pg_trgm.word_similarity_threshold','0.5',true) \g /dev/null
SET LOCAL work_mem = '16MB';
-- superuser: RLS bypassed, so this is option (c)'s best case (GIN usable), filtered by tenant by hand
PREPARE g(text) AS SELECT count(*) FROM (SELECT key_id FROM keys k WHERE tenant_id='00000000-0000-0000-0000-000000000001' AND key_kind IN (1,2,3,4,5) AND $1 <% key LIMIT 10001) z;
\timing on
EXECUTE g('skrorsors10'); EXECUTE g('skrorsors10');
EXECUTE g('pryia ramn'); EXECUTE g('johanson'); EXECUTE g('johanson'); EXECUTE g('zx0946z'); EXECUTE g('mullerberger'); EXECUTE g('mullerberger'); EXECUTE g('raman'); EXECUTE g('raman');
\timing off
EXPLAIN (ANALYZE, COSTS off) EXECUTE g('johanson');
ROLLBACK;
CREATE ROLE definer NOLOGIN NOBYPASSRLS;
GRANT SELECT ON keys TO definer;
CREATE POLICY definer_all ON keys FOR SELECT TO definer USING (true);
BEGIN;
SET LOCAL ROLE definer;
SELECT set_config('pg_trgm.word_similarity_threshold','0.5',true) \g /dev/null
EXPLAIN (COSTS off) SELECT key_id FROM keys k WHERE tenant_id='00000000-0000-0000-0000-000000000001' AND key_kind IN (1,2,3,4,5) AND 'johanson' <% key LIMIT 10001;
ROLLBACK;
DROP POLICY definer_all ON keys; REVOKE ALL ON keys FROM definer; DROP ROLE definer;
\timing on
CREATE TABLE trg2 (tenant_id uuid not null, trgm text collate "C" not null, key_id bigint not null, primary key (tenant_id, trgm, key_id));
INSERT INTO trg2 SELECT tenant_id, t, key_id FROM keys, unnest(show_trgm(key)) t WHERE key_kind IN (1,3) AND tenant_id='00000000-0000-0000-0000-000000000001';
\timing off
VACUUM ANALYZE trg2;
ALTER TABLE trg2 ENABLE ROW LEVEL SECURITY; ALTER TABLE trg2 FORCE ROW LEVEL SECURITY;
CREATE POLICY p ON trg2 USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
GRANT SELECT ON trg2 TO app;
SELECT count(*), pg_size_pretty(pg_total_relation_size('trg2')) FROM trg2;
BEGIN;
SET LOCAL ROLE app;
SELECT set_config('app.tenant_id','00000000-0000-0000-0000-000000000001',true) \g /dev/null
SELECT set_config('pg_trgm.word_similarity_threshold','0.5',true) \g /dev/null
SET LOCAL work_mem = '16MB';
PREPARE f(text) AS
WITH qt AS MATERIALIZED (SELECT show_trgm($1) a),
cand AS MATERIALIZED (
  SELECT p.key_id FROM trg2 p
  WHERE p.tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND p.trgm = ANY ((SELECT a FROM qt)::text[])
  GROUP BY p.key_id
  HAVING count(*) >= ceil(0.5 * (SELECT cardinality(a) FROM qt)))
SELECT count(*) FROM (SELECT c.key_id FROM cand c CROSS JOIN LATERAL (
  SELECT k.key, k.key_kind FROM keys k WHERE k.tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND k.key_id = c.key_id OFFSET 0) k
WHERE $1 <% k.key LIMIT 10001) z;
\timing on
EXECUTE f('skrorsors10'); EXECUTE f('skrorsors10');
EXECUTE f('pryia ramn'); EXECUTE f('pryia ramn');
EXECUTE f('johanson'); EXECUTE f('johanson');
EXECUTE f('zx0946z');
EXECUTE f('mullerberger'); EXECUTE f('mullerberger');
EXECUTE f('raman'); EXECUTE f('raman');
ROLLBACK;

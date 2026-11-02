package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/tools/fitness/internal/boundtest"
)

const mod = "example.test/m"

func write(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for p, c := range files {
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// base is a small repository that has the search packages and obeys every rule.
func base() map[string]string {
	return map[string]string{
		"go.mod": "module " + mod + "\n\ngo 1.22\n",
		"internal/platform/authz/authz.go": `package authz

type ReadScope struct{ n int }

func (s ReadScope) Terms() []int          { return nil }
func (s ReadScope) Token() (int, bool)    { return 0, false }
func (s ReadScope) Connections() []int    { return nil }
func (s ReadScope) Admits(v int) bool     { return v > s.n }
func (s ReadScope) SearchRoots(c int) []int { return nil }
`,
		"internal/platform/rbac/rbac.go": `package rbac

const countRoles = "SELECT count(*) FROM public.authz_roles"
`,
		"internal/platform/store/like.go": `package store

type LikePattern struct{ p string }

func (LikePattern) Prefix(s string) (LikePattern, error) { return LikePattern{s + "%"}, nil }
`,
		"internal/platform/store/localsetting.go": `package store

const setThreshold = "SELECT set_config('pg_trgm.word_similarity_threshold', $1, true)"
`,
		"internal/platform/store/reportsql/scope.go": `package reportsql

import "` + mod + `/internal/platform/authz"

func scope(s authz.ReadScope) int { return len(s.Terms()) }
`,
		"internal/platform/store/reportsql/search.go": `package reportsql

import "errors"

var errBad = errors.New("like a bad pattern")

type Search struct{}

// CompileSearch is the one statement.
func (Search) CompileSearch() string {
	return "SELECT k.object_guid FROM inventory_search_keys k WHERE k.key_kind = 1 AND " + "$1 <% k.key AND k.key % $2 ORDER BY k.key <-> $1 LIMIT 10"
}
`,
		"internal/directory/inventory/inventory.go": `package inventory

import "` + mod + `/internal/platform/store/reportsql"

const writeKeys = "INSERT INTO public.inventory_search_keys (object_guid, key) VALUES ($1, $2)"
const deleteKeys = "DELETE FROM public.inventory_search_keys WHERE object_guid = $1"
const backfill = "SELECT k.connection_id, k.object_guid, k.norm_version FROM public.inventory_search_keys k WHERE k.norm_version <> $1"

func Compile(s reportsql.Search) string { return s.CompileSearch() }
`,
		"internal/modules/search/search.go": `package search

import "` + mod + `/internal/platform/authz"

func Fresh(s authz.ReadScope) int { return len(s.Connections()) }
`,
		"internal/platform/store/owners/owners.gen.tsv": "# generated\nauthz_roles\tauthz\tconfig\nauthz_assignments\tauthz\tconfig\n",
		"migrations/0001_base.sql": `CREATE TABLE public.authz_roles (id int);
CREATE TABLE public.inventory_search_keys (key text, key_kind int);
CREATE INDEX k_trgm ON public.inventory_search_keys USING gin (key gin_trgm_ops);
CREATE FUNCTION public.authz_tier2_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.id < 0 THEN RAISE EXCEPTION 'bad id % in authz_roles', NEW.id; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER authz_roles_tier2 BEFORE INSERT ON public.authz_roles FOR EACH ROW EXECUTE FUNCTION public.authz_tier2_guard();
-- a comment mentioning authz_roles and % and LIKE
DO $$ BEGIN PERFORM 1 WHERE 'abc' LIKE '%b%'; END $$;
`,
	}
}

func tree(t *testing.T, extra map[string]string, drop ...string) string {
	t.Helper()
	files := base()
	for k, v := range extra {
		files[k] = v
	}
	for _, d := range drop {
		delete(files, d)
	}
	root := t.TempDir()
	write(t, root, files)
	return root
}

func run(t *testing.T, root string, o Options) *Result {
	t.Helper()
	o.Root = root
	o.StaticOnly = o.StaticOnly || (o.Bindings == nil && !o.Nightly)
	if o.Exceptions == nil {
		o.Exceptions = []*exception{}
	}
	r, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func expect(t *testing.T, r *Result, check, rule, where, msg string) {
	t.Helper()
	for _, v := range r.Violations {
		if v.Check == check && strings.HasPrefix(v.Rule, rule) && strings.Contains(v.Where, where) && strings.Contains(v.Msg, msg) {
			return
		}
	}
	t.Fatalf("want %s [%s] at %q containing %q, got:\n%v", check, rule, where, msg, r.Violations)
}

func none(t *testing.T, r *Result) {
	t.Helper()
	if len(r.Violations) != 0 {
		t.Fatalf("want no violation, got:\n%v", r.Violations)
	}
}

func TestCleanTreePasses(t *testing.T) {
	r := run(t, tree(t, nil), Options{})
	none(t, r)
	if len(r.Pending) != 0 {
		t.Fatalf("a tree with every package has nothing pending: %v", r.Pending)
	}
	if len(r.Passed) < 2 {
		t.Fatalf("SE1 and SE2 ran and must be listed as passed: %v", r.Passed)
	}
}

// A tree without the search module is pending, not passing.
func TestAbsentSearchModuleIsPending(t *testing.T) {
	r := run(t, tree(t, nil, "internal/modules/search/search.go"), Options{})
	none(t, r)
	if got := strings.Join(r.Pending, ";"); !strings.Contains(got, "SE2 internal/modules/search") {
		t.Fatalf("pending: %v", r.Pending)
	}
	for _, p := range r.Passed {
		if strings.HasPrefix(p, "SE2") {
			t.Fatalf("SE2 must not pass while a part is pending: %v", r.Passed)
		}
	}
}

// ---- SE1: the scope ----

func TestSE1TermsAndTokenOutsideReportsql(t *testing.T) {
	r := run(t, tree(t, map[string]string{"internal/modules/reports/export/e.go": `package export

import "` + mod + `/internal/platform/authz"

func Leak(s authz.ReadScope) ([]int, bool) { v, ok := s.Token(); _ = v; return s.Terms(), ok }

var viaValue = authz.ReadScope.Terms
`}), Options{})
	expect(t, r, "SE1", "scope-renderer", "internal/modules/reports/export/e.go:5", "ReadScope.Token")
	expect(t, r, "SE1", "scope-renderer", "internal/modules/reports/export/e.go:5", "ReadScope.Terms")
	expect(t, r, "SE1", "scope-renderer", "internal/modules/reports/export/e.go:7", "ReadScope.Terms")
}

func TestSE1EmbeddingAndInterfacePromoteTheMethods(t *testing.T) {
	r := run(t, tree(t, map[string]string{"internal/modules/x/x.go": `package x

import "` + mod + `/internal/platform/authz"

type Holder struct{ authz.ReadScope }

type Renderer interface{ Terms() []int }
`}), Options{})
	expect(t, r, "SE1", "scope-embedding", "internal/modules/x/x.go:5", "embeds authz.ReadScope")
	expect(t, r, "SE1", "scope-interface", "internal/modules/x/x.go:7", "Terms")
}

func TestSE1AdmitsAndSearchRootsOutsideAuthz(t *testing.T) {
	r := run(t, tree(t, map[string]string{"internal/directory/client/c.go": `package client

import "` + mod + `/internal/platform/authz"

func f(s authz.ReadScope) bool { _ = s.SearchRoots(1); return s.Admits(2) }
`}), Options{})
	expect(t, r, "SE1", "scope-members", "internal/directory/client/c.go:5", "ReadScope.Admits")
	expect(t, r, "SE1", "scope-members", "internal/directory/client/c.go:5", "ReadScope.SearchRoots")
}

func TestSE1ListedExceptionIsPendingAndStaleOneFails(t *testing.T) {
	files := map[string]string{"internal/directory/client/usersearch.go": `package client

import "` + mod + `/internal/platform/authz"

func f(s authz.ReadScope) bool { return s.Admits(2) }
`}
	ex := func() []*exception {
		return []*exception{{Check: "SE1", Rule: "scope-members", File: "internal/directory/client/usersearch.go", Pending: true, Why: "T-1127"}}
	}
	r := run(t, tree(t, files), Options{Exceptions: ex()})
	none(t, r)
	if !strings.Contains(strings.Join(r.Pending, ";"), "usersearch.go") {
		t.Fatalf("the exception must be pending: %v", r.Pending)
	}
	// Another file is not covered by it.
	files["internal/directory/client/other.go"] = strings.Replace(files["internal/directory/client/usersearch.go"], "func f", "func g", 1)
	expect(t, run(t, tree(t, files), Options{Exceptions: ex()}), "SE1", "scope-members", "other.go:5", "Admits")
	// Once the file stops calling it the exception is stale.
	r = run(t, tree(t, nil), Options{Exceptions: ex()})
	expect(t, r, "SE1", "stale-exception", "usersearch.go", "no longer matches")
}

func TestSE1ConnectionsAllowedOnlyForFreshnessCallers(t *testing.T) {
	src := `package %s

import "` + mod + `/internal/platform/authz"

func f(s authz.ReadScope) int { return len(s.Connections()) }
`
	ok := run(t, tree(t, map[string]string{"internal/modules/reports/run/r.go": strings.Replace(src, "%s", "run", 1)}), Options{})
	none(t, ok)
	r := run(t, tree(t, map[string]string{"internal/modules/users/u.go": strings.Replace(src, "%s", "users", 1)}), Options{})
	expect(t, r, "SE1", "scope-connections", "internal/modules/users/u.go:5", "Connections")
}

func TestSE1CompileSearchOnlyFromInventory(t *testing.T) {
	r := run(t, tree(t, map[string]string{"internal/modules/search/s.go": `package search

import "` + mod + `/internal/platform/store/reportsql"

func Again(s reportsql.Search) string { return s.CompileSearch() }
`}), Options{})
	expect(t, r, "SE1", "compile-search", "internal/modules/search/s.go:5", "CompileSearch")
}

func TestSE1RBACTablesNamedInGoSQL(t *testing.T) {
	r := run(t, tree(t, map[string]string{
		"internal/compose/server/l.go":                  "package server\n\nconst q = `SELECT count(*) FROM public.authz_role_permissions`\n",
		"internal/modules/x/x.go":                       "package x\n\nconst q = \"DELETE FROM authz_future WHERE id = $1\"\n",
		"internal/platform/store/owners/owners.gen.tsv": "authz_roles\tauthz\tconfig\nauthz_future\trbac\tconfig\n",
	}), Options{})
	expect(t, r, "SE1", "rbac-table-sql", "internal/compose/server/l.go:3", "authz_role_permissions")
	expect(t, r, "SE1", "rbac-table-sql", "internal/modules/x/x.go:3", "authz_future")
	// rbac itself is fine (the base tree has one), and an error message is not SQL.
	r = run(t, tree(t, map[string]string{"internal/modules/y/y.go": "package y\n\nimport \"errors\"\n\nvar e = errors.New(\"authz_roles is empty\")\n"}), Options{})
	none(t, r)
}

func TestSE1MigrationsDefineNoObjectOverRBACTables(t *testing.T) {
	for name, sql := range map[string]string{
		"view":                      "CREATE VIEW v AS SELECT * FROM public.authz_assignments;",
		"matview":                   "CREATE MATERIALIZED VIEW v AS SELECT id FROM authz_roles;",
		"rule":                      "CREATE RULE r AS ON INSERT TO t DO ALSO INSERT INTO authz_roles VALUES (1);",
		"function":                  "CREATE FUNCTION f() RETURNS int LANGUAGE sql AS $$ SELECT count(*)::int FROM authz_roles $$;",
		"procedure":                 "CREATE PROCEDURE p() LANGUAGE sql AS $$ DELETE FROM authz_roles $$;",
		"format":                    "CREATE FUNCTION f() RETURNS void LANGUAGE plpgsql AS $$ BEGIN EXECUTE format('DELETE FROM %I', 'authz_roles'); END $$;",
		"do":                        "DO $$ BEGIN CREATE VIEW v AS SELECT * FROM authz_roles; END $$;",
		"unlisted trigger function": "CREATE FUNCTION f() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM 1 FROM authz_roles; RETURN NEW; END $$;",
	} {
		t.Run(name, func(t *testing.T) {
			r := run(t, tree(t, map[string]string{"migrations/0002_bad.sql": sql}), Options{})
			expect(t, r, "SE1", "rbac-derived-object", "migrations/0002_bad.sql:1", "authz_")
		})
	}
	// Policies, grants and indexes on the tables are allowed, as is a listed guard that is attached.
	ok := "CREATE POLICY p ON authz_roles USING (true);\nGRANT SELECT ON authz_roles TO app;\nCREATE INDEX i ON authz_roles (id);\nALTER TABLE authz_roles ENABLE ROW LEVEL SECURITY;"
	none(t, run(t, tree(t, map[string]string{"migrations/0002_ok.sql": ok}), Options{}))
}

func TestSE1ListedGuardMustBeAttached(t *testing.T) {
	files := base()
	files["migrations/0001_base.sql"] = strings.Replace(files["migrations/0001_base.sql"], "CREATE TRIGGER authz_roles_tier2 BEFORE INSERT ON public.authz_roles FOR EACH ROW EXECUTE FUNCTION public.authz_tier2_guard();", "", 1)
	root := t.TempDir()
	write(t, root, files)
	expect(t, run(t, root, Options{}), "SE1", "rbac-guard-detached", "migrations/0001_base.sql", "authz_tier2_guard")
}

func TestSE1OnlyTheTemplateReadsTheKeyTable(t *testing.T) {
	cases := map[string]string{
		"from":                  "SELECT key FROM public.inventory_search_keys WHERE key_kind = 1",
		"join":                  "SELECT o.id FROM objects o JOIN inventory_search_keys k ON k.object_guid = o.id",
		"subquery":              "SELECT id FROM objects WHERE id IN (SELECT object_guid FROM public.inventory_search_keys)",
		"backfill with key":     "SELECT k.connection_id, k.object_guid, k.norm_version, k.key FROM public.inventory_search_keys k",
		"backfill other column": "SELECT k.connection_id, k.object_guid, k.key_kind FROM public.inventory_search_keys k",
	}
	for name, q := range cases {
		t.Run(name, func(t *testing.T) {
			r := run(t, tree(t, map[string]string{"internal/modules/x/x.go": "package x\n\nconst q = `" + q + "`\n"}), Options{})
			expect(t, r, "SE1", "key-table-read", "internal/modules/x/x.go:3", "inventory_search_keys")
		})
	}
	// The inventory's own backfill (projection of three columns) and its writes pass; the same read
	// elsewhere does not.
	r := run(t, tree(t, map[string]string{"internal/modules/x/x.go": "package x\n\nconst q = `" + "SELECT k.connection_id, k.object_guid, k.norm_version FROM public.inventory_search_keys k" + "`\n"}), Options{})
	expect(t, r, "SE1", "key-table-read", "internal/modules/x/x.go:3", "backfill")
	// A query file counts as much as Go.
	r = run(t, tree(t, map[string]string{"internal/modules/x/q.sql": "SELECT key\nFROM inventory_search_keys;\n"}), Options{})
	expect(t, r, "SE1", "key-table-read", "internal/modules/x/q.sql:2", "inventory_search_keys")
}

func TestSE1MigrationsDefineNoObjectOverTheKeyTable(t *testing.T) {
	for name, sql := range map[string]string{
		"view":             "CREATE VIEW v AS SELECT key FROM inventory_search_keys;",
		"function":         "CREATE FUNCTION f() RETURNS bigint LANGUAGE sql AS $$ SELECT count(*) FROM public.inventory_search_keys $$;",
		"trigger function": "CREATE FUNCTION f() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN DELETE FROM inventory_search_keys; RETURN NEW; END $$;",
	} {
		t.Run(name, func(t *testing.T) {
			r := run(t, tree(t, map[string]string{"migrations/0002_bad.sql": sql}), Options{})
			expect(t, r, "SE1", "key-table-derived-object", "migrations/0002_bad.sql:1", "inventory_search_keys")
		})
	}
}

// ---- SE2 ----

func TestSE2PatternsInSearchSQL(t *testing.T) {
	for name, q := range map[string]string{
		"LIKE":       "SELECT id FROM t WHERE name LIKE 'a%'",
		"ILIKE":      "SELECT id FROM t WHERE name ilike 'a%'",
		"NOT LIKE":   "SELECT id FROM t WHERE name NOT LIKE 'a%'",
		"SIMILAR TO": "SELECT id FROM t WHERE name SIMILAR TO 'a|b'",
		"~":          "SELECT id FROM t WHERE name ~ '^a'",
		"~*":         "SELECT id FROM t WHERE name ~* '^a'",
		"!~":         "SELECT id FROM t WHERE name !~ '^a'",
		"~~":         "SELECT id FROM t WHERE name ~~ 'a%'",
		"regexp":     "SELECT regexp_matches(name, 'a') FROM t",
	} {
		for _, dir := range []string{"internal/directory/inventory", "internal/modules/search"} {
			t.Run(name+" in "+dir, func(t *testing.T) {
				r := run(t, tree(t, map[string]string{dir + "/bad.go": "package " + filepath.Base(dir) + "\n\nconst q = `" + q + "`\n"}), Options{})
				expect(t, r, "SE2", "pattern", dir+"/bad.go:3", "")
			})
		}
	}
	// the template itself is held to the same bans
	r := run(t, tree(t, map[string]string{"internal/platform/store/reportsql/search.go": `package reportsql

type Search struct{}

func (Search) CompileSearch() string {
	return "SELECT 1 FROM inventory_search_keys k WHERE k.key " + "ILIKE $1"
}
`}), Options{})
	expect(t, r, "SE2", "pattern", "internal/platform/store/reportsql/search.go:6", "ILIKE")
}

func TestSE2PatternsElsewhereAreNotBannedButBoundLikeIsChecked(t *testing.T) {
	// A literal pattern elsewhere in the repository is fine (store.go has one on main).
	r := run(t, tree(t, map[string]string{"internal/modules/x/x.go": "package x\n\nconst q = `SELECT 1 FROM pg_class WHERE relname NOT LIKE 'pg_toast%'`\n"}), Options{})
	none(t, r)
}

func TestSE2TrigramUseOutsideTheTemplate(t *testing.T) {
	for name, c := range map[string]struct{ file, text string }{
		"operator in Go":           {"internal/modules/x/x.go", "package x\n\nconst q = `SELECT 1 FROM t WHERE a % $1`\n"},
		"word operator in Go":      {"internal/modules/x/x.go", "package x\n\nconst q = `SELECT 1 FROM t WHERE $1 <% a`\n"},
		"distance operator":        {"internal/modules/x/x.go", "package x\n\nconst q = `SELECT 1 FROM t ORDER BY a <->> $1`\n"},
		"similarity in Go":         {"internal/modules/x/x.go", "package x\n\nconst q = `SELECT similarity(a, $1) FROM t`\n"},
		"show_limit in Go":         {"internal/modules/x/x.go", "package x\n\nconst q = `SELECT show_limit() FROM t`\n"},
		"operator in migration":    {"migrations/0002_bad.sql", "CREATE INDEX i ON t (a);\nSELECT 1 FROM t WHERE a % 'x';\n"},
		"function in migration":    {"migrations/0002_bad.sql", "CREATE FUNCTION f() RETURNS real LANGUAGE sql AS $$ SELECT word_similarity('a', 'b') $$;"},
		"operator in a function":   {"migrations/0002_bad.sql", "CREATE FUNCTION f() RETURNS bool LANGUAGE sql AS $$ SELECT 'a' %> 'b' $$;"},
		"operator in a query file": {"internal/modules/x/q.sql", "SELECT 1\nFROM t WHERE a <<% 'x';\n"},
	} {
		t.Run(name, func(t *testing.T) {
			r := run(t, tree(t, map[string]string{c.file: c.text}), Options{})
			expect(t, r, "SE2", "trigram-", c.file, "outside the reportsql search template")
		})
	}
}

// Strings and comments are skipped, so the % placeholders and LIKE literals of today's migrations pass.
func TestSE2SkipsStringsCommentsAndPlaceholders(t *testing.T) {
	sql := `-- % and <% in a comment
/* similarity(a, b) % c */
DO $$ BEGIN RAISE EXCEPTION 'bad value %: %', 1, 2; END $$;
SELECT 1 WHERE 'a' LIKE '%x%';
DO $$ DECLARE v public.t%ROWTYPE; BEGIN NULL; END $$;
SELECT format($p$CREATE POLICY %I ON %I$p$, 'a', 'b');
SELECT E'it\'s 100% % done';
`
	none(t, run(t, tree(t, map[string]string{"migrations/0002_ok.sql": sql}), Options{}))
	// printf verbs in a tool's format string are not operators; the same text in product code is.
	fmtSQL := "package x\n\nconst q = `ALTER SCHEMA public OWNER TO %1$I`\n"
	none(t, run(t, tree(t, map[string]string{"tools/fitness/pgharness/p.go": fmtSQL}), Options{}))
	expect(t, run(t, tree(t, map[string]string{"internal/modules/x/x.go": fmtSQL}), Options{}), "SE2", "trigram-operator", "internal/modules/x/x.go:3", "%")
}

func TestSE2Settings(t *testing.T) {
	for name, c := range map[string]struct{ file, text, rule string }{
		"SET":                   {"migrations/0002_bad.sql", "SET pg_trgm.similarity_threshold = 0.5;", "set-pg_trgm"},
		"SET SESSION":           {"migrations/0002_bad.sql", "SET SESSION pg_trgm.word_similarity_threshold TO 0.5;", "set-pg_trgm"},
		"ALTER ROLE SET":        {"migrations/0002_bad.sql", "ALTER ROLE app SET pg_trgm.word_similarity_threshold = 0.5;", "set-pg_trgm"},
		"set_config false":      {"internal/modules/x/x.go", "package x\n\nconst q = `SELECT set_config('app.tenant_id', $1, false)`\n", "set-config-persistent"},
		"set_config param":      {"internal/modules/x/x.go", "package x\n\nconst q = `SELECT set_config('app.tenant_id', $1, $2)`\n", "set-config-persistent"},
		"set_config two args":   {"migrations/0002_bad.sql", "SELECT set_config('app.x', 'y');", "set-config-persistent"},
		"set_config name":       {"internal/modules/x/x.go", "package x\n\nconst q = `SELECT set_config($1, $2, true)`\n", "set-config-name"},
		"pg_trgm elsewhere":     {"internal/modules/x/x.go", "package x\n\nconst q = `SELECT set_config('pg_trgm.word_similarity_threshold', $1, true)`\n", "set-config-pg_trgm"},
		"pg_trgm literal value": {"internal/platform/store/localsetting.go", "package store\n\nconst q = `SELECT set_config('pg_trgm.word_similarity_threshold', '0.9', true)`\n", "set-config-pg_trgm"},
	} {
		t.Run(name, func(t *testing.T) {
			r := run(t, tree(t, map[string]string{c.file: c.text}), Options{})
			expect(t, r, "SE2", c.rule, c.file, "")
		})
	}
	// transaction-local, with a literal true: fine, and so is reading the setting.
	ok := "package x\n\nconst q = `SELECT set_config('app.tenant_id', $1, true), current_setting('pg_trgm.word_similarity_threshold')`\n"
	none(t, run(t, tree(t, map[string]string{"internal/modules/x/x.go": ok}), Options{}))
}

func TestSE2ListedSetConfigExceptionIsANoteAndGoesStale(t *testing.T) {
	probe := "package tenancy\n\nconst q = `SELECT set_config('app.tenant_id', $1, $2)`\n"
	ex := func() []*exception {
		return []*exception{{Check: "SE2", Rule: "set-config-persistent", File: "tools/fitness/tenancy/probes.go", Why: "probe"}}
	}
	r := run(t, tree(t, map[string]string{"tools/fitness/tenancy/probes.go": probe}), Options{Exceptions: ex()})
	none(t, r)
	if len(r.Notes) != 1 {
		t.Fatalf("the exception is listed as a note: %v", r.Notes)
	}
	expect(t, run(t, tree(t, nil), Options{Exceptions: ex()}), "SE2", "stale-exception", "probes.go", "")
}

func TestSE2BoundLikeTakesALikePattern(t *testing.T) {
	call := func(arg string) map[string]string {
		return map[string]string{"internal/modules/x/x.go": `package x

import "` + mod + `/internal/platform/store"

type db struct{}

func (db) Query(sql string, args ...any) {}

const q = "SELECT 1 FROM t WHERE name LIKE $1 ESCAPE '\\'"

func f(d db, text string) {
	p, _ := store.LikePattern{}.Prefix(text)
	_ = p
	d.Query(q, ` + arg + `)
}
`}
	}
	none(t, run(t, tree(t, call("p")), Options{}))
	r := run(t, tree(t, call(`text + "%"`)), Options{})
	expect(t, r, "SE2", "like-operand", "internal/modules/x/x.go:14", "not store.LikePattern")
	// a constant that is never passed to a call cannot be verified
	r = run(t, tree(t, map[string]string{"internal/modules/x/x.go": "package x\n\nconst q = `SELECT 1 FROM t WHERE name ILIKE $1`\n"}), Options{})
	expect(t, r, "SE2", "like-operand-unverified", "internal/modules/x/x.go:3", "LikePattern")
	// a LIKE built by concatenation: the operand must be the binder taking a LikePattern
	chain := `package x

import "` + mod + `/internal/platform/store"

type binder struct{}

func (binder) bind(t string, v any) string { return "$1" }

func good(b binder, p store.LikePattern) string { return "name ILIKE " + b.bind("text", p) + " ESCAPE '\\'" }
func bad(b binder, s string) string { return "name ILIKE " + b.bind("text", s) }
func raw(s string) string { return "name LIKE " + s }
`
	r = run(t, tree(t, map[string]string{"internal/modules/x/x.go": chain}), Options{})
	expect(t, r, "SE2", "like-operand", "internal/modules/x/x.go:10", "not a store.LikePattern")
	expect(t, r, "SE2", "like-operand", "internal/modules/x/x.go:11", "not a store.LikePattern")
	for _, v := range r.Violations {
		if strings.Contains(v.Where, "x.go:9") {
			t.Fatalf("the typed binder call passes: %v", v)
		}
	}
}

func TestSE2SqlconstCoversTheSearchPackages(t *testing.T) {
	r := run(t, tree(t, map[string]string{"internal/directory/inventory/gen.go": "// Code generated by sqlc. DO NOT EDIT.\n\npackage inventory\n\nconst genQuery = \"SELECT 1\"\n"}), Options{})
	expect(t, r, "SE2", "sqlconst-coverage", "internal/directory/inventory/gen.go", "sqlc")
}

// ---- lexer ----

func TestLexer(t *testing.T) {
	kinds := func(src string) string {
		var b strings.Builder
		for _, x := range lexSQL(src, 1) {
			b.WriteString(string(x.kind) + ":" + x.text + " ")
		}
		return strings.TrimSpace(b.String())
	}
	for src, want := range map[string]string{
		"a % b":              "w:a o:% w:b",
		"a<->b":              "w:a o:<-> w:b",
		"a=-1":               "w:a o:= o:- n:1",
		"x <<<-> y":          "w:x o:<<<-> w:y",
		"'it''s %'":          "s:it's %",
		"-- % c\n a":         "w:a",
		"/* /* % */ */ a":    "w:a",
		"$1 <% k":            "p:$1 o:<% w:k",
		`"Q%" x`:             "q:Q% w:x",
		"f($$a % b$$)":       "w:f ,:( s:a % b ,:)",
		"AS $q$ x % y $q$ ;": "w:as {:$q$ w:x o:% w:y }:$q$ ,:;",
	} {
		if got := kinds(src); got != want {
			t.Errorf("%q: got %q want %q", src, got, want)
		}
	}
}

// ---- bound tests ----

// events renders go test -json output for the named tests and subtests.
func events(pkg string, results map[string]string) []byte {
	var b strings.Builder
	for name, action := range results {
		e, _ := json.Marshal(map[string]string{"Action": action, "Package": pkg, "Test": name})
		b.Write(e)
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

func bindingTree(t *testing.T, declared ...string) string {
	t.Helper()
	files := map[string]string{}
	for _, d := range declared {
		pkg, name, _ := strings.Cut(d, ":")
		files[pkg+"/x_test.go"] = "package p\n\nimport \"testing\"\n\nfunc " + name + "(t *testing.T) {}\n"
	}
	return tree(t, files)
}

func recorded(out map[string]map[string]string) boundtest.Runner {
	return func(_ context.Context, _ string, pkgs, _ []string) ([]byte, error) {
		var all []byte
		for _, p := range pkgs {
			all = append(all, events(p, out[p])...)
		}
		return all, nil
	}
}

var oneBinding = []binding{{Check: "SE5", Name: "Test_bounded", Pkg: "./internal/directory/inventory", Landed: true, Owner: "T-1095",
	Subtests: pg(), What: "bounded work"}}

func TestBindingsPendingWhenTheTestIsAbsent(t *testing.T) {
	bs := []binding{{Check: "SE4", Name: "Test_later", Pkg: "./internal/modules/search", Owner: "T-1096", What: "x"}}
	r := run(t, tree(t, nil), Options{Bindings: bs})
	none(t, r)
	if !strings.Contains(strings.Join(r.Pending, ";"), "SE4 Test_later (T-1096 has not landed it)") {
		t.Fatalf("pending: %v", r.Pending)
	}
}

func TestBindingDeclaredButNotMarkedLandedFails(t *testing.T) {
	bs := []binding{{Check: "SE4", Name: "Test_later", Pkg: "./internal/modules/search", Owner: "T-1096", What: "x"}}
	r := run(t, bindingTree(t, "internal/modules/search:Test_later"), Options{Bindings: bs})
	expect(t, r, "SE4", "binding-not-landed", "Test_later", "Landed")
}

func TestLandedBindingRequiresBothPostgresVersions(t *testing.T) {
	pkg := "./internal/directory/inventory"
	root := bindingTree(t, "internal/directory/inventory:Test_bounded")
	full := map[string]string{"Test_bounded": "pass", "Test_bounded/pg16": "pass", "Test_bounded/pg18": "pass"}
	none(t, run(t, root, Options{Bindings: oneBinding, Runner: recorded(map[string]map[string]string{pkg: full})}))

	// pg18 never ran
	r := run(t, root, Options{Bindings: oneBinding, Runner: recorded(map[string]map[string]string{pkg: {"Test_bounded": "pass", "Test_bounded/pg16": "pass"}})})
	expect(t, r, "SE5", "subtest-missing", "Test_bounded/pg18", "")
	// pg16 skipped (no Docker): not a pass
	r = run(t, root, Options{Bindings: oneBinding, Runner: recorded(map[string]map[string]string{pkg: {"Test_bounded": "pass", "Test_bounded/pg16": "skip", "Test_bounded/pg18": "pass"}})})
	expect(t, r, "SE5", "subtest-skip", "Test_bounded/pg16", "")
	// the test failed
	r = run(t, root, Options{Bindings: oneBinding, Runner: recorded(map[string]map[string]string{pkg: {"Test_bounded": "fail", "Test_bounded/pg16": "fail", "Test_bounded/pg18": "pass"}})})
	expect(t, r, "SE5", "test-failed", "Test_bounded", "")
	// the test was deleted
	r = run(t, root, Options{Bindings: oneBinding, Runner: recorded(map[string]map[string]string{pkg: {}})})
	expect(t, r, "SE5", "test-missing", "Test_bounded", "")
}

func TestDefaultBindingsCoverSE3ToSE6AndKnowTheirPackages(t *testing.T) {
	seen := map[string]bool{}
	for _, b := range defaultBindings {
		seen[b.Check] = true
		if b.Name == "" || b.Pkg == "" || b.What == "" || b.Owner == "" {
			t.Errorf("incomplete binding: %+v", b)
		}
		if b.Landed && b.Nightly && b.Check != "SE6" {
			t.Errorf("only SE6 runs nightly: %+v", b)
		}
	}
	for _, c := range []string{"SE3", "SE4", "SE5", "SE6"} {
		if !seen[c] {
			t.Errorf("no binding for %s", c)
		}
	}
}

func TestNightlyRunsOnlySE6(t *testing.T) {
	bs := []binding{
		{Check: "SE5", Name: "Test_bounded", Pkg: "./internal/directory/inventory", Landed: true, Owner: "T-1095", What: "x"},
		{Check: "SE6", Name: "TestSearchLatency50k", Pkg: "./internal/modules/search/latency", Nightly: true, Landed: true, Owner: "T-1102", Subtests: []string{"pg16", "pg18"}, What: "latency"},
	}
	root := bindingTree(t, "internal/modules/search/latency:TestSearchLatency50k")
	pkg := "./internal/modules/search/latency"
	ok := recorded(map[string]map[string]string{pkg: {"TestSearchLatency50k": "pass", "TestSearchLatency50k/pg16": "pass", "TestSearchLatency50k/pg18": "pass"}})
	r := run(t, root, Options{Nightly: true, Bindings: bs, Runner: ok})
	none(t, r)
	if len(r.Passed) != 1 || !strings.HasPrefix(r.Passed[0], "SE6") {
		t.Fatalf("passed: %v", r.Passed)
	}
	// a miss in the benchmark fails the nightly
	miss := recorded(map[string]map[string]string{pkg: {"TestSearchLatency50k": "fail", "TestSearchLatency50k/pg16": "pass", "TestSearchLatency50k/pg18": "fail"}})
	expect(t, run(t, root, Options{Nightly: true, Bindings: bs, Runner: miss}), "SE6", "test-failed", "TestSearchLatency50k", "")
	// the per-change job does not run SE6 and lists it landed-but-nightly without a violation
	r = run(t, root, Options{Bindings: bs, Runner: recorded(map[string]map[string]string{"./internal/directory/inventory": {"Test_bounded": "pass"}})})
	none(t, r)
	// not landed: pending in both jobs
	bs[1].Landed = false
	r = run(t, tree(t, nil), Options{Bindings: bs, Runner: recorded(nil)})
	if !strings.Contains(strings.Join(r.Pending, ";"), "SE6 TestSearchLatency50k") {
		t.Fatalf("pending: %v", r.Pending)
	}
}

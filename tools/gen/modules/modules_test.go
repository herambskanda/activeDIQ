package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

func fsOf(files map[string]string) fstest.MapFS {
	m := fstest.MapFS{}
	for n, c := range files {
		m[n] = &fstest.MapFile{Data: []byte(c)}
	}
	return m
}

const good = `-- 0001_tenant_tenants: header mentioning CREATE TABLE public.nothing ( in prose.
-- write-class: tenants system
CREATE TABLE public.tenants (id uuid PRIMARY KEY);
`

func TestParseReadsOwnerFromFileNameAndClassFromLine(t *testing.T) {
	got, err := Parse(fsOf(map[string]string{
		"0001_tenant_tenants.sql": good,
		"0002_authz_rbac.sql": "-- write-class: authz_roles config\nCREATE TABLE public.authz_roles (id int);\n" +
			"-- write-class: authz_log system\nCREATE TABLE authz_log (id int);\n" +
			"CREATE FUNCTION f() RETURNS trigger AS $fn$ BEGIN RETURN NEW; END $fn$ LANGUAGE plpgsql;\n",
	}))
	if err != nil {
		t.Fatal(err)
	}
	want := []Entry{
		{Table: "authz_log", Owner: "authz", Class: System},
		{Table: "authz_roles", Owner: "authz", Class: Config},
		{Table: "tenants", Owner: "tenant", Class: System},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i := range want {
		if got[i].Table != want[i].Table || got[i].Owner != want[i].Owner || got[i].Class != want[i].Class {
			t.Errorf("entry %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestPartitionTakesItsParentsClass(t *testing.T) {
	got, err := Parse(fsOf(map[string]string{
		"0001_audit_event.sql": "-- write-class: audit_event system\nCREATE TABLE public.audit_event (id int) PARTITION BY RANGE (id);\n" +
			"CREATE TABLE public.audit_event_p1 PARTITION OF public.audit_event FOR VALUES FROM (0) TO (10);\n",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[1].Table != "audit_event_p1" || got[1].Class != System {
		t.Fatalf("got %+v", got)
	}
}

// Each case is a violation the generator must refuse, with the reason it must give.
func TestParseRefuses(t *testing.T) {
	for name, tc := range map[string]struct {
		files map[string]string
		want  string
	}{
		"table with no class":       {map[string]string{"0001_a_b.sql": "CREATE TABLE public.t (id int);\n"}, "has no `-- write-class: t config|system` line"},
		"unknown class":             {map[string]string{"0001_a_b.sql": "-- write-class: t other\nCREATE TABLE public.t (id int);\n"}, `"other" is neither config nor system`},
		"malformed class line":      {map[string]string{"0001_a_b.sql": "-- write-class: t\nCREATE TABLE public.t (id int);\n"}, "malformed write-class line"},
		"class for a foreign table": {map[string]string{"0001_a_b.sql": "-- write-class: t system\nCREATE TABLE public.t (id int);\n", "0002_c_d.sql": "-- write-class: t config\n"}, "which this file does not create"},
		"class declared twice":      {map[string]string{"0001_a_b.sql": "-- write-class: t system\n-- write-class: t config\nCREATE TABLE public.t (id int);\n"}, "declared twice"},
		"table created twice":       {map[string]string{"0001_a_b.sql": "-- write-class: t system\nCREATE TABLE public.t (id int);\n", "0002_c_d.sql": "-- write-class: t system\nCREATE TABLE public.t (id int);\n"}, "already created by 0001_a_b.sql"},
		"drop table":                {map[string]string{"0001_a_b.sql": "-- write-class: t system\nCREATE TABLE public.t (id int);\nDROP TABLE public.t;\n"}, "DROP TABLE and table renames"},
		"rename table":              {map[string]string{"0001_a_b.sql": "-- write-class: t system\nCREATE TABLE public.t (id int);\nALTER TABLE public.t RENAME TO u;\n"}, "DROP TABLE and table renames"},
		"create in a DO block":      {map[string]string{"0001_a_b.sql": "DO $do$\nBEGIN\n  CREATE TABLE public.hidden (id int);\nEND\n$do$;\n"}, "inside a function or DO body"},
		"unreadable create form":    {map[string]string{"0001_a_b.sql": "CREATE TEMP TABLE t (id int);\n"}, "cannot read"},
		"quoted table name":         {map[string]string{"0001_a_b.sql": "CREATE TABLE public.\"T\" (id int);\n"}, "cannot read"},
		"bad file name":             {map[string]string{"1_a.sql": "\n"}, "not named NNNN_<owner>_<what>.sql"},
		"partition declares class":  {map[string]string{"0001_a_b.sql": "-- write-class: p system\nCREATE TABLE public.p (id int);\n-- write-class: c system\nCREATE TABLE public.c PARTITION OF public.p FOR VALUES IN (1);\n"}, "takes its parent"},
		"partition of unknown":      {map[string]string{"0001_a_b.sql": "CREATE TABLE public.c PARTITION OF public.p FOR VALUES IN (1);\n"}, "which no migration creates"},
		"partition across owners":   {map[string]string{"0001_a_b.sql": "-- write-class: p system\nCREATE TABLE public.p (id int);\n", "0002_c_d.sql": "CREATE TABLE public.c PARTITION OF public.p FOR VALUES IN (1);\n"}, "owned by a"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(fsOf(tc.files))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

func TestRenderIsDeterministicData(t *testing.T) {
	es := []Entry{{Table: "a", Owner: "x", Class: Config}, {Table: "bb", Owner: "y", Class: System}}
	a, err := Render(es)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Render(es)
	if string(a) != string(b) || !strings.HasPrefix(string(a), "# Generated by tools/gen/modules") {
		t.Fatalf("render:\n%s", a)
	}
	for _, want := range []string{"\na\tx\tconfig\n", "\nbb\ty\tsystem\n"} {
		if !strings.Contains(string(a), want) {
			t.Errorf("missing %q in\n%s", want, a)
		}
	}
}

// -check on a scratch copy of the repository layout: a clean tree passes; a stale, hand-edited or missing
// file fails; and a migration that gains a table without a class stops generation.
func TestCheckFailsOnDrift(t *testing.T) {
	root := t.TempDir()
	mig := filepath.Join(root, "migrations")
	if err := os.MkdirAll(mig, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, filepath.Dir(out)), 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(p, c string) {
		t.Helper()
		if err := os.WriteFile(p, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(mig, "0001_tenant_tenants.sql"), good)
	if err := run(root, true); err == nil || !strings.Contains(err.Error(), "is missing") {
		t.Fatalf("no generated file: %v", err)
	}
	if err := run(root, false); err != nil {
		t.Fatal(err)
	}
	if err := run(root, true); err != nil {
		t.Fatalf("clean tree: %v", err)
	}
	gen := filepath.Join(root, out)
	orig, _ := os.ReadFile(gen)
	write(gen, strings.Replace(string(orig), "\tsystem\n", "\tconfig\n", 1))
	if err := run(root, true); err == nil || !strings.Contains(err.Error(), "stale or hand-edited") {
		t.Fatalf("hand-edited file: %v", err)
	}
	write(gen, string(orig))
	write(filepath.Join(mig, "0002_authz_rbac.sql"), "-- write-class: authz_roles config\nCREATE TABLE public.authz_roles (id int);\n")
	if err := run(root, true); err == nil || !strings.Contains(err.Error(), "stale or hand-edited") {
		t.Fatalf("new table, file not regenerated: %v", err)
	}
	write(filepath.Join(mig, "0002_authz_rbac.sql"), "CREATE TABLE public.authz_roles (id int);\n")
	if err := run(root, true); err == nil || !strings.Contains(err.Error(), "no `-- write-class:") {
		t.Fatalf("new table without a class: %v", err)
	}
}

// The committed migrations and owners.gen.tsv agree (the same comparison as `make gen-modules-check`),
// and the facts other tickets rely on hold.
func TestRepositoryMapIsCurrent(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	if err := run(root, true); err != nil {
		t.Fatal(err)
	}
	es, err := Parse(os.DirFS(filepath.Join(root, "migrations")))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Entry{}
	for _, e := range es {
		got[e.Table] = e
	}
	for table, want := range map[string]Entry{
		"report_runs":       {Owner: "reports", Class: System},
		"report_run_rows":   {Owner: "reports", Class: System},
		"directory_objects": {Owner: "inventory", Class: System},
		"inventory_servers": {Owner: "invhost", Class: Config},
		"authz_roles":       {Owner: "authz", Class: Config},
		"audit_event":       {Owner: "audit", Class: System},
	} {
		if g := got[table]; g.Owner != want.Owner || g.Class != want.Class {
			t.Errorf("%s = %s/%s, want %s/%s", table, g.Owner, g.Class, want.Owner, want.Class)
		}
	}
}

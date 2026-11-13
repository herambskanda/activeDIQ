package main

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/skenzeriq/activediq/tools/analyzers"
	"github.com/skenzeriq/activediq/tools/analyzers/policy"
	"github.com/skenzeriq/activediq/tools/fitness/internal/boundtest"
)

// Violation is one failed rule. Check is SE1..SE6, Rule names the rule inside the check.
type Violation struct{ Check, Rule, Where, Msg string }

func (v Violation) String() string {
	return fmt.Sprintf("%s %s [%s]: %s", v.Where, v.Check, v.Rule, v.Msg)
}

// Options configures one run.
type Options struct {
	Root string
	// StaticOnly skips the bound tests (used by the gate proofs).
	StaticOnly bool
	// Nightly runs only the nightly bindings (SE6, behind the large-dataset switch).
	Nightly bool
	// Runner runs the bound tests; nil means go test. Tests inject recorded output.
	Runner boundtest.Runner
	// Bindings overrides the bound-test table; nil means defaultBindings.
	Bindings []binding
	// Exceptions overrides the exception list; nil means defaultExceptions.
	Exceptions []*exception
}

// Result is everything a run found. Pending lists parts whose code has not landed. Passed lists each
// check that ran and found nothing, so the CI log itself is the evidence ADR-0011 cites when it moves to
// accepted.
type Result struct {
	Violations []Violation
	Pending    []string
	Notes      []string
	Passed     []string
}

// Run executes every check.
func Run(ctx context.Context, o Options) (*Result, error) {
	res := &Result{}
	bs := o.Bindings
	if bs == nil {
		bs = defaultBindings
	}
	run := o.Runner
	if run == nil {
		run = boundtest.GoTest
	}
	var ran []string
	if o.Nightly {
		bv, bp, br, err := runBindings(ctx, o.Root, bs, true, run)
		if err != nil {
			return nil, err
		}
		res.Violations, res.Pending, ran = bv, bp, br
		res.Passed = passed(ran, res.Pending, res.Violations)
		return res, nil
	}

	ex := o.Exceptions
	if ex == nil {
		ex = defaultExceptions()
	}
	st, err := checkStatic(o.Root, ex)
	if err != nil {
		return nil, err
	}
	res.Violations = append(res.Violations, st.Violations...)
	res.Pending = append(res.Pending, st.Pending...)
	ran = append(ran,
		"SE1 ReadScope callers, CompileSearch caller, RBAC tables in Go SQL and migrations, search key table readers",
		"SE2 pattern, trigram and set_config bans in SQL text; bound LIKE operands; sqlconst coverage")

	sq, err := checkSQLText(o.Root, st, ex)
	if err != nil {
		return nil, err
	}
	res.Violations = append(res.Violations, sq.Violations...)
	res.Pending = append(res.Pending, sq.Pending...)
	for _, e := range ex {
		if e.Pending && e.used {
			res.Pending = append(res.Pending, fmt.Sprintf("%s %s in %s (%s)", e.Check, e.Rule, e.File, e.Why))
		} else if e.used {
			res.Notes = append(res.Notes, fmt.Sprintf("%s %s: %s is a listed exception (%s)", e.Check, e.Rule, e.File, e.Why))
		}
	}
	for _, e := range ex {
		if !e.used {
			res.Violations = append(res.Violations, Violation{e.Check, "stale-exception", e.File + ":1", "the listed exception (" + e.Rule + ") no longer matches anything: delete it from defaultExceptions in tools/fitness/search/static.go (" + e.Why + ")"})
		}
	}

	if !o.StaticOnly {
		bv, bp, br, err := runBindings(ctx, o.Root, bs, false, run)
		if err != nil {
			return nil, err
		}
		res.Violations = append(res.Violations, bv...)
		res.Pending = append(res.Pending, bp...)
		ran = append(ran, br...)
	}
	res.Passed = passed(ran, res.Pending, res.Violations)
	sort.SliceStable(res.Violations, func(i, j int) bool {
		a, b := res.Violations[i], res.Violations[j]
		if a.Check != b.Check {
			return a.Check < b.Check
		}
		return a.Where < b.Where
	})
	return res, nil
}

// passed keeps each part that ran with nothing pending or failing against it. SE1 and SE2 are listed per
// check, so a pending or failing part of one withdraws the whole line. A bound test ("SEn TestName (pkg)")
// stands alone: it is a pass when it ran and no violation names it, whatever else of its check is pending.
func passed(ran, pending []string, vs []Violation) []string {
	bad := map[string]bool{}
	for _, p := range pending {
		bad[checkOf(p)] = true
	}
	for _, v := range vs {
		bad[v.Check] = true
	}
	var out []string
	for _, r := range ran {
		if name := testOf(r); name != "" {
			failed := false
			for _, v := range vs {
				if v.Check == checkOf(r) && strings.Contains(v.Where, name) {
					failed = true
				}
			}
			if !failed {
				out = append(out, r)
			}
			continue
		}
		if !bad[checkOf(r)] {
			out = append(out, r)
		}
	}
	return out
}

// testOf is the test name of a bound-test entry ("SE3 Test_x (./pkg)"), or "" for a static line.
func testOf(s string) string {
	_, rest, _ := strings.Cut(s, " ")
	name, _, _ := strings.Cut(rest, " ")
	if strings.HasPrefix(name, "Test") {
		return name
	}
	return ""
}

func checkOf(s string) string { c, _, _ := strings.Cut(s, " "); return c }

type sqlResult struct {
	Violations []Violation
	Pending    []string
}

// skipDirs are never walked for SQL files.
var skipDirs = map[string]bool{".git": true, "node_modules": true, "testdata": true, "vendor": true, "web": true, "factory": true, "knowledge": true, ".activeDIQ-worktrees": true, "garage": true}

// selfDir is this tool: its fixtures and messages quote the SQL they forbid.
const selfDir = "tools/fitness/search"

func productCode(file string) bool { return under(file, "internal") || under(file, "cmd") }

// scopeFor says which SE2 bans apply to SQL found in file.
func scopeFor(file string) (sqlScope, bool) {
	switch {
	case file == templateFile:
		return scopeTemplate, true
	case under(file, inventoryDir) || under(file, searchDir):
		return scopeSearch, true
	}
	return scopeRepo, false
}

// printfVerb matches a printf verb: a string with one is a format string, and its % is not an operator.
var printfVerb = regexp.MustCompile(`%[0-9.+#\-]*(\[[0-9]+\])?[0-9]*\$?[bcdeEfFgGoOpqstTvxXUI]`)

// looksSQL says whether a Go string constant is SQL text rather than prose: it starts with a statement
// keyword and holds a clause keyword. Strings in the search template are all SQL fragments.
func looksSQL(toks []tok) bool {
	if len(toks) < 2 || toks[0].kind != tWord {
		return false
	}
	switch toks[0].text {
	case "select", "insert", "update", "delete", "with", "create", "alter", "drop", "set", "grant", "revoke", "do", "explain", "copy", "merge", "values", "truncate", "call", "lock", "comment":
	default:
		return false
	}
	for _, t := range toks[1:] {
		if t.kind == tWord {
			switch t.text {
			case "from", "into", "set", "values", "table", "index", "view", "function", "where", "join", "as", "select", "policy", "trigger", "extension", "role", "on", "to":
				return true
			}
		}
		if t.kind == tPunct && t.text == "(" {
			return toks[0].text == "select" || toks[0].text == "with"
		}
	}
	return false
}

// checkSQLText applies the text rules to the Go string constants and the .sql files of the tree.
func checkSQLText(root string, st *staticResult, ex []*exception) (*sqlResult, error) {
	out := &sqlResult{}
	seen := map[string]bool{}
	add := func(check, rule, file string, line int, msg string) {
		for _, e := range ex {
			if e.Check == check && e.Rule == rule && e.File == file {
				e.used = true
				return
			}
		}
		v := Violation{check, rule, fmt.Sprintf("%s:%d", file, line), msg}
		if k := v.String(); !seen[k] {
			seen[k] = true
			out.Violations = append(out.Violations, v)
		}
	}
	extra := extraRBACTables(root)
	rbacOwned := func(file string) bool { return under(file, rbacDir) || under(file, authzDir) }
	allRBAC := append(append([]string{}, rbacTables...), extra...)

	// ---- Go string constants ----
	for _, sc := range st.Consts {
		if under(sc.File, selfDir) || sc.inErrCall {
			continue
		}
		toks := lexSQL(sc.Value, sc.Line)
		scope, inSearch := scopeFor(sc.File)
		sql := scope == scopeTemplate || looksSQL(toks)
		if sql {
			for _, stmt := range splitStatements(toks) {
				for _, f := range checkSE2(stmt, sqlOpts{scope: scope, trgmSetting: sc.File == trgmSettingFile, format: !productCode(sc.File) && printfVerb.MatchString(sc.Value)}) {
					add(f.Check, f.Rule, sc.File, f.Line, f.Msg)
				}
			}
		}
		_ = inSearch
		if !productCode(sc.File) {
			continue
		}
		if !rbacOwned(sc.File) {
			for _, tbl := range allRBAC {
				if line, ok := namesInside(toks, tbl); ok {
					add("SE1", "rbac-table-sql", sc.File, line, "Go code names the RBAC table "+tbl+": only "+rbacDir+" and "+authzDir+" read or write the RBAC tables, everything else asks rbac (ADR-0011 SE1)")
					break
				}
			}
		}
		if sc.File == templateFile {
			continue
		}
		if line, ok := namesInside(toks, postingTable); ok && looksSQL(toks) {
			add("SE1", "posting-table-sql", sc.File, line, "Go code names "+postingTable+": only the reportsql search template reads the trigram postings and the migration triggers are the only writer (ADR-0011 SE1, rule 5a)")
		}
		for _, stmt := range splitStatements(toks) {
			for _, at := range keyTableReads(stmt) {
				if under(sc.File, inventoryDir) && backfillProjection(stmt, at) {
					continue
				}
				add("SE1", "key-table-read", sc.File, stmt[at].line, "SQL reads "+keyTable+": only the reportsql search template reads the key table; "+inventoryDir+" may INSERT, UPDATE and DELETE it and has one allowed read, the backfill query that projects only (connection_id, object_guid, norm_version) (ADR-0011 SE1)")
			}
		}
	}

	// ---- sqlconst covers the search packages ----
	for _, dir := range []string{inventoryDir, searchDir, reportsqlDir} {
		files := st.Files[dir]
		if len(files) == 0 && dir == searchDir {
			out.Pending = append(out.Pending, "SE2 "+searchDir+" (has not landed: T-1096; the rules apply to it the moment it exists)")
		}
		for _, f := range files {
			if firstLine(filepath.Join(root, filepath.FromSlash(f))) == sqlcHeader {
				add("SE2", "sqlconst-coverage", f, 1, "a file under "+dir+" carries the sqlc-generated header, which exempts it from the sqlconst analyser (FF-SP2/RP1): search code is covered, so generated query code does not belong here (ADR-0011 SE2)")
			}
		}
		for _, fw := range policy.SQLForwarders {
			if under(fw.Pkg, dir) {
				add("SE2", "sqlconst-coverage", fw.Pkg, 1, "policy.SQLForwarders lists a wrapper in "+dir+", which exempts its callers' SQL from sqlconst: search packages are covered (ADR-0011 SE2)")
			}
		}
	}
	if st.Files[reportsqlDir] != nil && !fileExists(filepath.Join(root, filepath.FromSlash(templateFile))) {
		out.Pending = append(out.Pending, "SE2 the reportsql search template ("+templateFile+" has not landed: T-1095)")
	}
	haveSqlconst := false
	for _, a := range analyzers.All() {
		haveSqlconst = haveSqlconst || a.Name == "sqlconst"
	}
	if !haveSqlconst {
		add("SE2", "sqlconst-coverage", "tools/analyzers/analyzers.go", 1, "the sqlconst analyser is not in analyzers.All(), so no SQL text is checked for being constant (FF-SP2)")
	}

	// ---- .sql files: migrations and query files ----
	type sqlFile struct {
		rel   string
		stmts [][]tok
	}
	var files []sqlFile
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDirs[d.Name()] && p != root {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".sql") {
			return nil
		}
		rel := relSlash(root, p)
		if !(under(rel, "migrations") || productCode(rel)) {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		files = append(files, sqlFile{rel, splitStatements(lexSQL(string(b), 1))})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].rel < files[j].rel })
	var migrations [][]tok
	for _, f := range files {
		if under(f.rel, "migrations") {
			migrations = append(migrations, f.stmts...)
		}
	}
	attached := triggerAttachments(migrations)
	var migFiles []migStmts
	for _, f := range files {
		if under(f.rel, "migrations") {
			migFiles = append(migFiles, migStmts{f.rel, f.stmts})
		}
	}
	for _, fi := range checkSearchTables(migFiles) {
		add(fi.Check, fi.Rule, fi.file, fi.Line, fi.Msg)
	}
	for _, f := range files {
		scope, _ := scopeFor(f.rel)
		isMigration := under(f.rel, "migrations")
		if scope == scopeTemplate {
			scope = scopeSearch
		}
		for _, stmt := range f.stmts {
			showOK := isMigration && (definesFunction(stmt, syncFunc) || insertsPostings(stmt))
			for _, fi := range checkSE2(stmt, sqlOpts{scope: scope, showTrgm: showOK}) {
				add(fi.Check, fi.Rule, f.rel, fi.Line, fi.Msg)
			}
			if isMigration {
				continue
			}
			if !rbacOwned(f.rel) {
				for _, tbl := range allRBAC {
					if line, ok := namesInside(stmt, tbl); ok {
						add("SE1", "rbac-table-sql", f.rel, line, "a query file names the RBAC table "+tbl+": only "+rbacDir+" and "+authzDir+" read or write the RBAC tables (ADR-0011 SE1)")
						break
					}
				}
			}
			if line, ok := namesInside(stmt, postingTable); ok {
				add("SE1", "posting-table-sql", f.rel, line, "a query file names "+postingTable+": only the reportsql search template reads the trigram postings (ADR-0011 SE1, rule 5a)")
			}
			for _, at := range keyTableReads(stmt) {
				if under(f.rel, inventoryDir) && backfillProjection(stmt, at) {
					continue
				}
				add("SE1", "key-table-read", f.rel, stmt[at].line, "a query file reads "+keyTable+": only the reportsql search template reads the key table (ADR-0011 SE1)")
			}
		}
		if isMigration {
			for _, fi := range checkMigration(f.stmts, attached, extra) {
				add(fi.Check, fi.Rule, f.rel, fi.Line, fi.Msg)
			}
		}
	}
	return out, nil
}

// extraRBACTables reads the generated ownership map for authz_* tables owned by rbac or authz beyond the
// four ADR-0011 names: "any later authz_* table that the owners map assigns to rbac".
func extraRBACTables(root string) []string {
	b, err := os.ReadFile(filepath.Join(root, "internal/platform/store/owners/owners.gen.tsv"))
	if err != nil {
		return nil
	}
	named := map[string]bool{}
	for _, t := range rbacTables {
		named[t] = true
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "#") {
			continue
		}
		f := strings.Split(l, "\t")
		if len(f) >= 2 && strings.HasPrefix(f[0], "authz_") && (f[1] == "rbac" || f[1] == "authz") && !named[f[0]] {
			out = append(out, f[0])
		}
	}
	return out
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

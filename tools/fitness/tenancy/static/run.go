package static

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/checker"
	"golang.org/x/tools/go/packages"
)

// Run loads the product packages (cmd/ and internal/, tests included) under root, applies the
// analyzer, scans .sql files and the OpenAPI documents, and checks the registry for stale entries.
func Run(root string, cfg *Config) ([]Finding, error) {
	obs := NewObserved()
	pkgCfg := &packages.Config{
		Mode:  packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles | packages.NeedImports | packages.NeedTypes | packages.NeedTypesSizes | packages.NeedSyntax | packages.NeedTypesInfo | packages.NeedDeps,
		Dir:   root,
		Tests: true,
	}
	// Load only the trees that exist: a pattern for a missing directory is an error, and the product
	// has no cmd/ or internal/ until its first package lands.
	var patterns []string
	for _, top := range []string{"cmd", "internal"} {
		if st, err := os.Stat(filepath.Join(root, top)); err == nil && st.IsDir() {
			patterns = append(patterns, "./"+top+"/...")
		}
	}
	var pkgs []*packages.Package
	if len(patterns) > 0 {
		var err error
		if pkgs, err = packages.Load(pkgCfg, patterns...); err != nil {
			return nil, err
		}
	}
	var use []*packages.Package
	for _, p := range pkgs {
		if strings.HasSuffix(p.ID, ".test") {
			continue // the generated test main
		}
		if len(p.Errors) > 0 {
			return nil, fmt.Errorf("package %s does not type-check (run go build ./... first): %v", p.PkgPath, p.Errors[0])
		}
		use = append(use, p)
	}
	var fnd []Finding
	if len(use) > 0 {
		g, err := checker.Analyze([]*analysis.Analyzer{New(cfg, obs)}, use, nil)
		if err != nil {
			return nil, err
		}
		seen := map[string]bool{}
		for _, act := range g.Roots {
			if act.Err != nil {
				return nil, act.Err
			}
			for _, d := range act.Diagnostics {
				pos := act.Package.Fset.Position(d.Pos)
				rel, err := filepath.Rel(root, pos.Filename)
				if err != nil {
					rel = pos.Filename
				}
				f := Finding{Rule: d.Category, File: filepath.ToSlash(rel), Line: pos.Line, Msg: strings.TrimPrefix(d.Message, d.Category+": ")}
				if k := f.String(); !seen[k] {
					seen[k] = true
					fnd = append(fnd, f)
				}
			}
		}
	}
	fnd = append(fnd, staleRegistry(root, cfg, obs)...)
	sf, err := scanSQLFiles(root, cfg)
	if err != nil {
		return nil, err
	}
	fnd = append(fnd, sf...)
	of, _, err := CheckOpenAPI(root)
	if err != nil {
		return nil, err
	}
	fnd = append(fnd, of...)
	sort.SliceStable(fnd, func(i, j int) bool {
		if fnd[i].File != fnd[j].File {
			return fnd[i].File < fnd[j].File
		}
		return fnd[i].Line < fnd[j].Line
	})
	return fnd, nil
}

func staleRegistry(root string, cfg *Config, obs *Observed) []Finding {
	const reg = "registry"
	var out []Finding
	add := func(entry, msg string) { out = append(out, Finding{"registry-stale", reg, 0, entry + ": " + msg}) }
	for _, p := range cfg.Registry.PlatformPaths {
		e := "platformPaths[" + p.Package + "." + p.Function + "]"
		key := p.Package + "." + p.Function
		switch {
		case !obs.Packages[p.Package]:
			add(e, "names a package that does not exist")
		case !obs.Funcs[key]:
			add(e, "names a function that does not exist")
		default:
			if p.WithPlatform && !obs.WithPlat[key] {
				add(e, "is listed with withPlatform but the function no longer calls WithPlatform")
			}
			if p.MintsTenantID && !obs.Mints[key] {
				add(e, "is listed with mintsTenantID but the function no longer mints a tenant.ID")
			}
		}
	}
	for _, j := range cfg.Registry.PlatformJobs {
		if !obs.JobTypes[j.Type] {
			add("platformJobs["+j.Type+"]", "names a type that does not exist or is not a job type (a type with a Kind() string method)")
		}
	}
	for _, g := range cfg.Registry.GlobalTables {
		if st, err := os.Stat(filepath.Join(root, filepath.FromSlash(g.Owner))); err != nil || !st.IsDir() {
			add("globalTables["+g.Table+"]", "owning package directory "+g.Owner+" does not exist")
		}
	}
	return out
}

// scanSQLFiles checks the .sql files outside migrations/ and testdata/ (sqlc query files): no
// set_config or SET text, and no reference to a registered-global table outside its owning package.
func scanSQLFiles(root string, cfg *Config) ([]Finding, error) {
	var out []Finding
	for _, top := range []string{"cmd", "internal"} {
		base := filepath.Join(root, top)
		if _, err := os.Stat(base); err != nil {
			continue
		}
		err := filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() && d.Name() == "testdata" {
				return filepath.SkipDir
			}
			if d.IsDir() || !strings.HasSuffix(p, ".sql") {
				return nil
			}
			rel, _ := filepath.Rel(root, p)
			rel = filepath.ToSlash(rel)
			dir := filepath.ToSlash(filepath.Dir(rel))
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			text := string(b)
			line := func(off int) int { return strings.Count(text[:off], "\n") + 1 }
			if dir != cfg.StoreDir {
				for _, re := range []*regexp.Regexp{setConfigRe, setStmtRe} {
					for _, m := range re.FindAllStringIndex(text, -1) {
						out = append(out, Finding{RuleSetConfig, rel, line(m[0]), "SQL file contains set_config/SET text outside the tenancy package " + cfg.StoreDir})
					}
				}
			}
			for _, g := range cfg.Registry.GlobalTables {
				if UnderDir(dir, g.Owner) {
					continue
				}
				for _, m := range TableRef(g.Table).FindAllStringIndex(text, -1) {
					out = append(out, Finding{RuleGlobalSQL, rel, line(m[0]), "SQL references the registered-global table " + g.Table + " outside its owning package " + g.Owner})
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

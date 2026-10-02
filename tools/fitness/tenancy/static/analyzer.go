// Package static is check T5 of ADR-0002: go/analysis rules over the product source that keep the
// tenancy boundary where the database checks (T2–T4) cannot see it. One analyzer applies every rule;
// each diagnostic's message starts with its rule name. What the registry lists is recorded as it is
// seen, so entries that match nothing can be reported as stale.
package static

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/tools/go/analysis"

	"github.com/skenzeriq/activediq/tools/fitness/tenancy/registry"
)

// Config says where each tenancy role lives (repo-relative package directories; a directory includes
// its subpackages unless a rule says "exactly") and what the registry exempts.
type Config struct {
	Module       string // go.mod module path
	StoreDir     string // the data-access package: pgx, set_config, WithTenantTx, WithPlatform
	TenantDir    string // defines tenant.ID
	AuthnDir     string // may mint tenant.ID
	JobsDir      string // the job wrapper: may mint tenant.ID, the only importer of River
	ReportSQLDir string // the report compiler's identifier registry
	Registry     *registry.Registry
}

// DefaultConfig is the layout of blueprint §1.1.
func DefaultConfig(module string, reg *registry.Registry) *Config {
	return &Config{Module: module, StoreDir: "internal/platform/store", TenantDir: "internal/platform/tenant",
		AuthnDir: "internal/platform/authn", JobsDir: "internal/platform/jobs",
		ReportSQLDir: "internal/platform/store/reportsql", Registry: reg}
}

// Observed records what the analysis saw, for the registry's staleness check.
type Observed struct {
	mu         sync.Mutex
	Packages   map[string]bool // repo-relative package directories
	Funcs      map[string]bool // dir.Func and dir.Recv.Method
	WithPlat   map[string]bool // functions that use WithPlatform
	Mints      map[string]bool // functions that mint a tenant.ID
	JobTypes   map[string]bool // dir.Type for every job type
	TenantType bool            // the tenant package declares ID
}

func NewObserved() *Observed {
	return &Observed{Packages: map[string]bool{}, Funcs: map[string]bool{}, WithPlat: map[string]bool{}, Mints: map[string]bool{}, JobTypes: map[string]bool{}}
}

func (o *Observed) set(m map[string]bool, k string) { o.mu.Lock(); m[k] = true; o.mu.Unlock() }

// Rule names (the prefix of every message).
const (
	RulePgx        = "pgx-boundary"
	RuleRiver      = "river-boundary"
	RuleSetConfig  = "set-config-text"
	RuleGlobalSQL  = "global-table-sql"
	RuleMint       = "tenant-id-minting"
	RuleWithPlat   = "with-platform-site"
	RuleJob        = "job-carries-tenant"
	RuleIDDecoders = "tenant-id-decoder"
)

var (
	setConfigRe = regexp.MustCompile(`(?i)\bset_config\b`)
	// A statement that starts with SET or RESET and changes a session setting, role or authorization.
	setStmtRe = regexp.MustCompile(`(?i)(?:^|;)\s*(?:set|reset)\s+(?:session\s+|local\s+)?(?:role\b|session\s+authorization\b|all\b|[a-z_][\w.]*\s*(?:=|\bto\b|\bfrom\s+current\b))`)
)

// SQLTextProblem reports why a string must not appear outside the tenancy package: it sets a session
// or transaction setting. Shared with the .sql file scan.
func SQLTextProblem(s string) string {
	switch {
	case setConfigRe.MatchString(s):
		return "contains set_config SQL text"
	case setStmtRe.MatchString(s):
		return "contains SET/RESET SQL text"
	}
	return ""
}

// TableRef returns a regexp matching a reference to a table in SQL text: after a keyword that takes a
// table, with or without the schema, quoted or not.
func TableRef(qualified string) *regexp.Regexp {
	schema, table, _ := strings.Cut(qualified, ".")
	id := func(s string) string { return `"?` + regexp.QuoteMeta(s) + `"?` }
	return regexp.MustCompile(`(?i)\b(?:from|join|into|update|truncate|table|only|using)\s+(?:only\s+)?(?:` + id(schema) + `\.)?` + id(table) + `\b`)
}

// UnderDir reports whether relDir is dir or inside it.
func UnderDir(relDir, dir string) bool {
	return relDir == dir || strings.HasPrefix(relDir, dir+"/")
}

// New builds the analyzer.
func New(cfg *Config, obs *Observed) *analysis.Analyzer {
	return &analysis.Analyzer{
		Name: "tenancy",
		Doc:  "ADR-0002 T5: tenancy boundary rules",
		Run:  func(p *analysis.Pass) (any, error) { return nil, (&runner{cfg: cfg, obs: obs, pass: p}).run() },
	}
}

type runner struct {
	cfg  *Config
	obs  *Observed
	pass *analysis.Pass
	dir  string // repo-relative directory of the package under analysis
	// registry lookups
	withPlat map[string]bool
	mint     map[string]bool
	jobs     map[string]bool
	globals  []globalRef
	tenantID *types.Named
}

type globalRef struct {
	table string
	re    *regexp.Regexp
	owner string
}

func (r *runner) relDir(pkgPath string) string {
	p := strings.TrimSuffix(pkgPath, "_test")
	p = strings.TrimSuffix(p, " [")
	return strings.TrimPrefix(p, r.cfg.Module+"/")
}

func (r *runner) report(pos token.Pos, rule, msg string) {
	r.pass.Report(analysis.Diagnostic{Pos: pos, Category: rule, Message: rule + ": " + msg})
}

func (r *runner) run() error {
	pass := r.pass
	r.dir = r.relDir(pass.Pkg.Path())
	r.obs.set(r.obs.Packages, r.dir)
	r.withPlat, r.mint, r.jobs = map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, p := range r.cfg.Registry.PlatformPaths {
		if p.WithPlatform {
			r.withPlat[p.Package+"."+p.Function] = true
		}
		if p.MintsTenantID {
			r.mint[p.Package+"."+p.Function] = true
		}
	}
	for _, j := range r.cfg.Registry.PlatformJobs {
		r.jobs[j.Type] = true
	}
	for _, g := range r.cfg.Registry.GlobalTables {
		r.globals = append(r.globals, globalRef{g.Table, TableRef(g.Table), g.Owner})
	}
	r.tenantID = r.findTenantID()

	for _, f := range pass.Files {
		file := pass.Fset.File(f.Pos()).Name()
		isTest := strings.HasSuffix(file, "_test.go")
		r.imports(f)
		r.strings(f, isTest)
		r.decls(f, file, isTest)
	}
	if r.dir == r.cfg.TenantDir {
		r.decoders()
	}
	return nil
}

func (r *runner) findTenantID() *types.Named {
	var tp *types.Package
	want := r.cfg.Module + "/" + r.cfg.TenantDir
	if r.pass.Pkg.Path() == want || strings.TrimSuffix(r.pass.Pkg.Path(), "_test") == want {
		tp = r.pass.Pkg
	}
	for _, imp := range r.pass.Pkg.Imports() {
		if imp.Path() == want {
			tp = imp
		}
	}
	if tp == nil {
		return nil
	}
	if tn, ok := tp.Scope().Lookup("ID").(*types.TypeName); ok {
		if n, ok := tn.Type().(*types.Named); ok {
			r.obs.mu.Lock()
			r.obs.TenantType = true
			r.obs.mu.Unlock()
			return n
		}
	}
	return nil
}

func (r *runner) imports(f *ast.File) {
	for _, im := range f.Imports {
		p, _ := strconv.Unquote(im.Path.Value)
		switch {
		case strings.HasPrefix(p, "github.com/jackc/") && !UnderDir(r.dir, r.cfg.StoreDir):
			r.report(im.Pos(), RulePgx, "pgx ("+p+") is imported outside the data-access package "+r.cfg.StoreDir)
		case strings.HasPrefix(p, "github.com/riverqueue/") && !UnderDir(r.dir, r.cfg.JobsDir):
			r.report(im.Pos(), RuleRiver, "River ("+p+") is imported outside the job wrapper "+r.cfg.JobsDir)
		}
	}
}

// strings checks every constant string expression once (the outermost one).
func (r *runner) strings(f *ast.File, isTest bool) {
	inReport := UnderDir(r.dir, r.cfg.ReportSQLDir)
	ast.Inspect(f, func(n ast.Node) bool {
		switch n.(type) {
		case *ast.ImportSpec:
			return false
		case *ast.Ident, *ast.SelectorExpr, *ast.Field:
			return true
		}
		e, ok := n.(ast.Expr)
		if !ok {
			return true
		}
		tv, ok := r.pass.TypesInfo.Types[e]
		if !ok || tv.Value == nil || tv.Value.Kind() != constant.String {
			return true
		}
		s, err := strconv.Unquote(tv.Value.ExactString())
		if err != nil {
			s = tv.Value.ExactString()
		}
		if r.dir != r.cfg.StoreDir {
			if why := SQLTextProblem(s); why != "" {
				r.report(e.Pos(), RuleSetConfig, "string "+why+" outside the tenancy package "+r.cfg.StoreDir+" (the transaction's tenant is set only by WithTenantTx)")
			}
		}
		for _, g := range r.globals {
			bare := strings.Trim(strings.TrimSpace(s), `"`)
			table := g.table[strings.Index(g.table, ".")+1:]
			named := g.re.MatchString(s)
			if inReport && (named || strings.EqualFold(bare, table) || strings.EqualFold(bare, g.table)) {
				r.report(e.Pos(), RuleGlobalSQL, "the report compiler's identifier registry names the registered-global table "+g.table)
			} else if named && !UnderDir(r.dir, g.owner) {
				r.report(e.Pos(), RuleGlobalSQL, "SQL references the registered-global table "+g.table+" outside its owning package "+g.owner)
			}
		}
		return false
	})
}

// funcKey names the enclosing function of a declaration: dir.Func or dir.Recv.Method.
func (r *runner) funcKey(fd *ast.FuncDecl) string {
	name := fd.Name.Name
	if fd.Recv != nil && len(fd.Recv.List) == 1 {
		t := fd.Recv.List[0].Type
		if s, ok := t.(*ast.StarExpr); ok {
			t = s.X
		}
		if ix, ok := t.(*ast.IndexExpr); ok {
			t = ix.X
		}
		if id, ok := t.(*ast.Ident); ok {
			name = id.Name + "." + name
		}
	}
	return r.dir + "." + name
}

func (r *runner) isTenantID(t types.Type) bool {
	if r.tenantID == nil || t == nil {
		return false
	}
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	return types.Identical(t, r.tenantID)
}

func (r *runner) mintAllowed(file string, key string) bool {
	return strings.HasSuffix(file, "_test.go") || UnderDir(r.dir, r.cfg.TenantDir) || UnderDir(r.dir, r.cfg.AuthnDir) ||
		UnderDir(r.dir, r.cfg.JobsDir) || r.mint[key]
}

func (r *runner) decls(f *ast.File, file string, isTest bool) {
	info := r.pass.TypesInfo
	storePkg := r.cfg.Module + "/" + r.cfg.StoreDir
	for _, d := range f.Decls {
		fd, isFunc := d.(*ast.FuncDecl)
		key := ""
		if isFunc {
			key = r.funcKey(fd)
			r.obs.set(r.obs.Funcs, key)
		}
		// Job types.
		if gd, ok := d.(*ast.GenDecl); ok && gd.Tok == token.TYPE && !isTest {
			for _, sp := range gd.Specs {
				ts := sp.(*ast.TypeSpec)
				if obj, ok := info.Defs[ts.Name].(*types.TypeName); ok {
					r.jobType(ts, obj)
				}
			}
		}
		if !isFunc || fd.Body == nil {
			continue
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CompositeLit:
				if r.isTenantID(info.TypeOf(x)) {
					r.minted(x.Pos(), file, key, "a tenant.ID composite literal")
				}
			case *ast.CallExpr:
				if tv, ok := info.Types[x.Fun]; ok && tv.IsType() && r.isTenantID(tv.Type) && len(x.Args) == 1 {
					r.minted(x.Pos(), file, key, "a conversion to tenant.ID")
				}
				if fn := r.calleeFunc(x.Fun); fn != nil && r.tenantID != nil && fn.Pkg() != nil && fn.Pkg() == r.tenantID.Obj().Pkg() {
					sig := fn.Type().(*types.Signature)
					if recv := sig.Recv(); recv == nil || !r.isTenantID(recv.Type()) {
						for i := 0; i < sig.Results().Len(); i++ {
							if r.isTenantID(sig.Results().At(i).Type()) {
								r.minted(x.Pos(), file, key, "a call to "+fn.Name()+", which returns a tenant.ID")
								break
							}
						}
					}
				}
			case *ast.IndexExpr:
				if r.isTenantID(info.TypeOf(x.X)) {
					r.minted(x.Pos(), file, key, "an index into tenant.ID bytes")
				}
			case *ast.SliceExpr:
				if r.isTenantID(info.TypeOf(x.X)) {
					r.minted(x.Pos(), file, key, "a slice of tenant.ID bytes")
				}
			case *ast.Ident:
				if obj := info.Uses[x]; obj != nil {
					if fn, ok := obj.(*types.Func); ok && fn.Name() == "WithPlatform" && fn.Pkg() != nil && fn.Pkg().Path() == storePkg && r.dir != r.cfg.StoreDir {
						r.obs.set(r.obs.WithPlat, key)
						if !r.withPlat[key] {
							r.report(x.Pos(), RuleWithPlat, "WithPlatform used in "+key+", which is not a registered platform path (add it to the exemption registry with a reason)")
						}
					}
				}
			}
			return true
		})
	}
}

func (r *runner) calleeFunc(fun ast.Expr) *types.Func {
	switch f := fun.(type) {
	case *ast.Ident:
		fn, _ := r.pass.TypesInfo.Uses[f].(*types.Func)
		return fn
	case *ast.SelectorExpr:
		fn, _ := r.pass.TypesInfo.Uses[f.Sel].(*types.Func)
		return fn
	case *ast.IndexExpr:
		return r.calleeFunc(f.X)
	}
	return nil
}

func (r *runner) minted(pos token.Pos, file, key, what string) {
	r.obs.set(r.obs.Mints, key)
	if !r.mintAllowed(file, key) {
		r.report(pos, RuleMint, what+" outside the packages allowed to mint a tenant ID (authn, the job wrapper, registered platform paths, tests; ADR-0002 rule 5)")
	}
}

// jobType flags a job type (a type with a Kind() string method) that carries no tenant.
func (r *runner) jobType(ts *ast.TypeSpec, obj *types.TypeName) {
	named, ok := obj.Type().(*types.Named)
	if !ok || !strings.HasPrefix(r.dir, "internal/") {
		return
	}
	hasKind := false
	for _, t := range []types.Type{named, types.NewPointer(named)} {
		ms := types.NewMethodSet(t)
		if sel := ms.Lookup(obj.Pkg(), "Kind"); sel != nil {
			if sig, ok := sel.Type().(*types.Signature); ok && sig.Params().Len() == 0 && sig.Results().Len() == 1 {
				if b, ok := sig.Results().At(0).Type().(*types.Basic); ok && b.Kind() == types.String {
					hasKind = true
				}
			}
		}
	}
	if !hasKind {
		return
	}
	key := r.dir + "." + ts.Name.Name
	r.obs.set(r.obs.JobTypes, key)
	if r.jobs[key] || r.carriesTenant(named.Underlying(), 0) {
		return
	}
	r.report(ts.Pos(), RuleJob, "job type "+key+" has a Kind method but no tenant.ID field, and is not a registered platform job")
}

func (r *runner) carriesTenant(t types.Type, depth int) bool {
	if depth > 3 {
		return false
	}
	st, ok := t.(*types.Struct)
	if !ok {
		return false
	}
	for i := 0; i < st.NumFields(); i++ {
		ft := st.Field(i).Type()
		if r.isTenantID(ft) {
			return true
		}
		if n, ok := ft.(*types.Named); ok && st.Field(i).Embedded() && r.carriesTenant(n.Underlying(), depth+1) {
			return true
		}
	}
	return false
}

// decoders: tenant.ID must not decode itself, or any package could mint one with json.Unmarshal,
// sql.Scan, flag.Value or an encoding interface.
func (r *runner) decoders() {
	if r.tenantID == nil {
		return
	}
	forbidden := map[string]bool{"UnmarshalJSON": true, "UnmarshalText": true, "UnmarshalBinary": true, "UnmarshalYAML": true, "Scan": true, "Set": true, "DecodeValue": true}
	ms := types.NewMethodSet(types.NewPointer(r.tenantID))
	var names []string
	for i := 0; i < ms.Len(); i++ {
		if forbidden[ms.At(i).Obj().Name()] {
			names = append(names, ms.At(i).Obj().Name())
		}
	}
	sort.Strings(names)
	for _, n := range names {
		obj := ms.Lookup(r.tenantID.Obj().Pkg(), n)
		r.report(obj.Obj().Pos(), RuleIDDecoders, "tenant.ID has a "+n+" method: it would let any package mint a tenant ID by decoding input (ADR-0002 rule 5)")
	}
}

// Dir is exported for the driver: the repo-relative directory of an import path.
func Dir(module, pkgPath string) string {
	return strings.TrimPrefix(path.Clean(strings.TrimSuffix(pkgPath, "_test")), module+"/")
}

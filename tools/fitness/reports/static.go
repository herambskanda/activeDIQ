package main

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/tools/go/packages"
)

// Repository-relative directories the rules name.
const (
	authzDir      = "internal/platform/authz"
	authztestDir  = "internal/platform/authz/authztest"
	rbacDir       = "internal/platform/rbac"
	reportsqlDir  = "internal/platform/store/reportsql"
	reportDir     = "internal/platform/report"
	reportsModDir = "internal/modules/reports"
	runDir        = "internal/modules/reports/run"
)

var (
	scopeRenderers = []string{authzDir, reportsqlDir}          // may call ReadScope.Terms and .Token
	scopeProducers = []string{authzDir, rbacDir, authztestDir} // may call authz.NewReadScope
	compileNames   = map[string]bool{"Compile": true, "CompileCount": true, "Exec": true}
	scopeMethods   = map[string]bool{"Terms": true, "Token": true}
)

type staticResult struct {
	Violations []Violation
	Pending    []string
	Datasets   []string // constant IDs of every report.Dataset literal in non-test code
}

func modulePath(root string) (string, error) {
	b, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return "", err
	}
	for _, l := range strings.Split(string(b), "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(l), "module "); ok {
			return strings.Trim(strings.TrimSpace(rest), `"`), nil
		}
	}
	return "", fmt.Errorf("%s/go.mod: no module directive", root)
}

// checkStatic type-checks the non-test code of the module and judges RP2, RP3 and the RP11 dataset
// enumeration. Tests are not loaded: RP2 is stated for non-test files, and RP3 guards product code.
func checkStatic(root string) (*staticResult, error) {
	mod, err := modulePath(root)
	if err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	cfg := &packages.Config{
		Dir:  abs,
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo | packages.NeedImports | packages.NeedDeps,
	}
	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		return nil, err
	}
	res := &staticResult{}
	c := &checker{res: res, mod: mod, root: abs, seen: map[string]bool{}, datasets: map[string]bool{}}
	for _, p := range pkgs {
		c.pkg(p)
		switch c.dirOf(p.PkgPath) {
		case authzDir:
			c.sawScope = p.Types != nil && p.Types.Scope().Lookup("ReadScope") != nil
		case reportsqlDir:
			c.sawReportsql = true
		}
	}
	for d := range c.datasets {
		res.Datasets = append(res.Datasets, d)
	}
	sort.Strings(res.Datasets)
	if !c.sawScope {
		res.Pending = append(res.Pending, "RP2 ReadScope.Terms/.Token and NewReadScope callers (authz.ReadScope has not landed: T-0880; the rule applies the moment the type exists)")
	}
	if !c.sawReportsql {
		res.Pending = append(res.Pending, "RP3 reportsql.Compile/CompileCount/Exec callers under internal/modules/reports (store/reportsql has not landed: row B2; the rule applies the moment the package exists)")
	}
	sort.Slice(res.Violations, func(i, j int) bool { return res.Violations[i].Where < res.Violations[j].Where })
	return res, nil
}

type checker struct {
	res                    *staticResult
	mod, root              string
	seen                   map[string]bool
	datasets               map[string]bool
	sawScope, sawReportsql bool
}

func (c *checker) add(check, rule string, p *packages.Package, pos token.Pos, msg string) {
	pp := p.Fset.Position(pos)
	v := Violation{check, rule, relSlash(c.root, pp.Filename) + ":" + strconv.Itoa(pp.Line), msg}
	if k := v.String(); !c.seen[k] {
		c.seen[k] = true
		c.res.Violations = append(c.res.Violations, v)
	}
}

// dirOf returns the module-relative directory of a package path in this module, "" otherwise.
func (c *checker) dirOf(pkgPath string) string {
	if pkgPath == c.mod {
		return "."
	}
	if rest, ok := strings.CutPrefix(pkgPath, c.mod+"/"); ok {
		return rest
	}
	return ""
}

// recvNamed returns the named receiver type of a method, dereferencing a pointer.
func recvNamed(fn *types.Func) *types.Named {
	sig, _ := fn.Type().(*types.Signature)
	if sig == nil || sig.Recv() == nil {
		return nil
	}
	t := sig.Recv().Type()
	if pt, ok := t.(*types.Pointer); ok {
		t = pt.Elem()
	}
	n, _ := types.Unalias(t).(*types.Named)
	return n
}

func (c *checker) pkg(p *packages.Package) {
	dir := c.dirOf(strings.TrimSuffix(p.PkgPath, "_test"))
	if dir == "" {
		return
	}
	judged := under(dir, reportsModDir)
	for imp := range p.Imports {
		switch c.dirOf(imp) {
		case authzDir, reportsqlDir, reportDir:
			judged = true
		}
	}
	// A package whose type information is partial cannot be judged: say so rather than pass it.
	if len(p.Errors) > 0 {
		if judged {
			pos := token.NoPos
			if len(p.Syntax) > 0 {
				pos = p.Syntax[0].Pos()
			}
			c.add("RP2", "type-check", p, pos, "package "+dir+" does not type-check, so the report rules cannot be judged: "+p.Errors[0].Error())
		}
	}
	inRun := dir == runDir
	inReports := under(dir, reportsModDir) && !inRun
	for _, f := range p.Syntax {
		for _, spec := range f.Imports {
			ip, _ := strconv.Unquote(spec.Path.Value)
			if c.dirOf(ip) == authztestDir && dir != authztestDir {
				c.add("RP2", "test-double-import", p, spec.Pos(), "non-test code imports authz/authztest: its ReadScope builder is for tests only, product code gets a ReadScope from rbac.ReadScopes.For")
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.Ident:
				fn, _ := p.TypesInfo.Uses[v].(*types.Func)
				if fn == nil || fn.Pkg() == nil {
					return true
				}
				c.use(p, v, fn, dir, inReports)
			case *ast.CompositeLit:
				c.dataset(p, v)
			case *ast.InterfaceType:
				if inReports {
					c.iface(p, v)
				}
			}
			return true
		})
	}
}

// use judges one reference to a function or method.
func (c *checker) use(p *packages.Package, id *ast.Ident, fn *types.Func, dir string, inReports bool) {
	fdir := c.dirOf(fn.Pkg().Path())
	if rn := recvNamed(fn); rn != nil && rn.Obj().Pkg() != nil {
		rdir := c.dirOf(rn.Obj().Pkg().Path())
		if rdir == authzDir && rn.Obj().Name() == "ReadScope" {
			if scopeMethods[fn.Name()] && !slices.Contains(scopeRenderers, dir) {
				c.add("RP2", "scope-renderer", p, id.Pos(), "ReadScope."+fn.Name()+" is called outside "+join(scopeRenderers)+": one renderer turns a scope into SQL (reports contract §4)")
			}
		}
	}
	switch {
	case fdir == authzDir && fn.Name() == "NewReadScope" && recvNamed(fn) == nil:
		if !slices.Contains(scopeProducers, dir) {
			c.add("RP2", "scope-producer", p, id.Pos(), "authz.NewReadScope is called outside "+join(scopeProducers)+": rbac.ReadScopes.For is the one producer of a ReadScope (reports contract §4)")
		}
	case fdir == reportsqlDir && compileNames[fn.Name()]:
		if inReports {
			c.add("RP3", "export-compiles", p, id.Pos(), "reportsql."+fn.Name()+" is called from "+dir+": only "+runDir+" compiles or executes a report; export and delivery read the stored run (ADR-0010 rule 4)")
		}
	}
}

// iface flags an interface in the reports module (outside run) that gives the compiler a second
// door: a Compile, CompileCount or Exec method whose signature mentions a reportsql type.
func (c *checker) iface(p *packages.Package, it *ast.InterfaceType) {
	t, _ := p.TypesInfo.TypeOf(it).(*types.Interface)
	if t == nil {
		return
	}
	for i := 0; i < t.NumMethods(); i++ {
		m := t.Method(i)
		if compileNames[m.Name()] && c.mentionsReportsql(m.Type(), map[types.Type]bool{}) {
			c.add("RP3", "export-compiles", p, it.Pos(), "an interface in the reports module declares "+m.Name()+" over reportsql types: that is a second door to the compiler, and only "+runDir+" may compile (ADR-0010 rule 4)")
			return
		}
	}
}

func (c *checker) mentionsReportsql(t types.Type, seen map[types.Type]bool) bool {
	if seen[t] {
		return false
	}
	seen[t] = true
	switch v := types.Unalias(t).(type) {
	case *types.Named:
		if v.Obj().Pkg() != nil && c.dirOf(v.Obj().Pkg().Path()) == reportsqlDir {
			return true
		}
	case *types.Pointer:
		return c.mentionsReportsql(v.Elem(), seen)
	case *types.Slice:
		return c.mentionsReportsql(v.Elem(), seen)
	case *types.Signature:
		for _, tup := range []*types.Tuple{v.Params(), v.Results()} {
			for i := 0; i < tup.Len(); i++ {
				if c.mentionsReportsql(tup.At(i).Type(), seen) {
					return true
				}
			}
		}
	}
	return false
}

// dataset records the constant ID of a report.Dataset literal, which RP11 compares with its subtests.
func (c *checker) dataset(p *packages.Package, lit *ast.CompositeLit) {
	n, _ := types.Unalias(p.TypesInfo.TypeOf(lit)).(*types.Named)
	if n == nil || n.Obj().Name() != "Dataset" || n.Obj().Pkg() == nil || c.dirOf(n.Obj().Pkg().Path()) != reportDir {
		return
	}
	for _, e := range lit.Elts {
		kv, ok := e.(*ast.KeyValueExpr)
		if !ok {
			c.add("RP11", "dataset-id", p, lit.Pos(), "a report.Dataset literal with positional fields: write the ID key so the job can list the dataset")
			return
		}
		if k, _ := kv.Key.(*ast.Ident); k != nil && k.Name == "ID" {
			tv := p.TypesInfo.Types[kv.Value]
			if tv.Value == nil || tv.Value.Kind() != constant.String {
				c.add("RP11", "dataset-id", p, kv.Pos(), "a report.Dataset whose ID is not a constant: RP11 runs one subtest per dataset ID, so the ID must be a string constant")
				return
			}
			c.datasets[constant.StringVal(tv.Value)] = true
			return
		}
	}
	c.add("RP11", "dataset-id", p, lit.Pos(), "a report.Dataset literal without an ID: RP11 cannot list it")
}

package main

import (
	"fmt"
	"go/ast"
	"go/token"
	"strconv"
	"strings"
)

// P4 (telemetry half, T-0135, TM-TB17-T8, TM-Q10): ADR-0002 "Logs, metrics, caches" row. Every log
// line and metric about tenant work carries the tenant ID and in-process caches are keyed by
// tenant. The check is syntactic and reads the same parsed tree as P1; it has three rules.
//
//	log    a log call inside a function that has a tenant in scope (a tenant.ID parameter, variable or
//	       receiver field) passes the tenant attribute, directly or through a logger built with
//	       With("tenant_id", ...).
//	metric a labelled metric constructor lists the tenant label; an unlabelled constructor cannot
//	       carry one and fails.
//	cache  a map held in a struct field or package variable named *cache*, or in a struct whose type
//	       name contains Cache, is keyed by tenant.ID or by a struct that carries one; a sync.Map or
//	       a generic cache type is judged by its declared key type.
//
// A platform-scope exception is declared in the manifest (p4.exempt) with an ADR, a reason and the
// place it covers; a stale exception fails.

// P4Config is the "p4" object of the manifest.
type P4Config struct {
	Scope           []string    `json:"scope"`           // directories checked (descendants included)
	TenantPackage   string      `json:"tenantPackage"`   // import path suffix of the package that declares tenant.ID
	TenantAttr      string      `json:"tenantAttr"`      // the attribute / label key every line and metric carries
	MetricPackages  []string    `json:"metricPackages"`  // import paths (or path suffixes) of metric libraries
	LogMethods      []string    `json:"logMethods"`      // method names that emit a log line
	LabelledMetrics []string    `json:"labelledMetrics"` // constructors whose []string argument lists label names
	FlatMetrics     []string    `json:"flatMetrics"`     // constructors that make a metric with no labels
	Exempt          []Exception `json:"exempt"`          // path = "file", "file#Func" or "file#Name"
}

type p4Run struct {
	c    *Ctx
	cfg  *P4Config
	used map[int]bool
	vs   []Violation
}

func (c *Ctx) checkP4() []Violation {
	cfg := c.Cfg.P4
	r := &p4Run{c: c, cfg: cfg, used: map[int]bool{}}
	if cfg == nil || cfg.TenantAttr == "" || len(cfg.Scope) == 0 {
		return []Violation{{"P4", "manifest p4", "the manifest has no p4 object (scope, tenantPackage, tenantAttr, logMethods, labelledMetrics, flatMetrics); the logs, metrics and caches rule cannot be switched off by deleting it"}}
	}
	for i, e := range cfg.Exempt {
		if ok, why := c.adrGrants(e.ADR); !ok {
			r.vs = append(r.vs, Violation{"P4", fmt.Sprintf("manifest p4.exempt[%d] (%s)", i, e.Path), why})
		}
		if strings.TrimSpace(e.Reason) == "" {
			r.vs = append(r.vs, Violation{"P4", fmt.Sprintf("manifest p4.exempt[%d] (%s)", i, e.Path), "it gives no reason"})
		}
	}
	for _, f := range c.Tree.Files {
		if f.Test || !underAny(f.Dir, cfg.Scope) {
			continue
		}
		r.file(f)
	}
	for i, e := range cfg.Exempt {
		if !r.used[i] {
			r.vs = append(r.vs, Violation{"P4", fmt.Sprintf("manifest p4.exempt[%d] (%s)", i, e.Path), "stale: nothing at that place needs the exception any more; delete it"})
		}
	}
	return r.vs
}

// exempt reports whether place (file, file#Func or file#Name) carries a valid exception.
func (r *p4Run) exempt(file string, names ...string) bool {
	for i, e := range r.cfg.Exempt {
		hit := e.Path == file
		for _, n := range names {
			hit = hit || e.Path == file+"#"+n
		}
		if hit {
			r.used[i] = true
			ok, _ := r.c.adrGrants(e.ADR)
			return ok && strings.TrimSpace(e.Reason) != ""
		}
	}
	return false
}

func (r *p4Run) add(f *File, p token.Pos, msg string) {
	r.vs = append(r.vs, Violation{"P4", f.Pos(p), msg})
}

// isTenantID reports whether e names the tenant ID type: tenant.ID through an import of the tenant
// package, or ID inside that package.
func (r *p4Run) isTenantID(f *File, e ast.Expr) bool {
	switch t := e.(type) {
	case *ast.StarExpr:
		return r.isTenantID(f, t.X)
	case *ast.ParenExpr:
		return r.isTenantID(f, t.X)
	case *ast.SelectorExpr:
		if id, ok := t.X.(*ast.Ident); ok && t.Sel.Name == "ID" {
			ip := f.Imports[id.Name]
			return ip != "" && (ip == r.cfg.TenantPackage || strings.HasSuffix(ip, "/"+r.cfg.TenantPackage))
		}
	case *ast.Ident:
		return t.Name == "ID" && f.Dir == r.cfg.TenantPackage
	}
	return false
}

// carriesTenant reports whether a type is tenant.ID or a struct type of the package that has a
// tenant.ID field.
func (r *p4Run) carriesTenant(f *File, e ast.Expr) bool {
	if r.isTenantID(f, e) {
		return true
	}
	if st, ok := e.(*ast.StructType); ok {
		return r.structHasTenant(f, st)
	}
	if id, ok := e.(*ast.Ident); ok {
		for _, g := range r.c.Tree.byDir[f.Dir] {
			if g.Test {
				continue
			}
			for _, d := range g.AST.Decls {
				gd, ok := d.(*ast.GenDecl)
				if !ok || gd.Tok != token.TYPE {
					continue
				}
				for _, s := range gd.Specs {
					if ts := s.(*ast.TypeSpec); ts.Name.Name == id.Name {
						if st, ok := ts.Type.(*ast.StructType); ok {
							return r.structHasTenant(g, st)
						}
						return r.isTenantID(g, ts.Type)
					}
				}
			}
		}
	}
	return false
}

func (r *p4Run) structHasTenant(f *File, st *ast.StructType) bool {
	for _, fl := range st.Fields.List {
		if r.isTenantID(f, fl.Type) {
			return true
		}
	}
	return false
}

// tenantTypes lists the struct types of a package that hold a tenant.ID field.
func (r *p4Run) tenantTypes(dir string) map[string]bool {
	m := map[string]bool{}
	for _, g := range r.c.Tree.byDir[dir] {
		if g.Test {
			continue
		}
		for _, d := range g.AST.Decls {
			if gd, ok := d.(*ast.GenDecl); ok && gd.Tok == token.TYPE {
				for _, s := range gd.Specs {
					ts := s.(*ast.TypeSpec)
					if st, ok := ts.Type.(*ast.StructType); ok && r.structHasTenant(g, st) {
						m[ts.Name.Name] = true
					}
				}
			}
		}
	}
	return m
}

func (r *p4Run) file(f *File) {
	tt := r.tenantTypes(f.Dir)
	for _, d := range f.AST.Decls {
		switch d := d.(type) {
		case *ast.FuncDecl:
			if d.Body != nil {
				r.fn(f, d, tt)
			}
		case *ast.GenDecl:
			r.decl(f, d)
		}
	}
	// Struct types declared inside functions are rare; metrics outside functions are package vars.
	for _, d := range f.AST.Decls {
		if gd, ok := d.(*ast.GenDecl); ok && gd.Tok == token.VAR {
			ast.Inspect(gd, func(n ast.Node) bool {
				if ce, ok := n.(*ast.CallExpr); ok {
					r.metric(f, ce, "")
				}
				return true
			})
		}
	}
}

// ---- log and metric: inside functions -------------------------------------------------------

func (r *p4Run) fn(f *File, fd *ast.FuncDecl, tt map[string]bool) {
	inScope := false
	check := func(fl *ast.FieldList) {
		if fl == nil {
			return
		}
		for _, p := range fl.List {
			if r.isTenantID(f, p.Type) {
				inScope = true
			}
			if id := baseIdent(p.Type); id != "" && tt[id] {
				inScope = true
			}
		}
	}
	check(fd.Recv)
	check(fd.Type.Params)
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.ValueSpec:
			if n.Type != nil && r.isTenantID(f, n.Type) {
				inScope = true
			}
		case *ast.FuncLit:
			check(n.Type.Params)
		}
		return true
	})
	// Loggers the function builds with the tenant attribute already attached.
	bound := map[string]bool{}
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		if as, ok := n.(*ast.AssignStmt); ok && len(as.Lhs) == len(as.Rhs) {
			for i, rhs := range as.Rhs {
				if id, ok := as.Lhs[i].(*ast.Ident); ok && r.boundLogger(f, rhs, bound) {
					bound[id.Name] = true
				}
			}
		}
		return true
	})
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		ce, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		r.metric(f, ce, fd.Name.Name)
		if inScope && r.isLogCall(f, ce) && !r.argsCarryTenant(f, ce) && !r.boundLogger(f, ce.Fun.(*ast.SelectorExpr).X, bound) {
			if !r.exempt(f.Rel, fd.Name.Name) {
				r.add(f, ce.Pos(), fmt.Sprintf("log line in %s, which works for a tenant, does not carry %q; pass the attribute or log through a logger built with With(%q, ...) (ADR-0002 Logs, metrics, caches; TM-TB17-T8)", fd.Name.Name, r.cfg.TenantAttr, r.cfg.TenantAttr))
			}
		}
		return true
	})
}

func baseIdent(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.StarExpr:
		return baseIdent(t.X)
	case *ast.Ident:
		return t.Name
	case *ast.IndexExpr:
		return baseIdent(t.X)
	}
	return ""
}

func (r *p4Run) isAttrLit(e ast.Expr) bool {
	bl, ok := e.(*ast.BasicLit)
	if !ok || bl.Kind != token.STRING {
		return false
	}
	s, err := strconv.Unquote(bl.Value)
	return err == nil && s == r.cfg.TenantAttr
}

func (r *p4Run) isLogCall(f *File, ce *ast.CallExpr) bool {
	se, ok := ce.Fun.(*ast.SelectorExpr)
	if !ok || !has(r.cfg.LogMethods, se.Sel.Name) {
		return false
	}
	switch x := se.X.(type) {
	case *ast.Ident:
		if f.Imports[x.Name] == "log/slog" {
			return true
		}
		return looksLikeLogger(x.Name)
	case *ast.SelectorExpr:
		return looksLikeLogger(x.Sel.Name)
	case *ast.CallExpr: // slog.Default().Info, l.With(...).Info
		return r.isLoggerExpr(f, x)
	}
	return false
}

func looksLikeLogger(name string) bool {
	n := strings.ToLower(name)
	return n == "l" || strings.Contains(n, "log")
}

func (r *p4Run) isLoggerExpr(f *File, ce *ast.CallExpr) bool {
	if se, ok := ce.Fun.(*ast.SelectorExpr); ok {
		switch se.Sel.Name {
		case "With", "WithGroup", "Default":
			return true
		}
	}
	return false
}

// argsCarryTenant reports whether any argument is the tenant attribute key as a literal, or an
// slog.Group / slog.Any / slog.String call that has it.
func (r *p4Run) argsCarryTenant(f *File, ce *ast.CallExpr) bool {
	found := false
	for _, a := range ce.Args {
		ast.Inspect(a, func(n ast.Node) bool {
			if e, ok := n.(ast.Expr); ok && r.isAttrLit(e) {
				found = true
			}
			return !found
		})
	}
	return found
}

// boundLogger reports whether e is a logger with the tenant attribute attached: an expression with
// With("tenant_id", ...) in its chain, or a local variable assigned from one.
func (r *p4Run) boundLogger(f *File, e ast.Expr, bound map[string]bool) bool {
	switch x := e.(type) {
	case *ast.Ident:
		return bound[x.Name]
	case *ast.CallExpr:
		if se, ok := x.Fun.(*ast.SelectorExpr); ok {
			if se.Sel.Name == "With" && r.argsCarryTenant(f, x) {
				return true
			}
			return r.boundLogger(f, se.X, bound)
		}
	}
	return false
}

func (r *p4Run) metricPkg(ip string) bool {
	for _, m := range r.cfg.MetricPackages {
		if ip != "" && (ip == m || strings.HasSuffix(ip, "/"+m)) {
			return true
		}
	}
	return false
}

// metric checks a constructor call made through a metric library's package name.
func (r *p4Run) metric(f *File, ce *ast.CallExpr, fn string) {
	fx, ok := ce.Fun.(*ast.SelectorExpr)
	if !ok {
		return
	}
	pkg, ok := fx.X.(*ast.Ident)
	if !ok || !r.metricPkg(f.Imports[pkg.Name]) {
		return
	}
	name := fx.Sel.Name
	switch {
	case has(r.cfg.FlatMetrics, name):
		if !r.exempt(f.Rel, fn, name) {
			r.add(f, ce.Pos(), fmt.Sprintf("metric made by %s has no labels, so it cannot carry %q; use a labelled constructor (%s) with the tenant label, or declare a platform metric under p4.exempt (ADR-0002 Logs, metrics, caches; TM-TB17-T8)", name, r.cfg.TenantAttr, strings.Join(r.cfg.LabelledMetrics, ", ")))
		}
	case has(r.cfg.LabelledMetrics, name):
		labels := false
		listed := false
		for _, a := range ce.Args {
			cl, ok := a.(*ast.CompositeLit)
			if !ok {
				continue
			}
			if at, ok := cl.Type.(*ast.ArrayType); ok {
				if id, ok := at.Elt.(*ast.Ident); ok && id.Name == "string" {
					listed = true
					for _, el := range cl.Elts {
						labels = labels || r.isAttrLit(el)
					}
				}
			}
		}
		switch {
		case labels:
		case r.exempt(f.Rel, fn, name):
		case !listed:
			r.add(f, ce.Pos(), fmt.Sprintf("metric made by %s takes its labels from something other than a []string literal, so the tenant label %q cannot be checked; write the label list in place (ADR-0002 Logs, metrics, caches; TM-TB17-T8)", name, r.cfg.TenantAttr))
		default:
			r.add(f, ce.Pos(), fmt.Sprintf("metric made by %s does not list the label %q (ADR-0002 Logs, metrics, caches; TM-TB17-T8)", name, r.cfg.TenantAttr))
		}
	}
}

// ---- cache: declarations ----------------------------------------------------------------------

func (r *p4Run) decl(f *File, gd *ast.GenDecl) {
	for _, s := range gd.Specs {
		switch s := s.(type) {
		case *ast.TypeSpec:
			if st, ok := s.Type.(*ast.StructType); ok {
				cacheType := strings.Contains(strings.ToLower(s.Name.Name), "cache")
				for _, fl := range st.Fields.List {
					for _, nm := range fl.Names {
						if cacheType || strings.Contains(strings.ToLower(nm.Name), "cache") {
							r.cache(f, nm.Pos(), s.Name.Name+"."+nm.Name, fl.Type, s.Name.Name, nm.Name)
						}
					}
				}
			}
		case *ast.ValueSpec:
			if gd.Tok != token.VAR {
				continue
			}
			for i, nm := range s.Names {
				if !strings.Contains(strings.ToLower(nm.Name), "cache") {
					continue
				}
				t := s.Type
				if t == nil && i < len(s.Values) {
					if cl, ok := s.Values[i].(*ast.CompositeLit); ok {
						t = cl.Type
					}
				}
				if t != nil {
					r.cache(f, nm.Pos(), nm.Name, t, nm.Name)
				}
			}
		}
	}
}

// cache judges one cache-like declaration. Only maps and the generic or sync.Map shapes are
// judged: an interface or a pointer to a type has its own declaration, which is judged there.
func (r *p4Run) cache(f *File, p token.Pos, what string, t ast.Expr, ex ...string) {
	var key ast.Expr
	switch tt := t.(type) {
	case *ast.MapType:
		key = tt.Key
	case *ast.StarExpr:
		r.cache(f, p, what, tt.X, ex...)
		return
	case *ast.SelectorExpr:
		if id, ok := tt.X.(*ast.Ident); ok && f.Imports[id.Name] == "sync" && tt.Sel.Name == "Map" {
			if !r.exempt(f.Rel, ex...) {
				r.add(f, p, fmt.Sprintf("cache %s is a sync.Map, whose key type no check can see; use a map keyed by tenant.ID (ADR-0002 Logs, metrics, caches; TM-TB17-T8)", what))
			}
		}
		return
	case *ast.IndexExpr:
		key = tt.Index
	case *ast.IndexListExpr:
		key = tt.Indices[0]
	default:
		return
	}
	if r.carriesTenant(f, key) || r.exempt(f.Rel, ex...) {
		return
	}
	r.add(f, p, fmt.Sprintf("cache %s is not keyed by tenant: its key type must be tenant.ID or a struct with a tenant.ID field, so one tenant's entry can never answer another's lookup (ADR-0002 Logs, metrics, caches; TM-TB17-T8)", what))
}

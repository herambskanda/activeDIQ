package main

import (
	"go/ast"
	"go/token"
	"regexp"
)

// callersAllow lists, per guarded function, the directory prefixes whose non-test code may call it
// (keys-custody-design FF-KEY-5 "Callers"). Rotate and ShredTenant belong to the packages of the two
// registered Actions and the deletion job; those packages do not exist yet, so the list is empty and
// any call outside the keys package fails until the owning ticket adds its package here, in review.
var callersAllow = map[string][]string{
	"Rotate":          {},
	"ShredTenant":     {},
	"OpenMaintenance": {"cmd/server"},
}

var insertTenantKeys = regexp.MustCompile(`(?is)insert\s+into\s+(public\.)?tenant_keys\b`)

// checkFFKey5 is the AST half of "eager, not lazy": INSERT INTO tenant_keys appears only in Provision
// and Rotate of the keys package (never reachable from KeySource), and Rotate, ShredTenant and
// OpenMaintenance are called only from their allow-listed places. It returns the notes of guarded
// functions that do not exist yet, which the caller prints as pending, never as a pass.
func checkFFKey5(files []goFile) (vs []Violation, pending []string) {
	inserts := 0
	declared := map[string]bool{}
	for _, g := range files {
		if g.Test || g.in("tools/fitness/keycustody") {
			continue
		}
		for _, d := range g.File.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok {
				continue
			}
			if g.in(keysDir) {
				declared[fd.Name.Name] = true
			}
			strLitsIn(fd, func(l *ast.BasicLit, s string) {
				if insertTenantKeys.MatchString(s) {
					inserts++
					if !g.in(keysDir) || (fd.Name.Name != "Provision" && fd.Name.Name != "Rotate") {
						vs = append(vs, Violation{"FF-KEY-5", "insert-site", g.where(l.Pos()), "INSERT INTO tenant_keys in " + fd.Name.Name + ": only keys.Provision and keys.Rotate may insert, never the KeySource"})
					}
				}
			})
		}
		if g.in(keysDir) {
			continue
		}
		ast.Inspect(g.File, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			allow, guarded := callersAllow[sel.Sel.Name]
			if !guarded || !importsKeys(g.File) {
				return true
			}
			ok2 := false
			for _, a := range allow {
				if g.in(a) {
					ok2 = true
				}
			}
			if !ok2 {
				vs = append(vs, Violation{"FF-KEY-5", "callers", g.where(sel.Pos()), sel.Sel.Name + " is called from a package that is not on its caller list (callers-allow in tools/fitness/keycustody/static5.go)"})
			}
			return true
		})
	}
	if inserts == 0 {
		vs = append(vs, Violation{"FF-KEY-5", "scan-empty", keysDir, "found no INSERT INTO tenant_keys at all: the scan is broken or Provision moved"})
	}
	for _, fn := range []string{"Rotate", "ShredTenant", "OpenMaintenance"} {
		if !declared[fn] {
			pending = append(pending, fn+" is not declared yet; its caller rule is checked once it lands")
		}
	}
	return vs, pending
}

func strLitsIn(n ast.Node, fn func(l *ast.BasicLit, s string)) {
	ast.Inspect(n, func(x ast.Node) bool {
		if l, ok := x.(*ast.BasicLit); ok && l.Kind == token.STRING {
			s := l.Value
			if len(s) >= 2 {
				s = s[1 : len(s)-1]
			}
			fn(l, s)
		}
		return true
	})
}

package main

import (
	"fmt"
	"go/ast"
	"regexp"
	"strings"
)

// domainFile reports whether f is domain code for P1: outside the composition root and outside the
// exempt build-tooling roots.
func (c *Ctx) domainFile(f *File) bool {
	return !underAny(f.Dir, c.Cfg.CompositionRoot) && !underAny(f.Dir, c.Cfg.ExemptRoots)
}

// normIdent lowercases an identifier and drops underscores so IsSaaS, is_saas and ISSAAS compare equal.
func normIdent(s string) string {
	return strings.ToLower(strings.ReplaceAll(s, "_", ""))
}

// profileNamed returns the denylist token an identifier or flag value contains, or "".
func (c *Ctx) profileNamed(s string) string {
	n := normIdent(strings.ReplaceAll(s, "-", ""))
	for _, tok := range c.Cfg.IdentDenylist {
		if strings.Contains(n, normIdent(tok)) {
			return tok
		}
	}
	return ""
}

var envFuncs = map[string]bool{"Getenv": true, "LookupEnv": true, "Environ": true, "ExpandEnv": true, "Expand": true}

// checkP1Domain is the part of P1 that reads source: composition imports, environment reads,
// profile-name identifiers and literals, and profile-named capability flags.
func (c *Ctx) checkP1Domain() []Violation {
	var vs []Violation
	add := func(pos, msg string) { vs = append(vs, Violation{"P1", pos, msg}) }
	profEnv := regexp.MustCompile("(?i)" + c.Cfg.ProfileEnvRegexp)
	composeDir := c.Cfg.ComposePackage

	for _, f := range c.Tree.Files {
		if underAny(f.Dir, c.Cfg.ExemptRoots) {
			continue
		}
		domain := c.domainFile(f)
		// Imports of the compose package (or anything under it) from outside the composition root.
		for _, is := range f.AST.Imports {
			ip := strings.Trim(is.Path.Value, `"`)
			if dir := c.Tree.Local(ip); domain && dir != "" && under(dir, composeDir) {
				add(f.Pos(is.Pos()), fmt.Sprintf("%s imports %s; only cmd/ and the composition root (%s) import the profile or compose packages, so domain code cannot branch on a profile", f.Dir, dir, strings.Join(c.Cfg.CompositionRoot, ", ")))
			}
		}
		inLoader := underAny(f.Dir, c.Cfg.ConfigLoader)
		parents := map[ast.Node]ast.Node{}
		var stack []ast.Node
		ast.Inspect(f.AST, func(n ast.Node) bool {
			if n == nil {
				stack = stack[:len(stack)-1]
				return true
			}
			if len(stack) > 0 {
				parents[n] = stack[len(stack)-1]
			}
			stack = append(stack, n)
			return true
		})
		ast.Inspect(f.AST, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.Ident:
				if !domain {
					return true
				}
				if tok := c.profileNamed(x.Name); tok != "" {
					add(f.Pos(x.Pos()), fmt.Sprintf("identifier %q names a deployment profile (%q); name the capability or the setting, never the profile (ADR-0002 rule 1)", x.Name, tok))
				}
			case *ast.BasicLit:
				if !domain {
					return true
				}
				if s, _, ok := c.Tree.EvalString(f, x); ok {
					for _, lit := range c.Cfg.LiteralDenylist {
						if strings.EqualFold(s, lit) {
							add(f.Pos(x.Pos()), fmt.Sprintf("string literal %q is a profile name; domain code does not compare against profiles", s))
						}
					}
				}
			case *ast.SelectorExpr:
				if inLoader {
					return true
				}
				pk, ok := x.X.(*ast.Ident)
				if !ok {
					return true
				}
				ip := f.Imports[pk.Name]
				if (ip != "os" && ip != "syscall") || !envFuncs[x.Sel.Name] {
					return true
				}
				call, isCall := parents[x].(*ast.CallExpr)
				if !isCall || call.Fun != ast.Expr(x) || len(call.Args) == 0 || x.Sel.Name == "Environ" {
					add(f.Pos(x.Pos()), fmt.Sprintf("%s.%s is read outside the config loader (%s) in a way that hides which variable it reads; read configuration through compose/config", ip, x.Sel.Name, strings.Join(c.Cfg.ConfigLoader, ", ")))
					return true
				}
				name, prefix, ok := c.Tree.EvalString(f, call.Args[0])
				switch {
				case !ok:
					add(f.Pos(x.Pos()), fmt.Sprintf("%s.%s reads an environment variable whose name is not a constant, outside the config loader (%s); it cannot be shown not to select a profile", ip, x.Sel.Name, strings.Join(c.Cfg.ConfigLoader, ", ")))
				case profEnv.MatchString(name):
					suffix := ""
					if prefix {
						suffix = "…"
					}
					add(f.Pos(x.Pos()), fmt.Sprintf("%s.%s reads %q, a profile-selecting environment variable, outside the config loader (%s); only compose/config reads it (ADR-0002 rule 1)", ip, x.Sel.Name, name+suffix, strings.Join(c.Cfg.ConfigLoader, ", ")))
				}
			}
			return true
		})
	}
	vs = append(vs, c.checkCapabilityNames()...)
	return vs
}

// checkCapabilityNames fails a capability constant whose name or value is a profile's name: a
// capability describes what the system can do, never where it runs ("profile logic smuggled in
// as a capability flag").
func (c *Ctx) checkCapabilityNames() []Violation {
	var vs []Violation
	for _, f := range c.Tree.Files {
		if f.Dir != c.Cfg.CapabilityPkg || f.Test {
			continue
		}
		for _, d := range f.AST.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, sp := range gd.Specs {
				vsp, ok := sp.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i := range vsp.Names {
					if i < len(vsp.Values) {
						if s, _, ok := c.Tree.EvalString(f, vsp.Values[i]); ok {
							if tok := c.profileNamed(s); tok != "" {
								vs = append(vs, Violation{"P1", f.Pos(vsp.Values[i].Pos()), fmt.Sprintf("capability flag value %q is named after a profile (%q); a capability flag describes a capability, not a deployment (the constant name is checked as an identifier)", s, tok)})
							}
						}
					}
				}
			}
		}
	}
	return vs
}

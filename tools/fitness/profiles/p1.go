package main

import (
	"fmt"
	"go/ast"
	"go/token"
	"net/url"
	"regexp"
	"sort"
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

// refusedStems are normalised stems that no externalVocabulary entry may equal: they are the
// prefix of Microsoft's names, not a name, so registering one would exempt every identifier that
// starts with it (ADR-0002 erratum E-1). This is source, not manifest.json, so editing the registry
// cannot loosen it; adding a stem is a reviewed code change. There is no length rule: onpremsid
// (token + 3) must pass and onpremises (token + 4) must fail.
var refusedStems = []string{"onpremise", "onpremises"}

var externalKinds = map[string]bool{"graph-property": true, "graph-segment": true, "token-claim": true}

// normTerm normalises a denylist token or a registered term: normIdent, hyphens dropped.
func normTerm(s string) string { return normIdent(strings.ReplaceAll(s, "-", "")) }

// termProblems returns why a registry entry is refused, ignoring staleness (which needs the tree).
func (c *Ctx) termProblems(e ExternalTerm) []string {
	var ps []string
	if e.Term == "" {
		return []string{"has no term"}
	}
	if !externalKinds[e.Kind] {
		ps = append(ps, fmt.Sprintf("kind %q is not graph-property, graph-segment or token-claim", e.Kind))
	}
	if u, err := url.Parse(e.Source); err != nil || u.Scheme != "https" || u.Host == "" {
		ps = append(ps, "has no https source; the URL of the Microsoft page that defines the term is the guard against an invented term")
	}
	n := normTerm(e.Term)
	contains := false
	for _, tok := range c.Cfg.IdentDenylist {
		t := normTerm(tok)
		contains = contains || strings.Contains(n, t)
		if n == t {
			ps = append(ps, fmt.Sprintf("normalises to %q, a denylist token; a profile word is never an external name", n))
		}
	}
	if !contains {
		ps = append(ps, fmt.Sprintf("normalises to %q, which contains no denylist token and needs no registration", n))
	}
	for _, st := range refusedStems {
		if n == st {
			ps = append(ps, fmt.Sprintf("normalises to %q, a refused stem; a stem is not an exact external name", n))
		}
	}
	return ps
}

// externalTerms returns the normalised registered terms that are cut out of an identifier: every
// entry that passes termProblems, longest first so a term that contains another is cut whole.
func (c *Ctx) externalTerms() []string {
	if c.extTerms != nil {
		return *c.extTerms
	}
	ts := []string{}
	for _, e := range c.Cfg.ExternalVocabulary {
		if len(c.termProblems(e)) == 0 {
			ts = append(ts, normTerm(e.Term))
		}
	}
	sort.Slice(ts, func(i, j int) bool { return len(ts[i]) > len(ts[j]) || len(ts[i]) == len(ts[j]) && ts[i] < ts[j] })
	c.extTerms = &ts
	return ts
}

// profileNamed returns the denylist token an identifier or flag value contains, or "". It
// normalises s, cuts out every occurrence of every registered external term (each cut leaves a
// separator, so the pieces on either side never join into a token), and runs the denylist over
// each remaining piece (erratum E-1). A refused or invalid registry entry cuts nothing.
func (c *Ctx) profileNamed(s string) string {
	n := normTerm(s)
	for _, t := range c.externalTerms() {
		n = strings.ReplaceAll(n, t, "|")
	}
	for _, piece := range strings.Split(n, "|") {
		for _, tok := range c.Cfg.IdentDenylist {
			if strings.Contains(piece, normIdent(tok)) {
				return tok
			}
		}
	}
	return ""
}

// checkExternalVocabulary validates the registry: an invalid entry fails naming the entry and the
// reason, and so does a stale one (no identifier the check evaluates contains it).
func (c *Ctx) checkExternalVocabulary() []Violation {
	var vs []Violation
	const pos = defaultManifest
	seen := map[string]bool{}
	for _, e := range c.Cfg.ExternalVocabulary {
		fail := func(why string) {
			vs = append(vs, Violation{"P1", pos, fmt.Sprintf("externalVocabulary entry %q: %s (ADR-0002 erratum E-1)", e.Term, why)})
		}
		for _, p := range c.termProblems(e) {
			fail(p)
		}
		n := normTerm(e.Term)
		if seen[n] {
			fail("is registered twice")
		}
		seen[n] = true
		used := false
		for _, f := range c.Tree.Files {
			if !c.domainFile(f) {
				continue
			}
			ast.Inspect(f.AST, func(nd ast.Node) bool {
				if id, ok := nd.(*ast.Ident); ok && !used && strings.Contains(normTerm(id.Name), n) {
					used = true
				}
				return !used
			})
			if used {
				break
			}
		}
		if !used && n != "" {
			fail("matches no identifier in the tree (stale); remove it")
		}
	}
	return vs
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
				// os.Environ(), syscall.Environ() and the method (*exec.Cmd).Environ(), which is
				// treated exactly like os.Environ() so the method is no way around the rule (E-2).
				if x.Sel.Name == "Environ" {
					if pk, isIdent := x.X.(*ast.Ident); isIdent {
						if ip, isPkg := f.Imports[pk.Name]; isPkg && ip != "os" && ip != "syscall" {
							return true // another package's function of that name
						}
					}
					if ok, why := c.environForwarded(f, x, parents, profEnv); !ok {
						add(f.Pos(x.Pos()), fmt.Sprintf("%s outside the config loader (%s); %s", environText(x), strings.Join(c.Cfg.ConfigLoader, ", "), why))
					}
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
				if !isCall || call.Fun != ast.Expr(x) || len(call.Args) == 0 {
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

// environText renders pkg.Environ or recv.Environ for a message.
func environText(x *ast.SelectorExpr) string {
	if id, ok := x.X.(*ast.Ident); ok {
		return id.Name + ".Environ"
	}
	return "(…).Environ"
}

// hasCall reports whether the expression contains a call, which is never part of a constant string.
func hasCall(e ast.Expr) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		if _, ok := n.(*ast.CallExpr); ok {
			found = true
		}
		return !found
	})
	return found
}

// environForwarded decides erratum E-2 for one os.Environ / cmd.Environ selector. The environment
// may be handed to a child process in exactly two forms, and nothing else is allowed:
//
//	X.Env = os.Environ()
//	X.Env = append(os.Environ(), a, b…)   every a constant string whose name part (before "=")
//	                                      does not match profileEnvRegexp
//
// A constant string is a constant expression (a literal, a package constant, a concatenation of
// those), not only a literal. Any function call or conversion inside the argument disqualifies it. The tree is parsed, not type-checked, so a
// function-local constant is not recognised and fails: declare it at package level.
func (c *Ctx) environForwarded(f *File, sel *ast.SelectorExpr, parents map[ast.Node]ast.Node, profEnv *regexp.Regexp) (bool, string) {
	const hint = "allowed only as X.Env = os.Environ() or X.Env = append(os.Environ(), constant strings); read configuration through compose/config"
	call, isCall := parents[sel].(*ast.CallExpr)
	if !isCall || call.Fun != ast.Expr(sel) || len(call.Args) != 0 {
		return false, "the environment is read in a way that hides which variable it reads; " + hint
	}
	var top ast.Node = call
	var appended []ast.Expr
	if ap, isAppend := parents[call].(*ast.CallExpr); isAppend {
		if fn, ok := ap.Fun.(*ast.Ident); !ok || fn.Name != "append" || len(ap.Args) == 0 || ap.Args[0] != ast.Expr(call) || ap.Ellipsis.IsValid() {
			return false, "the environment is passed on or consumed, not assigned to a child's Env; " + hint
		}
		top, appended = ap, ap.Args[1:]
	}
	as, isAssign := parents[top].(*ast.AssignStmt)
	if !isAssign || as.Tok != token.ASSIGN || len(as.Lhs) != 1 || len(as.Rhs) != 1 || as.Rhs[0] != top.(ast.Expr) {
		return false, "the environment is used other than as the right side of X.Env = …; " + hint
	}
	if lhs, ok := as.Lhs[0].(*ast.SelectorExpr); !ok || lhs.Sel.Name != "Env" {
		return false, "the environment is assigned to something other than a child's Env field; " + hint
	}
	for _, a := range appended {
		// EvalString reads a one-argument call as a conversion, which is right for its other callers
		// but would let mk("A=1") through here; a constant expression contains no call at all.
		s, prefix, ok := c.Tree.EvalString(f, a)
		if hasCall(a) || !ok || prefix {
			return false, "an appended argument is not a constant string, so it cannot be shown not to set a profile-selecting variable; " + hint
		}
		name, _, _ := strings.Cut(s, "=")
		if profEnv.MatchString(name) {
			return false, fmt.Sprintf("it appends %q, a profile-selecting environment variable; only compose/config sets it (ADR-0002 rule 1)", s)
		}
	}
	return true, ""
}

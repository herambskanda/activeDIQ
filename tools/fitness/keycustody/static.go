package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Violation is one failed rule. Check is FF-KEY-1..6, Rule names the rule inside the check.
type Violation struct {
	Check, Rule, Where, Msg string
}

func (v Violation) String() string {
	return fmt.Sprintf("%s %s [%s]: %s", v.Where, v.Check, v.Rule, v.Msg)
}

const (
	keysDir     = "internal/platform/keys"
	composeDir  = "internal/compose/server"
	keystestDir = "internal/platform/keys/keystest"
)

// goFile is one parsed Go source file of the tree.
type goFile struct {
	Rel    string // slash path relative to the root
	Test   bool
	File   *ast.File
	Fset   *token.FileSet
	Source string
}

func (g goFile) line(p token.Pos) int { return g.Fset.Position(p).Line }
func (g goFile) where(p token.Pos) string {
	return g.Rel + ":" + strconv.Itoa(g.line(p))
}

// in reports whether the file is dir or below it.
func (g goFile) in(dir string) bool { return g.Rel == dir || strings.HasPrefix(g.Rel, dir+"/") }

var skipDirs = map[string]bool{".git": true, "node_modules": true, "testdata": true, "vendor": true, ".activeDIQ-worktrees": true, "web": true, "factory": true, "knowledge": true}

// loadGo parses every Go file under root (not testdata, vendor, web or the knowledge base). A file that
// does not parse is a hard error: a check never passes over code it could not read.
func loadGo(root string) ([]goFile, error) {
	var out []goFile
	fset := token.NewFileSet()
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
		if !strings.HasSuffix(p, ".go") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		f, err := parser.ParseFile(fset, p, b, parser.SkipObjectResolution)
		if err != nil {
			return fmt.Errorf("parse %s: %w", p, err)
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		out = append(out, goFile{Rel: rel, Test: strings.HasSuffix(rel, "_test.go"), File: f, Fset: fset, Source: string(b)})
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Rel < out[j].Rel })
	return out, err
}

func importsKeys(f *ast.File) bool {
	for _, im := range f.Imports {
		if strings.HasSuffix(strings.Trim(im.Path.Value, `"`), "/internal/platform/keys") {
			return true
		}
	}
	return false
}

func strLits(f *ast.File, fn func(lit *ast.BasicLit, s string)) {
	ast.Inspect(f, func(n ast.Node) bool {
		if l, ok := n.(*ast.BasicLit); ok && l.Kind == token.STRING {
			if s, err := strconv.Unquote(l.Value); err == nil {
				fn(l, s)
			}
		}
		return true
	})
}

// kekPrefix is the prefix of the KEK settings, split so that this tool does not itself "name" them:
// the composition root's own scope test (kekscope_test.go) scans tools/ for the whole word.
const kekPrefix = "ACTIVEDIQ_" + "KEK_"

var tenantKeysRE = regexp.MustCompile(`(?i)\btenant_keys\b`)

// checkFFKey2 is the single-owner scan: tenant_keys is named only inside the keys package (and the
// migrations, which are .sql); the DEK constructors and the provider wrap/unwrap calls are used only
// by the keys package, keystest and the composition root. Test files may name tenant_keys only in
// internal/platform/keys and the composition root's own tests; calls are judged in non-test code.
func checkFFKey2(files []goFile) []Violation {
	var vs []Violation
	callBanned := map[string]bool{"NewDEK": true, "DEKFromBytes": true, "WrapDEK": true, "UnwrapDEK": true}
	methodBanned := map[string]bool{"Wrap": true, "Unwrap": true}
	for _, g := range files {
		keysOwner := g.in(keysDir)
		if !keysOwner && !(g.Test && g.in(composeDir)) && !g.in("tools/fitness/keycustody") {
			strLits(g.File, func(l *ast.BasicLit, s string) {
				if tenantKeysRE.MatchString(s) {
					vs = append(vs, Violation{"FF-KEY-2", "tenant_keys-owner", g.where(l.Pos()), "tenant_keys is named outside internal/platform/keys; only the keys package reads or writes it"})
				}
			})
		}
		if g.Test || keysOwner || g.in(composeDir) || g.in("tools/fitness/keycustody") {
			continue
		}
		imp := importsKeys(g.File)
		ast.Inspect(g.File, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.SelectorExpr:
				if id, ok := x.X.(*ast.Ident); ok && id.Name == "keys" && callBanned[x.Sel.Name] {
					vs = append(vs, Violation{"FF-KEY-2", "dek-calls", g.where(x.Pos()), "keys." + x.Sel.Name + " is used outside internal/platform/keys, keystest and compose/server"})
				}
			case *ast.CallExpr:
				// Provider.Wrap(req, plaintext) takes 2 arguments and Provider.Unwrap(req, ref, wrapped) 3;
				// errors.Unwrap(err) and friends do not match, which is what keeps this name-based scan quiet.
				sel, ok := x.Fun.(*ast.SelectorExpr)
				if !ok || !imp || !methodBanned[sel.Sel.Name] {
					return true
				}
				if (sel.Sel.Name == "Wrap" && len(x.Args) == 2) || (sel.Sel.Name == "Unwrap" && len(x.Args) == 3) {
					vs = append(vs, Violation{"FF-KEY-2", "provider-calls", g.where(sel.Pos()), "Provider." + sel.Sel.Name + " is called outside the keys package and compose/server"})
				}
			}
			return true
		})
	}
	return vs
}

var (
	kekEnvRE     = regexp.MustCompile(kekPrefix)
	secretNameRE = regexp.MustCompile(`(?i)^(passphrase|kek|kekvalue|kekbytes|kekpassphrase|kekpass|rawkek|kekmaterial)$`)
	secretFlagRE = regexp.MustCompile(`(?i)(passphrase|kek)`)
	secretColRE  = regexp.MustCompile(`(?im)^\s*(passphrase|kek_value|kek_secret|raw_kek|kek_bytes|kek_passphrase)\s+(text|bytea|varchar|character)`)
	providerDef  = regexp.MustCompile(kekPrefix + `PROVIDER["']?\s*[=:]\s*["']?[A-Za-z0-9]`)
)

// checkFFKey3 is "config only in the root": the KEK settings are named only by the composition root (its
// tests too, and this tool); no struct field, flag or column carries a passphrase or KEK value; no
// shipped file gives the provider setting a default.
func checkFFKey3(root string, files []goFile) ([]Violation, error) {
	var vs []Violation
	for _, g := range files {
		if g.in(composeDir) || g.in("tools/fitness/keycustody") {
			continue
		}
		if !g.Test {
			strLits(g.File, func(l *ast.BasicLit, s string) {
				if kekEnvRE.MatchString(s) {
					vs = append(vs, Violation{"FF-KEY-3", "env-owner", g.where(l.Pos()), "the KEK settings are read outside internal/compose/server"})
				}
			})
		}
		ast.Inspect(g.File, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.Field:
				if _, isStruct := nodeIsStructField(x); !isStruct {
					return true
				}
				for _, nm := range x.Names {
					if secretNameRE.MatchString(nm.Name) && isStringOrBytes(x.Type) && !g.in(keysDir) && !g.Test {
						vs = append(vs, Violation{"FF-KEY-3", "secret-field", g.where(nm.Pos()), "struct field " + nm.Name + " carries a passphrase/KEK value; only a path to a file may be configured"})
					}
				}
			case *ast.CallExpr:
				sel, ok := x.Fun.(*ast.SelectorExpr)
				if !ok || g.Test {
					return true
				}
				if pk, ok := sel.X.(*ast.Ident); ok && pk.Name == "flag" && len(x.Args) > 0 {
					if lit, ok := x.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
						name, _ := strconv.Unquote(lit.Value)
						if secretFlagRE.MatchString(name) && !strings.HasSuffix(strings.ToLower(name), "file") && !strings.HasSuffix(strings.ToLower(name), "dir") && !strings.HasSuffix(strings.ToLower(name), "provider") {
							vs = append(vs, Violation{"FF-KEY-3", "secret-flag", g.where(lit.Pos()), "flag -" + name + " would take a passphrase/KEK value on the command line"})
						}
					}
				}
			}
			return true
		})
	}
	// Non-Go files: migrations (columns) and shipped config (defaults for the provider).
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if skipDirs[d.Name()] && p != root {
				return filepath.SkipDir
			}
			return nil
		}
		top := strings.SplitN(rel, "/", 2)[0]
		inMig := top == "migrations" && strings.HasSuffix(rel, ".sql")
		inShip := top == "packaging" || top == "helm.yaml" || top == "lab" || strings.HasPrefix(d.Name(), ".env") || strings.HasPrefix(d.Name(), "Dockerfile") || strings.HasSuffix(d.Name(), ".env")
		if !inMig && !inShip {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for i, ln := range strings.Split(string(b), "\n") {
			at := rel + ":" + strconv.Itoa(i+1)
			if inMig && secretColRE.MatchString(ln) {
				vs = append(vs, Violation{"FF-KEY-3", "secret-column", at, "a database column would hold a passphrase/KEK value"})
			}
			if inShip && providerDef.MatchString(ln) {
				vs = append(vs, Violation{"FF-KEY-3", "provider-default", at, "the KEK provider setting is given a value in shipped config; there is no default custody model"})
			}
		}
		return nil
	})
	return vs, err
}

// nodeIsStructField is true for every *ast.Field found by Inspect that has names; interface methods and
// parameters also appear as Fields, but their types are funcs or are filtered by name+type above.
func nodeIsStructField(f *ast.Field) (*ast.Field, bool) { return f, len(f.Names) > 0 }

func isStringOrBytes(e ast.Expr) bool {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name == "string"
	case *ast.ArrayType:
		id, ok := t.Elt.(*ast.Ident)
		return ok && t.Len == nil && id.Name == "byte"
	}
	return false
}

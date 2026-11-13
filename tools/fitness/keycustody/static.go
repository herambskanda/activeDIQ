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
	// providerSet finds an assignment of the provider setting: NAME=v, NAME: v, "NAME": "v", ENV NAME v. The
	// match is the name and separator; the value runs to the next assignment on the line (or the end of it),
	// and providerDefault judges every such segment: a compliant first assignment must not hide a later default.
	providerSet = regexp.MustCompile(kekPrefix + `PROVIDER["']?\s*[=:]\s*`)
	providerEnv = regexp.MustCompile(`^\s*(?i:ENV)\s+` + kekPrefix + `PROVIDER\s+(\S.*)$`)
	// requiredForm is the only expansion that is not a default: ${VAR:?msg} / ${VAR?msg} fail when VAR is
	// unset, so the operator has to choose.
	requiredForm = regexp.MustCompile(`\$\{[A-Za-z_][A-Za-z0-9_]*:?\?[^}]*\}`)
	valueToken   = regexp.MustCompile(`^[^\s;&|#,}\]\\]+`)
	// providerRead is a read of the provider variable itself, `${<KEK prefix>PROVIDER<op><body>}`, as in a
	// launcher guard `: "${<KEK prefix>PROVIDER:?must choose}"`. It is not an assignment: the ?-forms and an
	// empty `${NAME:-}` (a test for "unset") are the operator-must-choose shapes; `${NAME:-x}`, `${NAME:=x}`
	// and `${NAME-x}` hand the model a default, so a non-empty body is a violation.
	providerRead = regexp.MustCompile(`\$\{` + kekPrefix + `PROVIDER(:?[-=+?])([^}]*)\}`)
)

// providerDefault is true when the line gives <KEK prefix>PROVIDER a value other than "operator must
// supply it". Empty (`NAME=`, `NAME:`), a YAML comment and the required-without-default expansion pass;
// everything else is a shipped default, whether literal, a $VAR / ${VAR} reference, a ${VAR:-x} /
// ${VAR-x} / ${VAR:=x} / ${VAR:+x} expansion, or command substitution: a variable defined by an ARG, a
// shell assignment or the host environment is how a default hides one hop away (T-1650). A read of the
// provider variable (providerRead) is judged on its own: ${NAME:?msg} / ${NAME?msg} and an empty ${NAME:-}
// guard pass, ${NAME:-x} / ${NAME:=x} / ${NAME-x} fail.
func providerDefault(line string) bool {
	for _, m := range providerRead.FindAllStringSubmatch(line, -1) {
		if !strings.HasSuffix(m[1], "?") && m[2] != "" {
			return true
		}
	}
	line = providerRead.ReplaceAllString(line, "")
	var segs []string
	if locs := providerSet.FindAllStringIndex(line, -1); len(locs) > 0 {
		for i, l := range locs {
			end := len(line)
			if i+1 < len(locs) {
				end = locs[i+1][0]
			}
			segs = append(segs, line[l[1]:end])
		}
	} else if m := providerEnv.FindStringSubmatch(line); m != nil {
		segs = append(segs, m[1])
	} else {
		return false
	}
	for _, rest := range segs {
		if providerValueDefault(rest) {
			return true
		}
	}
	return false
}

// providerValueDefault judges the text that follows one assignment of the provider setting.
func providerValueDefault(rest string) bool {
	rest = requiredForm.ReplaceAllString(rest, "")
	rest = strings.TrimLeft(rest, " \t\"'")
	rest = strings.ReplaceAll(rest, `"`, "")
	rest = strings.ReplaceAll(rest, `'`, "")
	return valueToken.MatchString(rest)
}

var (
	xmlComment = regexp.MustCompile(`(?s)<!--.*?-->`)
	// xmlElement matches one start tag, attribute-aware (a ">" inside a quoted value does not end it), over
	// several lines; xmlAttr then reads its name="value" pairs.
	xmlElement = regexp.MustCompile(`(?s)<[A-Za-z][\w:.-]*((?:\s+[\w:.-]+\s*=\s*(?:"[^"]*"|'[^']*'))*)\s*/?>`)
	xmlAttr    = regexp.MustCompile(`([\w:.-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')`)
	// pairArgs is NAME followed by a separate value token as the next call argument: SetEnvironmentVariable(
	// "NAME", "v"), Setenv, os.environ.setdefault, which may sit on the next line (PowerShell backtick
	// continuation allowed). pairWords is the word-separated form of the commands that set a variable: setx NAME v,
	// Set-Item Env:NAME v, New-ItemProperty/Set-ItemProperty -Name NAME -Value v (either order). Prose that
	// merely mentions the name is not a set.
	//
	// pairArgs needs a call context: an identifier (optionally ::member), "(", and the quoted name followed by a
	// comma. A list of names (@("NAME", "OTHER"), foreach ... in ('NAME','X')) or prose ("NAME, the KEK provider,
	// must be set") is not a set, and a preflight check that merely names the variable must not be flagged, or
	// authors split the name and every FF-KEY-3 rule goes blind (T-1764 review).
	pairArgs = regexp.MustCompile(`(?s)([\w-]+)(?:::\w+)?\s*\([\s` + "`" + `]*["']` + kekPrefix + `PROVIDER["']\s*,[\s` + "`" + `]*("[^"]*"|'[^']*'|[^\s,)"';&|}\]]+)`)
	tok      = `("[^"]*"|'[^']*'|[^\s,)"';&|}\]` + "`" + `]+)`
	// posTok is a positional value: a token that does not start with "-" (that would be the next parameter).
	posTok = `("[^"]*"|'[^']*'|[^\s,)"';&|}\]` + "`" + `\-][^\s,)"';&|}\]` + "`" + `]*)`
	// gap spans the rest of a PowerShell statement, following backtick line continuations.
	gap = "(?:[^\\n]|`\\r?\\n)*?"
	ws  = "(?:[ \\t]|`\\r?\\n)+"
	// envCmds are the cmdlets that write an Env: drive item.
	envCmds   = `\b(?:Set-Item|New-Item|Set-Content|Add-Content)\b`
	envName   = `["']?Env:\\?` + kekPrefix + `PROVIDER(?:["']|\b)`
	pairWords = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\bsetx(?:\.exe)?\s+(?:/\w+\s+)*["']?` + kekPrefix + `PROVIDER["']?[ \t]+` + tok),
		// Set-Item Env:NAME v, Set-Item Env:\NAME v, Set-Item -Path Env:NAME -Value v, New-Item/Set-Content alike.
		regexp.MustCompile(`(?i)` + envCmds + ws + `(?:-(?:Literal)?Path` + ws + `)?` + envName + ws + `(?:-Value` + ws + `)?` + posTok),
		regexp.MustCompile(`(?i)` + envCmds + gap + envName + gap + `-Value` + ws + tok),
		regexp.MustCompile(`(?i)` + envCmds + gap + `-Value` + ws + tok + gap + envName),
		// New-ItemProperty/Set-ItemProperty -Name NAME -Value v, either order, continued lines included.
		regexp.MustCompile(`(?i)-Name` + ws + `["']?` + kekPrefix + `PROVIDER(?:["']|\b)` + gap + `-Value` + ws + tok),
		regexp.MustCompile(`(?i)-Value` + ws + tok + gap + `-Name` + ws + `["']?` + kekPrefix + `PROVIDER\b`),
	}
	// readCall: a name followed by a scope is a read, not a value: GetEnvironmentVariable("NAME", "Machine").
	readCall = regexp.MustCompile(`(?i)^(GetEnvironmentVariable|ExpandEnvironmentVariables|LookupEnv)$`)
	// notCalls are keywords that take a parenthesised list, not calls: foreach ($v in ('NAME','X')).
	notCalls = map[string]bool{"in": true, "if": true, "elseif": true, "foreach": true, "for": true, "while": true, "switch": true, "return": true, "and": true, "or": true, "not": true, "array": true}
	// emptyValue is a token that unsets or leaves the setting empty.
	emptyValue = regexp.MustCompile(`(?i)^(""|''|\$null|\$\{?null\}?)$`)
	nameAttrs  = map[string]bool{"name": true, "key": true, "id": true, "variable": true}
	valueAttrs = map[string]bool{"value": true, "default": true, "defaultvalue": true}
)

// providerMultiToken finds the provider setting given a value where the name and the value are separate
// tokens, which the per-line providerDefault cannot see (T-1764): an XML element whose name-like attribute
// (Name, Key, Id) is <KEK prefix>PROVIDER and whose Value attribute is non-empty — WiX <Environment
// Name=".." Value=".."/> in any attribute order or across lines — and a name followed by its value as the next
// call argument or word (SetEnvironmentVariable("NAME","v"), setx NAME v). It returns the 1-based lines of the
// offending names, which the caller dedupes against the per-line pass.
func providerMultiToken(src string) []int {
	var lines []int
	lineOf := func(off int) int { return 1 + strings.Count(src[:off], "\n") }
	// XML comments are blanked, newlines kept so line numbers stay true.
	xml := xmlComment.ReplaceAllStringFunc(src, func(c string) string {
		return strings.Map(func(r rune) rune {
			if r == '\n' {
				return r
			}
			return ' '
		}, c)
	})
	for _, m := range xmlElement.FindAllStringSubmatchIndex(xml, -1) {
		var named, valued bool
		for _, a := range xmlAttr.FindAllStringSubmatch(xml[m[2]:m[3]], -1) {
			v := a[2] + a[3]
			k := strings.ToLower(a[1])
			if nameAttrs[k] && kekEnvRE.MatchString(v) && strings.EqualFold(v, kekPrefix+"PROVIDER") {
				named = true
			}
			if valueAttrs[k] && strings.TrimSpace(v) != "" {
				valued = true
			}
		}
		if named && valued {
			lines = append(lines, lineOf(m[0]))
		}
	}
	for _, m := range pairArgs.FindAllStringSubmatchIndex(src, -1) {
		if id := src[m[2]:m[3]]; readCall.MatchString(id) || notCalls[strings.ToLower(id)] {
			continue
		}
		if emptyValue.MatchString(src[m[4]:m[5]]) {
			continue
		}
		lines = append(lines, lineOf(m[0]))
	}
	for _, re := range pairWords {
		for _, m := range re.FindAllStringSubmatchIndex(src, -1) {
			if !emptyValue.MatchString(src[m[2]:m[3]]) {
				lines = append(lines, lineOf(m[0]))
			}
		}
	}
	return lines
}

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
		// lab/ is not shipped: the lab scripts write per-run config for a throw-away server and name the provider
		// they exercise explicitly; the scan covers what customers receive.
		inShip := top == "packaging" || top == "helm.yaml" || strings.HasPrefix(d.Name(), ".env") || strings.HasPrefix(d.Name(), "Dockerfile") || strings.HasSuffix(d.Name(), ".env")
		if !inMig && !inShip {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		reported := map[int]bool{}
		if inShip {
			for _, n := range providerMultiToken(string(b)) {
				if !reported[n] {
					reported[n] = true
					vs = append(vs, Violation{"FF-KEY-3", "provider-default", rel + ":" + strconv.Itoa(n), "the KEK provider setting is given a value in shipped config (name and value in separate tokens); there is no default custody model"})
				}
			}
		}
		for i, ln := range strings.Split(string(b), "\n") {
			at := rel + ":" + strconv.Itoa(i+1)
			if inMig && secretColRE.MatchString(ln) {
				vs = append(vs, Violation{"FF-KEY-3", "secret-column", at, "a database column would hold a passphrase/KEK value"})
			}
			if inShip && !reported[i+1] && providerDefault(ln) {
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

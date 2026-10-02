package main

import (
	"bufio"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Violation is one broken rule at one place. Check is the ADR-0002 check id (P1, P7, U1, U2,
// or ACT for the activation table); Pos is file:line, or just a file or a subject.
type Violation struct {
	Check string
	Pos   string
	Msg   string
}

func (v Violation) String() string {
	return fmt.Sprintf("%s: %s (ADR-0002 fitness function): %s", v.Pos, v.Check, v.Msg)
}

func sortViolations(vs []Violation) {
	sort.SliceStable(vs, func(i, j int) bool {
		if vs[i].Check != vs[j].Check {
			return vs[i].Check < vs[j].Check
		}
		if vs[i].Pos != vs[j].Pos {
			return vs[i].Pos < vs[j].Pos
		}
		return vs[i].Msg < vs[j].Msg
	})
}

// skipDir names directories that hold no product Go code, or hold copied or generated state.
func skipDir(name string) bool {
	switch name {
	case ".git", "node_modules", "testdata", "vendor", "factory", "knowledge", "garage", ".claude", "target":
		return true
	}
	return false
}

// under reports whether dir is prefix or a descendant of prefix.
func under(dir, prefix string) bool {
	prefix = strings.TrimSuffix(prefix, "/")
	return dir == prefix || strings.HasPrefix(dir, prefix+"/")
}

func underAny(dir string, prefixes []string) bool {
	for _, p := range prefixes {
		if under(dir, p) {
			return true
		}
	}
	return false
}

// File is one parsed Go file.
type File struct {
	Rel     string // slash path relative to the root
	Dir     string // package directory, slash path relative to the root ("." for the root)
	Test    bool
	AST     *ast.File
	Fset    *token.FileSet
	Imports map[string]string // local name -> import path
}

// Pos renders file:line for a node position.
func (f *File) Pos(p token.Pos) string {
	return fmt.Sprintf("%s:%d", f.Rel, f.Fset.Position(p).Line)
}

// Tree is every Go file of the repository, parsed once.
type Tree struct {
	Root    string
	ModPath string
	Files   []*File
	byDir   map[string][]*File
	consts  map[string]map[string]string // dir -> const name -> string value
}

// Dirs lists the package directories, sorted.
func (t *Tree) Dirs() []string {
	var ds []string
	for d := range t.byDir {
		ds = append(ds, d)
	}
	sort.Strings(ds)
	return ds
}

// LoadTree parses every Go file under root outside the skipped directories.
func LoadTree(root string) (*Tree, error) {
	modPath, err := modulePath(filepath.Join(root, "go.mod"))
	if err != nil {
		return nil, err
	}
	t := &Tree{Root: root, ModPath: modPath, byDir: map[string][]*File{}}
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != root && skipDir(d.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		fset := token.NewFileSet()
		af, err := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
		if err != nil {
			return fmt.Errorf("%s: %w", rel, err)
		}
		f := &File{Rel: rel, Dir: path.Dir(rel), Test: strings.HasSuffix(rel, "_test.go"), AST: af, Fset: fset, Imports: map[string]string{}}
		for _, is := range af.Imports {
			ip, err := strconv.Unquote(is.Path.Value)
			if err != nil {
				return fmt.Errorf("%s: %w", rel, err)
			}
			name := path.Base(ip)
			if strings.HasPrefix(name, "v") && len(name) > 1 && name[1] >= '0' && name[1] <= '9' {
				name = path.Base(path.Dir(ip))
			}
			if is.Name != nil {
				name = is.Name.Name
			}
			f.Imports[name] = ip
		}
		t.Files = append(t.Files, f)
		t.byDir[f.Dir] = append(t.byDir[f.Dir], f)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(t.Files, func(i, j int) bool { return t.Files[i].Rel < t.Files[j].Rel })
	t.consts = map[string]map[string]string{}
	return t, nil
}

func modulePath(gomod string) (string, error) {
	f, err := os.Open(gomod)
	if err != nil {
		return "", err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(s.Text()), "module "); ok {
			return strings.Trim(strings.TrimSpace(rest), `"`), nil
		}
	}
	return "", fmt.Errorf("%s: no module directive", gomod)
}

// Local converts an import path to a repository-relative directory, or "" if it is not ours.
func (t *Tree) Local(importPath string) string {
	if importPath == t.ModPath {
		return "."
	}
	if rest, ok := strings.CutPrefix(importPath, t.ModPath+"/"); ok {
		return rest
	}
	return ""
}

// Consts returns the package-level string constants of a package directory (test files excluded).
// A constant that is not a string literal, a conversion of one, or a concatenation of those is
// simply absent.
func (t *Tree) Consts(dir string) map[string]string {
	if m, ok := t.consts[dir]; ok {
		return m
	}
	m := map[string]string{}
	t.consts[dir] = m
	for pass := 0; pass < 3; pass++ { // constants may refer to later constants
		for _, f := range t.byDir[dir] {
			if f.Test {
				continue
			}
			for _, d := range f.AST.Decls {
				gd, ok := d.(*ast.GenDecl)
				if !ok || gd.Tok != token.CONST {
					continue
				}
				for _, sp := range gd.Specs {
					vs := sp.(*ast.ValueSpec)
					for i, n := range vs.Names {
						if i >= len(vs.Values) {
							continue
						}
						if s, _, ok := t.EvalString(f, vs.Values[i]); ok {
							m[n.Name] = s
						}
					}
				}
			}
		}
	}
	return m
}

// EvalString evaluates a string-valued expression in the context of file f: literals, package
// constants (own package or imported), conversions such as Role("x") and concatenation. prefix is
// true when only a leading part is known (a literal + a variable); s is then that leading part.
func (t *Tree) EvalString(f *File, e ast.Expr) (s string, prefix bool, ok bool) {
	switch x := e.(type) {
	case *ast.BasicLit:
		if x.Kind != token.STRING {
			return "", false, false
		}
		v, err := strconv.Unquote(x.Value)
		return v, false, err == nil
	case *ast.ParenExpr:
		return t.EvalString(f, x.X)
	case *ast.Ident:
		if v, ok := t.Consts(f.Dir)[x.Name]; ok {
			return v, false, true
		}
	case *ast.SelectorExpr:
		if id, ok := x.X.(*ast.Ident); ok {
			if ip, ok := f.Imports[id.Name]; ok {
				if dir := t.Local(ip); dir != "" {
					if v, ok := t.Consts(dir)[x.Sel.Name]; ok {
						return v, false, true
					}
				}
			}
		}
	case *ast.CallExpr:
		if len(x.Args) == 1 {
			if _, isType := x.Fun.(*ast.Ident); isType { // a conversion such as Role("x")
				return t.EvalString(f, x.Args[0])
			}
			if sel, isSel := x.Fun.(*ast.SelectorExpr); isSel { // capability.ID("x")
				if pk, isPkg := sel.X.(*ast.Ident); isPkg && t.Local(f.Imports[pk.Name]) != "" {
					return t.EvalString(f, x.Args[0])
				}
			}
		}
	case *ast.BinaryExpr:
		if x.Op != token.ADD {
			return "", false, false
		}
		l, lp, lok := t.EvalString(f, x.X)
		if !lok {
			return "", false, false
		}
		if lp {
			return l, true, true
		}
		r, rp, rok := t.EvalString(f, x.Y)
		if !rok {
			return l, true, true
		}
		return l + r, rp, true
	}
	return "", false, false
}

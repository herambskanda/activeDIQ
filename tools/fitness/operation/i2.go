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
	"strings"
)

// I2 (impersonate-as-admin attribution, invariant I-2, T-1601/T-1629): no Action writes a technician,
// token or account identifier into a directory attribute. The DC's own change log records written
// values, so such a value would leak the attribution into the DC log. Two syntactic halves:
//
//   - Go: in non-test source under internal/modules and internal/platform, no operation.Change literal
//     (the attribute diff of a step) takes its Before or After from an expression that names an
//     initiator-chain or account/token identifier (Requester, Via, Chain, Actor, PrincipalID,
//     AccountID, APITokenID, ApprovedBy ...);
//   - proto: in the connector write contract, only ActingPrincipal (and the Plan and Apply requests that
//     carry it, for the connector's own audit) may have a field that names a principal, token, account
//     or actor. Every message that carries a directory value is free of one.

const i2WriteProto = "proto/activediq/connector/v1/write.proto"

var i2GoRoots = []string{"internal/modules", "internal/platform"}

// i2Tainted are the identifiers an initiator's identity travels in.
var i2Tainted = map[string]bool{
	"Requester": true, "Via": true, "Chain": true, "Actor": true, "Initiator": true, "PrincipalID": true,
	"AccountID": true, "AccountId": true, "APITokenID": true, "ApiTokenId": true, "TokenID": true, "ApprovedBy": true,
}

var i2ProtoField = regexp.MustCompile(`(?i)(requester|technician|principal|token|account_id|actor|approver|initiator)`)
var i2ProtoExempt = map[string]bool{"ActingPrincipal": true, "PlanRequest": true, "ApplyRequest": true}
var protoMessage = regexp.MustCompile(`^\s*message\s+(\w+)\s*\{`)
var protoField = regexp.MustCompile(`^\s*(?:repeated\s+|optional\s+)?[\w.]+\s+(\w+)\s*=\s*\d+`)

// i2File is one parsed non-test source file.
type i2File struct {
	rel  string
	fset *token.FileSet
	f    *ast.File
	src  []string // source lines, for the i2:exempt directive
}

// CheckI2 returns the I2 violations under root.
func CheckI2(root string) ([]Violation, error) {
	var files []i2File
	for _, r := range i2GoRoots {
		base := filepath.Join(root, filepath.FromSlash(r))
		if _, err := os.Stat(base); err != nil {
			continue
		}
		err := filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if skipDir(d.Name()) {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, _ := filepath.Rel(root, path)
			rel = filepath.ToSlash(rel)
			src, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, rel, src, parser.SkipObjectResolution)
			if err != nil {
				return fmt.Errorf("%s: %w", rel, err)
			}
			files = append(files, i2File{rel, fset, f, strings.Split(string(src), "\n")})
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	funcs := taintedFuncs(files)
	var out []Violation
	for _, file := range files {
		out = append(out, checkI2File(file, funcs)...)
	}
	pv, err := checkI2Proto(root)
	if err != nil {
		return nil, err
	}
	out = append(out, pv...)
	sort.Slice(out, func(i, j int) bool { return out[i].Pos < out[j].Pos })
	return out, nil
}

// taintScope knows which local identifiers and which functions carry an initiator identity.
type taintScope struct {
	locals map[string]string // local variable -> the identity it was assigned from
	funcs  map[string]string // function or method name -> the identity it returns
}

// passThrough are the callees whose result is made of their arguments: conversions and the formatting
// and slice helpers. Any other call's arguments do not make its result an identity (w.Grant(ctx, tx, actor)).
var passThrough = map[string]bool{"string": true, "append": true, "sorted": true, "copy": true}
var passThroughPkg = map[string]bool{"fmt": true, "strings": true, "strconv": true, "slices": true, "sort": true, "path": true, "filepath": true}

// name returns the first initiator-identity identifier, selector, tainted local or tainted-function
// call named inside e.
func (s taintScope) name(e ast.Expr) string {
	var found string
	var walk func(n ast.Node) bool
	walk = func(n ast.Node) bool {
		if found != "" {
			return false
		}
		switch x := n.(type) {
		case *ast.SelectorExpr:
			if i2Tainted[x.Sel.Name] {
				found = x.Sel.Name
			}
		case *ast.Ident:
			if i2Tainted[x.Name] {
				found = x.Name
			} else if w := s.locals[x.Name]; w != "" {
				found = w
			}
		case *ast.CallExpr:
			var fn string
			through := false
			switch f := x.Fun.(type) {
			case *ast.Ident:
				fn = f.Name
				through = passThrough[fn]
			case *ast.SelectorExpr:
				fn = f.Sel.Name
				if id, ok := f.X.(*ast.Ident); ok && passThroughPkg[id.Name] {
					through = true
				}
			case *ast.ArrayType:
				through = true // []string(x)
			}
			if w := s.funcs[fn]; w != "" {
				found = w
				return false
			}
			ast.Inspect(x.Fun, walk) // the receiver chain: c.Requester.ID.String()
			if through {
				for _, a := range x.Args {
					ast.Inspect(a, walk)
				}
			}
			return false
		}
		return found == ""
	}
	ast.Inspect(e, walk)
	return found
}

// learn adds the locals a function body assigns from tainted expressions, to a fixpoint.
func (s taintScope) learn(body ast.Node) {
	for changed := true; changed; {
		changed = false
		ast.Inspect(body, func(n ast.Node) bool {
			if _, nested := n.(*ast.FuncLit); nested && n != body {
				return false // a nested literal is its own scope (see checkI2File)
			}
			add := func(lhs ast.Expr, rhs ast.Expr) {
				id, ok := lhs.(*ast.Ident)
				if !ok || id.Name == "_" || id.Name == "err" || s.locals[id.Name] != "" {
					return
				}
				if w := s.name(rhs); w != "" {
					s.locals[id.Name] = w
					changed = true
				}
			}
			switch x := n.(type) {
			case *ast.AssignStmt:
				for i, l := range x.Lhs {
					switch {
					case len(x.Lhs) == len(x.Rhs):
						add(l, x.Rhs[i])
					case len(x.Rhs) == 1:
						add(l, x.Rhs[0])
					}
				}
			case *ast.ValueSpec:
				for i, id := range x.Names {
					if len(x.Values) == len(x.Names) {
						add(id, x.Values[i])
					} else if len(x.Values) == 1 {
						add(id, x.Values[0])
					}
				}
			case *ast.RangeStmt:
				if x.Value != nil {
					add(x.Value, x.X)
				}
			}
			return true
		})
	}
}

// taintedFuncs finds, across all files, the functions that return an initiator identity (directly, through
// a tainted local, or through another such function), by name.
func taintedFuncs(files []i2File) map[string]string {
	funcs := map[string]string{}
	for changed := true; changed; {
		changed = false
		for _, file := range files {
			for _, d := range file.f.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || fd.Body == nil || funcs[fd.Name.Name] != "" || !returnsStrings(fd) {
					continue
				}
				sc := taintScope{locals: map[string]string{}, funcs: funcs}
				for _, p := range fd.Type.Params.List {
					for _, n := range p.Names {
						if i2Tainted[n.Name] {
							sc.locals[n.Name] = n.Name
						}
					}
				}
				sc.learn(fd.Body)
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					r, ok := n.(*ast.ReturnStmt)
					if !ok || funcs[fd.Name.Name] != "" {
						return funcs[fd.Name.Name] == ""
					}
					for _, e := range r.Results {
						if w := sc.name(e); w != "" {
							funcs[fd.Name.Name] = w
							changed = true
						}
					}
					return true
				})
			}
		}
	}
	return funcs
}

// returnsStrings reports whether every result of fd is a string or a []string, the shapes a diff value takes.
func returnsStrings(fd *ast.FuncDecl) bool {
	if fd.Type.Results == nil {
		return false
	}
	for _, r := range fd.Type.Results.List {
		t := r.Type
		if at, ok := t.(*ast.ArrayType); ok {
			t = at.Elt
		}
		if id, ok := t.(*ast.Ident); !ok || id.Name != "string" {
			return false
		}
	}
	return true
}

func checkI2File(file i2File, funcs map[string]string) []Violation {
	var out []Violation
	report := func(pos token.Pos, name string) {
		// "// i2:exempt <reason>" on the line or the one above marks a value that is the object of a Store
		// Action (the grantee of a role), not an initiator and not written to a directory.
		ln := file.fset.Position(pos).Line
		for _, l := range []int{ln, ln - 1} {
			if l >= 1 && l <= len(file.src) && strings.Contains(file.src[l-1], "i2:exempt ") {
				return
			}
		}
		out = append(out, Violation{Check: "I2", Pos: fmt.Sprintf("%s:%d", file.rel, file.fset.Position(pos).Line),
			Msg: fmt.Sprintf("a directory attribute value is taken from %s, an initiator identity (I-2): the attribution lives in the audit chain only", name)})
	}
	changeLits := map[*ast.CompositeLit]bool{}
	ast.Inspect(file.f, func(n ast.Node) bool {
		x, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		if x.Type != nil && isChangeType(x.Type) {
			changeLits[x] = true
		}
		// the elements of []Change{{...}}, [N]Change{{...}} and map[K]Change{k: {...}} have no type of their own
		var elem ast.Expr
		switch t := x.Type.(type) {
		case *ast.ArrayType:
			elem = t.Elt
		case *ast.MapType:
			elem = t.Value
		}
		if elem != nil && isChangeType(elem) {
			for _, e := range x.Elts {
				if kv, ok := e.(*ast.KeyValueExpr); ok {
					e = kv.Value
				}
				if l, ok := e.(*ast.CompositeLit); ok && l.Type == nil {
					changeLits[l] = true
				}
			}
		}
		return true
	})
	// Field assignments (ch.After = ...) are only judged in files that name the operation package, where
	// Change lives; other types (the audit chain's) have Before and After fields too.
	usesOperation := false
	for _, im := range file.f.Imports {
		if strings.HasSuffix(strings.Trim(im.Path.Value, `"`), "/platform/operation") {
			usesOperation = true
		}
	}
	if file.f.Name.Name == "operation" {
		usesOperation = true
	}
	var visit func(root ast.Node, sc taintScope)
	visit = func(root ast.Node, sc taintScope) {
		sc.learn(root)
		ast.Inspect(root, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.FuncLit:
				if n == root {
					return true
				}
				child := taintScope{locals: map[string]string{}, funcs: sc.funcs}
				for k, v := range sc.locals {
					child.locals[k] = v
				}
				for _, p := range x.Type.Params.List {
					for _, nm := range p.Names {
						delete(child.locals, nm.Name) // a parameter shadows the outer name
						if i2Tainted[nm.Name] {
							child.locals[nm.Name] = nm.Name
						}
					}
				}
				visit(x, child)
				return false
			case *ast.CompositeLit:
				if !changeLits[x] {
					return true
				}
				for i, e := range x.Elts {
					var val ast.Expr
					switch v := e.(type) {
					case *ast.KeyValueExpr:
						if k, ok := v.Key.(*ast.Ident); !ok || (k.Name != "Before" && k.Name != "After") {
							continue
						}
						val = v.Value
					default: // positional: Attribute, Before, After, Secret
						if i != 1 && i != 2 {
							continue
						}
						val = v
					}
					if name := sc.name(val); name != "" {
						report(val.Pos(), name)
					}
				}
			case *ast.AssignStmt:
				if !usesOperation {
					return true
				}
				// ch.After = ..., ch.Before = append(ch.Before, ...)
				for i, l := range x.Lhs {
					sel, ok := l.(*ast.SelectorExpr)
					if !ok || (sel.Sel.Name != "Before" && sel.Sel.Name != "After") {
						continue
					}
					var rhs ast.Expr
					if len(x.Lhs) == len(x.Rhs) {
						rhs = x.Rhs[i]
					} else if len(x.Rhs) == 1 {
						rhs = x.Rhs[0]
					}
					if rhs == nil {
						continue
					}
					if name := sc.name(rhs); name != "" {
						report(rhs.Pos(), name)
					}
				}
			}
			return true
		})
	}
	for _, d := range file.f.Decls {
		switch fd := d.(type) {
		case *ast.FuncDecl:
			if fd.Body == nil {
				continue
			}
			sc := taintScope{locals: map[string]string{}, funcs: funcs}
			for _, p := range fd.Type.Params.List {
				for _, n := range p.Names {
					if i2Tainted[n.Name] {
						sc.locals[n.Name] = n.Name
					}
				}
			}
			visit(fd.Body, sc)
		case *ast.GenDecl: // package-level var diffs
			visit(fd, taintScope{locals: map[string]string{}, funcs: funcs})
		}
	}
	return out
}

func isChangeType(e ast.Expr) bool {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name == "Change"
	case *ast.SelectorExpr:
		return t.Sel.Name == "Change"
	case *ast.StarExpr:
		return isChangeType(t.X)
	}
	return false
}

func checkI2Proto(root string) ([]Violation, error) {
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(i2WriteProto)))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []Violation
	msg := ""
	for i, line := range strings.Split(string(b), "\n") {
		if code, _, _ := strings.Cut(line, "//"); code != "" {
			line = code
		} else {
			continue
		}
		if m := protoMessage.FindStringSubmatch(line); m != nil {
			msg = m[1]
			continue
		}
		if msg == "" || i2ProtoExempt[msg] {
			continue
		}
		if m := protoField.FindStringSubmatch(line); m != nil && i2ProtoField.MatchString(m[1]) {
			out = append(out, Violation{Check: "I2", Pos: fmt.Sprintf("%s:%d", i2WriteProto, i+1),
				Msg: fmt.Sprintf("message %s has field %q naming an initiator identity; only ActingPrincipal carries one (I-2)", msg, m[1])})
		}
	}
	return out, nil
}

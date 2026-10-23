// Command objectid is the T-0180 fitness function: authz.ObjectID is [16]byte in AD octet order
// and must be built only by ObjectIDFromOctets or ParseObjectID. guid.GUID is also [16]byte, so a
// conversion authz.ObjectID(x) compiles but can silently reorder bytes and skip a scope
// exclusion (TM-TB1-T8/T11). This check fails on any conversion to authz.ObjectID outside package
// authz (and its tests), however the type is spelled (alias, rename, dot-import, generic).
package main

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"os"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
)

const (
	authzPath = "github.com/skenzeriq/activediq/internal/platform/authz"
	typeName  = "ObjectID"
)

func main() {
	dir := "."
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}
	v, err := Check(dir, "./...")
	if err != nil {
		fmt.Fprintln(os.Stderr, "fitness-objectid:", err)
		os.Exit(2)
	}
	for _, s := range v {
		fmt.Fprintln(os.Stderr, s)
	}
	if len(v) > 0 {
		fmt.Fprintf(os.Stderr, "fitness-objectid: FAIL: %d conversion(s) to authz.ObjectID outside %s; use ObjectIDFromOctets or ParseObjectID\n", len(v), authzPath)
		os.Exit(1)
	}
	fmt.Println("fitness-objectid: ok")
}

func isObjectID(t types.Type) bool {
	n, ok := types.Unalias(t).(*types.Named)
	if !ok {
		return false
	}
	o := n.Obj()
	return o.Pkg() != nil && o.Pkg().Path() == authzPath && o.Name() == typeName
}

// Check loads the packages matching pattern under dir (tests included) and returns one
// "file:line:col: message" per offending conversion, sorted.
func Check(dir string, pattern string) ([]string, error) {
	cfg := &packages.Config{
		Dir:   dir,
		Tests: true,
		Mode:  packages.NeedName | packages.NeedFiles | packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo | packages.NeedImports | packages.NeedDeps,
	}
	pkgs, err := packages.Load(cfg, pattern)
	if err != nil {
		return nil, err
	}
	var out []string
	seen := map[string]bool{}
	for _, p := range pkgs {
		// Type errors are the build and test gates' business; scanning continues on the partial
		// type information (conversions are still typed) and the error is surfaced as a warning.
		if len(p.Errors) > 0 {
			fmt.Fprintf(os.Stderr, "fitness-objectid: warning: %s: %v\n", p.ID, p.Errors[0])
		}
		// package authz, its in-package tests and its external tests (authz_test).
		base := strings.TrimSuffix(p.PkgPath, "_test")
		if base == authzPath {
			continue
		}
		for _, f := range p.Syntax {
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || len(call.Args) != 1 {
					return true
				}
				tv, ok := p.TypesInfo.Types[call.Fun]
				if !ok || !tv.IsType() || !isObjectID(tv.Type) {
					return true
				}
				pos := p.Fset.Position(call.Pos())
				msg := fmt.Sprintf("%s:%d:%d: conversion to authz.ObjectID is forbidden", relTo(dir, pos), pos.Line, pos.Column)
				if !seen[msg] {
					seen[msg] = true
					out = append(out, msg)
				}
				return true
			})
		}
	}
	sort.Strings(out)
	return out, nil
}

func relTo(dir string, pos token.Position) string {
	d := strings.TrimSuffix(dir, "/") + "/"
	if abs, err := absPath(dir); err == nil {
		d = abs + "/"
	}
	return strings.TrimPrefix(pos.Filename, d)
}

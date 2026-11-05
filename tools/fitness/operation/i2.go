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

// CheckI2 returns the I2 violations under root.
func CheckI2(root string) ([]Violation, error) {
	var out []Violation
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
			ast.Inspect(f, func(n ast.Node) bool {
				lit, ok := n.(*ast.CompositeLit)
				if !ok || !isChangeType(lit.Type) {
					return true
				}
				for _, e := range lit.Elts {
					kv, ok := e.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					if k, ok := kv.Key.(*ast.Ident); !ok || (k.Name != "Before" && k.Name != "After") {
						continue
					}
					if name := taintedName(kv.Value); name != "" {
						out = append(out, Violation{Check: "I2", Pos: fmt.Sprintf("%s:%d", rel, fset.Position(kv.Pos()).Line),
							Msg: fmt.Sprintf("a directory attribute value is taken from %s, an initiator identity (I-2): the attribution lives in the audit chain only", name)})
					}
				}
				return true
			})
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	pv, err := checkI2Proto(root)
	if err != nil {
		return nil, err
	}
	out = append(out, pv...)
	sort.Slice(out, func(i, j int) bool { return out[i].Pos < out[j].Pos })
	return out, nil
}

func isChangeType(e ast.Expr) bool {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name == "Change"
	case *ast.SelectorExpr:
		return t.Sel.Name == "Change"
	}
	return false
}

// taintedName returns the first initiator-identity identifier or selector named inside e.
func taintedName(e ast.Expr) string {
	var found string
	ast.Inspect(e, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SelectorExpr:
			if i2Tainted[x.Sel.Name] && found == "" {
				found = x.Sel.Name
			}
		case *ast.Ident:
			if i2Tainted[x.Name] && found == "" {
				found = x.Name
			}
		}
		return found == ""
	})
	return found
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

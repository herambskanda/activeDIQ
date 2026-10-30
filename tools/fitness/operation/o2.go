package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// O2 (ADR-0005 rule 2, write surface). Syntactic, no build needed. It fails when:
//
//   - an exported function or method of internal/directory/client that issues a connector-contract
//     write RPC (a call of sendPlan or sendApply, or of Plan or Apply on a `transport`) has no
//     step.Step parameter;
//   - any function there that calls the transport's Plan or Apply directly has no step.Clearance
//     parameter (only sendPlan and sendApply may, and each takes the Clearance);
//   - the generated connector client (connectorv1.ConnectorClient, NewConnectorClient) is referenced
//     outside internal/directory/client and internal/proto (test files under internal/connector, and
//     under the connector and server composition roots internal/compose/connector and
//     internal/compose/server, may drive it: they exercise the mounted connector listener and a
//     fake connector, and ship nothing);
//   - a directory protocol library (LDAP, Microsoft Graph) is imported outside the connector root
//     internal/connector (and tier L: tools/, lab/).

const (
	clientDir    = "internal/directory/client"
	protoDir     = "internal/proto"
	connectorDir = "internal/connector"
	composeConn  = "internal/compose/connector"
	composeSrv   = "internal/compose/server"
	connectorPkg = "/internal/proto/activediq/connector/v1"
)

var protocolImports = []string{
	"github.com/go-ldap/ldap",
	"github.com/microsoftgraph/",
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity",
	"github.com/Azure/azure-sdk-for-go/sdk/azcore",
}

var generatedClientNames = map[string]bool{"ConnectorClient": true, "NewConnectorClient": true}

// CheckO2 walks every .go file under root and returns the O2 violations.
func CheckO2(root string) ([]Violation, error) {
	modPath, err := modulePath(filepath.Join(root, "go.mod"))
	if err != nil {
		return nil, err
	}
	var out []Violation
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && skipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		vs, err := o2File(path, rel, modPath)
		out = append(out, vs...)
		return err
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Pos < out[j].Pos })
	return out, err
}

func under(rel, dir string) bool { return rel == dir || strings.HasPrefix(rel, dir+"/") }

func o2File(path, rel, modPath string) ([]Violation, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, rel, src, parser.SkipObjectResolution)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", rel, err)
	}
	isTest := strings.HasSuffix(rel, "_test.go")
	var out []Violation
	add := func(pos token.Pos, msg string) {
		out = append(out, Violation{Check: "O2", Pos: fmt.Sprintf("%s:%d", rel, fset.Position(pos).Line), Msg: msg})
	}
	stepLocal, connLocal := "", ""
	for _, im := range f.Imports {
		p, _ := strconv.Unquote(im.Path.Value)
		name := ""
		if im.Name != nil {
			name = im.Name.Name
		}
		switch {
		case p == modPath+stepSuffix:
			stepLocal = orDefault(name, "step")
		case p == modPath+connectorPkg:
			connLocal = orDefault(name, "v1")
		}
		if !under(rel, connectorDir) && !under(rel, "tools") && !under(rel, "lab") {
			for _, pre := range protocolImports {
				if strings.HasPrefix(p, pre) {
					add(im.Pos(), fmt.Sprintf("directory protocol library %q is imported outside internal/connector; only the connector root talks LDAP or Graph", p))
				}
			}
		}
	}
	if connLocal != "" && connLocal != "_" && !under(rel, clientDir) && !under(rel, protoDir) && !(isTest && (under(rel, connectorDir) || under(rel, composeConn) || under(rel, composeSrv))) {
		ast.Inspect(f, func(n ast.Node) bool {
			if s, ok := n.(*ast.SelectorExpr); ok {
				if id, ok := s.X.(*ast.Ident); ok && id.Name == connLocal && generatedClientNames[s.Sel.Name] {
					add(s.Pos(), "the generated connector-contract client ("+s.Sel.Name+") is referenced outside internal/directory/client; write RPCs go through client.Write")
				}
			}
			return true
		})
	}
	if rel == clientDir+"/"+filepath.Base(rel) && !isTest {
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			viaSend, direct := writeCalls(fd.Body)
			if (viaSend || direct) && fd.Name.IsExported() && !hasParam(fd, stepLocal, "Step") {
				add(fd.Pos(), fmt.Sprintf("exported %s issues a connector-contract write RPC but has no step.Step parameter", fd.Name.Name))
			}
			if direct && !hasParam(fd, stepLocal, "Clearance") {
				add(fd.Pos(), fmt.Sprintf("%s calls the connector-contract write RPC but has no step.Clearance parameter", fd.Name.Name))
			}
		}
	}
	return out, nil
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// writeCalls reports whether body calls sendPlan/sendApply (viaSend) or the transport's Plan/Apply
// (direct).
func writeCalls(body *ast.BlockStmt) (viaSend, direct bool) {
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		s, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch s.Sel.Name {
		case "sendPlan", "sendApply":
			viaSend = true
		case "Plan", "Apply":
			switch x := s.X.(type) {
			case *ast.Ident:
				direct = direct || x.Name == "transport"
			case *ast.SelectorExpr:
				direct = direct || x.Sel.Name == "transport"
			}
		}
		return true
	})
	return
}

func hasParam(fd *ast.FuncDecl, pkg, typ string) bool {
	if pkg == "" || fd.Type.Params == nil {
		return false
	}
	for _, p := range fd.Type.Params.List {
		t := p.Type
		if st, ok := t.(*ast.StarExpr); ok {
			t = st.X
		}
		if s, ok := t.(*ast.SelectorExpr); ok {
			if id, ok := s.X.(*ast.Ident); ok && id.Name == pkg && s.Sel.Name == typ {
				return true
			}
		}
	}
	return false
}

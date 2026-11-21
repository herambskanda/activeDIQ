package scan

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/skenzeriq/activediq/tools/analyzers/policy"
)

// ADR-0002 P3, second bullet (blueprint §7.3): a package outside internal/connector must not unseal a
// directory-credential type, and must not name one. Two rules carry it:
//
//	directory-credential-type    a selector that names an exported type declared by the credential
//	                             packages (internal/connector/credential and below), except the
//	                             passable ones in policy.CredentialPassable. Holding one as a field,
//	                             variable, parameter, result or composite literal all name it.
//	directory-credential-unseal  a call of an Unseal-named function or method in a file that imports a
//	                             credential package.
//
// The credential types are read from the credential packages' source, not copied here: they are
// "the types the connector's credential port declares". While the credential package does not exist
// the set is empty and only the unseal rule and the sealed/local import rules (rules.go) bite. The
// composition roots import credential/sealed and credential/local to build a source and hand it over
// as a value, so those imports are allowed in the rules.go homes; naming a credential type or calling
// Unseal is not allowed anywhere outside internal/connector.

// scanEnv is what one Scan knows beyond the file in hand.
type scanEnv struct {
	module string
	cred   credentialTypes
}

// credentialTypes maps a credential package directory (repository-relative) to the names of its
// exported credential types.
type credentialTypes map[string]map[string]bool

// loadCredentialTypes parses the non-test files of the credential packages. A file that does not
// parse is a hard error: the rule never passes over code it could not read.
func loadCredentialTypes(root, module string) (credentialTypes, error) {
	out := credentialTypes{}
	base := filepath.Join(root, filepath.FromSlash(policy.CredentialPkg))
	if st, err := os.Stat(base); err != nil || !st.IsDir() {
		return out, nil // the port has not landed
	}
	fset := token.NewFileSet()
	err := filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".go") || policy.IsTest(p) {
			return nil
		}
		f, err := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, filepath.Dir(p))
		rel = filepath.ToSlash(rel)
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			for _, sp := range gd.Specs {
				ts := sp.(*ast.TypeSpec)
				if !ts.Name.IsExported() || contains(policy.CredentialPassable, ts.Name.Name) {
					continue
				}
				if out[rel] == nil {
					out[rel] = map[string]bool{}
				}
				out[rel][ts.Name.Name] = true
			}
		}
		return nil
	})
	return out, err
}

// importDir turns an import path of this repository into its directory; ok is false for any other.
func (g *goFile) importDir(p string) (string, bool) {
	if rest, ok := strings.CutPrefix(p, modulePrefix); ok {
		return rest, true
	}
	return policy.ModuleRel(p, g.module)
}

// isUnsealName reports a function or method name that unseals: Unseal, Unseals, UnsealCredential,
// unsealKey, and so on.
func isUnsealName(n string) bool { return strings.HasPrefix(strings.ToLower(n), "unseal") }

func (g *goFile) checkCredentials() {
	if g.isTool || policy.Match(g.dir, policy.Connector) {
		return
	}
	credPkgs := map[string]string{} // local name -> directory, for the credential packages this file imports
	for name, p := range g.imports {
		if dir, ok := g.importDir(p); ok && policy.Match(dir, policy.CredentialPkg) {
			credPkgs[name] = dir
		}
	}
	if len(credPkgs) == 0 {
		return
	}
	ast.Inspect(g.file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); ok {
			if dir, in := credPkgs[id.Name]; in && g.cred[dir][sel.Sel.Name] {
				g.add("FF-SP2", "directory-credential-type", sel.Pos(), id.Name+"."+sel.Sel.Name+": a directory-credential type is named only under internal/connector; hand the source over as a value and never hold or unseal the credential (ADR-0002 P3, blueprint §7.3)")
			}
		}
		if isUnsealName(sel.Sel.Name) {
			g.add("FF-SP2", "directory-credential-unseal", sel.Pos(), "."+sel.Sel.Name+": unsealing a directory credential happens only under internal/connector (ADR-0002 P3, blueprint §7.3)")
		}
		return true
	})
}

// P3Rules are the rule names of the static half of activation row P3: the ones rules.go tags P3, and
// the credential rules above. `safeprim -p3` keeps exactly these findings.
func P3Rules() []string {
	var out []string
	for _, r := range importRules {
		if r.P3 {
			out = append(out, r.Rule)
		}
	}
	out = append(out, "directory-credential-type", "directory-credential-unseal")
	sort.Strings(out)
	return out
}

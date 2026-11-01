package main

import (
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/semver"
)

// FIT-SSO-1 (console-sso.md §13): the SAML and JOSE libraries are reachable from one package each, so a
// verifier that parses untrusted XML or a JWS cannot grow a second, unreviewed parsing path.

const (
	samlDir = "internal/platform/authn/sso/saml"
	oidcDir = "internal/platform/authn/sso/oidc"
	// authnDir is the tree in which encoding/xml is banned outside samlDir (§3: the SAML verifier is the
	// only XML parser under platform/authn).
	authnDir = "internal/platform/authn"
)

// fence is one import rule: a package whose import path equals Path, or lies below Path+"/", may be
// imported only from Dir and its subdirectories (samltest is the SAML package's test IdP).
type fence struct {
	Path   string // import path or prefix
	Prefix bool   // Path matches as a prefix on a path-element boundary
	Dir    string // the one directory subtree allowed to import it
	Under  string // when set, the rule applies only to files under this directory
}

var fences = []fence{
	{Path: "github.com/russellhaering", Prefix: true, Dir: samlDir},
	{Path: "github.com/beevik/etree", Prefix: true, Dir: samlDir},
	{Path: "github.com/mattermost/xml-roundtrip-validator", Prefix: true, Dir: samlDir},
	{Path: "github.com/coreos/go-oidc", Prefix: true, Dir: oidcDir},
	{Path: "github.com/go-jose", Prefix: true, Dir: oidcDir},
	{Path: "encoding/xml", Prefix: true, Dir: samlDir, Under: authnDir},
}

// floors are the go.mod minimum versions (§3.1, SSO-D2): goxmldsig v1.6.0 carries the fixes for the
// signature-wrapping and canonicalisation CVEs of the 1.5 line, gosaml2 v0.12.0 is the first release built
// on it. A module that is not required at all is fine (gosaml2 is not imported by T-0202).
var floors = []struct{ Module, Min string }{
	{"github.com/russellhaering/goxmldsig", "v1.6.0"},
	{"github.com/russellhaering/gosaml2", "v0.12.0"},
}

func inDir(rel, dir string) bool { return rel == dir || strings.HasPrefix(rel, dir+"/") }

func matches(f fence, imp string) bool {
	if imp == f.Path {
		return true
	}
	return f.Prefix && strings.HasPrefix(imp, f.Path+"/")
}

// CheckImports parses the import clauses of every .go file under root (tests included: a test that
// imports the library is a second parsing path too) and returns "file:line: message", sorted.
func CheckImports(root string) ([]string, error) {
	var out []string
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			n := d.Name()
			if rel != "." && (strings.HasPrefix(n, ".") || n == "vendor" || n == "node_modules" || n == "testdata") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly|parser.SkipObjectResolution)
		if err != nil {
			return fmt.Errorf("parse %s: %w", rel, err)
		}
		for _, im := range f.Imports {
			imp := strings.Trim(im.Path.Value, "\"`")
			for _, fc := range fences {
				if !matches(fc, imp) || (fc.Under != "" && !inDir(rel, fc.Under)) || inDir(rel, fc.Dir) {
					continue
				}
				out = append(out, fmt.Sprintf("%s:%d: imports %s; only %s may (FIT-SSO-1)", rel, fset.Position(im.Pos()).Line, imp, fc.Dir))
			}
		}
		return nil
	})
	sort.Strings(out)
	return out, err
}

// CheckModule reads root/go.mod and judges the library floors. Both the require line and any replace
// directive count: a replace to an older version, or to a local path whose version cannot be read, would
// defeat the floor, so it fails too.
func CheckModule(root string) ([]string, error) {
	b, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return nil, err
	}
	mf, err := modfile.Parse("go.mod", b, nil)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, fl := range floors {
		for _, r := range mf.Require {
			if r.Mod.Path == fl.Module && semver.Compare(r.Mod.Version, fl.Min) < 0 {
				out = append(out, fmt.Sprintf("go.mod: requires %s %s; the floor is %s (FIT-SSO-1)", fl.Module, r.Mod.Version, fl.Min))
			}
		}
		for _, r := range mf.Replace {
			if r.Old.Path != fl.Module {
				continue
			}
			switch {
			case r.New.Version == "":
				out = append(out, fmt.Sprintf("go.mod: replaces %s with the path %s, whose version cannot be checked against the floor %s (FIT-SSO-1)", fl.Module, r.New.Path, fl.Min))
			case r.New.Path != fl.Module:
				out = append(out, fmt.Sprintf("go.mod: replaces %s with %s %s; use the module itself at or above %s (FIT-SSO-1)", fl.Module, r.New.Path, r.New.Version, fl.Min))
			case semver.Compare(r.New.Version, fl.Min) < 0:
				out = append(out, fmt.Sprintf("go.mod: replaces %s with %s; the floor is %s (FIT-SSO-1)", fl.Module, r.New.Version, fl.Min))
			}
		}
	}
	return out, nil
}

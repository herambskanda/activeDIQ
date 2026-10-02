package main

import (
	"fmt"
	"go/ast"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/skenzeriq/activediq/tools/fitness/internal/adr"
)

// Manifest is a deployment profile read back from the Go values in the profile package. The fitness
// job evaluates the composite literals without compiling them, so it works on a tree that does not
// build yet.
type Manifest struct {
	Name         string
	Pos          string
	Processes    []Process
	Capabilities []string
	Exceptions   []ManifestException
}

// Process is one binary and the roles linked into it.
type Process struct {
	Binary    string
	Roles     []string
	Providers []string
	Pos       string
}

// ManifestException is a declared asymmetry between profiles.
type ManifestException struct {
	What, ADR, Pos string
}

// loadManifests evaluates every top-level function or variable of the profile package that yields
// a Manifest composite literal.
func (c *Ctx) loadManifests() []Manifest {
	var out []Manifest
	for _, f := range c.Tree.Files {
		if f.Dir != c.Cfg.ProfilePackage || f.Test {
			continue
		}
		for _, d := range f.AST.Decls {
			switch x := d.(type) {
			case *ast.FuncDecl:
				if x.Body == nil || x.Type.Params.NumFields() != 0 {
					continue
				}
				for _, st := range x.Body.List {
					if rs, ok := st.(*ast.ReturnStmt); ok && len(rs.Results) == 1 {
						if cl := manifestLit(rs.Results[0]); cl != nil {
							out = append(out, c.evalManifest(f, cl))
						}
					}
				}
			case *ast.GenDecl:
				for _, sp := range x.Specs {
					if vs, ok := sp.(*ast.ValueSpec); ok {
						for _, v := range vs.Values {
							if cl := manifestLit(v); cl != nil {
								out = append(out, c.evalManifest(f, cl))
							}
						}
					}
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func manifestLit(e ast.Expr) *ast.CompositeLit {
	if u, ok := e.(*ast.UnaryExpr); ok {
		e = u.X
	}
	cl, ok := e.(*ast.CompositeLit)
	if !ok {
		return nil
	}
	if id, ok := cl.Type.(*ast.Ident); ok && id.Name == "Manifest" {
		return cl
	}
	return nil
}

func kv(cl *ast.CompositeLit) map[string]ast.Expr {
	m := map[string]ast.Expr{}
	for _, el := range cl.Elts {
		if p, ok := el.(*ast.KeyValueExpr); ok {
			if k, ok := p.Key.(*ast.Ident); ok {
				m[k.Name] = p.Value
			}
		}
	}
	return m
}

func elems(e ast.Expr) []ast.Expr {
	if cl, ok := e.(*ast.CompositeLit); ok {
		return cl.Elts
	}
	return nil
}

func (c *Ctx) strList(f *File, e ast.Expr) []string {
	var out []string
	for _, el := range elems(e) {
		if s, _, ok := c.Tree.EvalString(f, el); ok {
			out = append(out, s)
		} else {
			out = append(out, "<unresolved:"+exprText(el)+">")
		}
	}
	return out
}

func exprText(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return exprText(x.X) + "." + x.Sel.Name
	}
	return fmt.Sprintf("%T", e)
}

func (c *Ctx) evalManifest(f *File, cl *ast.CompositeLit) Manifest {
	fields := kv(cl)
	m := Manifest{Pos: f.Pos(cl.Pos())}
	if e, ok := fields["Name"]; ok {
		m.Name, _, _ = c.Tree.EvalString(f, e)
	}
	for _, pe := range elems(fields["Processes"]) {
		pcl, ok := pe.(*ast.CompositeLit)
		if !ok {
			continue
		}
		pf := kv(pcl)
		p := Process{Pos: f.Pos(pcl.Pos())}
		if e, ok := pf["Binary"]; ok {
			p.Binary, _, _ = c.Tree.EvalString(f, e)
		}
		p.Roles = c.strList(f, pf["Roles"])
		p.Providers = c.strList(f, pf["Providers"])
		m.Processes = append(m.Processes, p)
	}
	m.Capabilities = c.strList(f, fields["Capabilities"])
	for _, ee := range elems(fields["Exceptions"]) {
		ecl, ok := ee.(*ast.CompositeLit)
		if !ok {
			continue
		}
		ef := kv(ecl)
		x := ManifestException{Pos: f.Pos(ecl.Pos())}
		if e, ok := ef["What"]; ok {
			x.What, _, _ = c.Tree.EvalString(f, e)
		}
		if e, ok := ef["ADR"]; ok {
			x.ADR, _, _ = c.Tree.EvalString(f, e)
		}
		m.Exceptions = append(m.Exceptions, x)
	}
	return m
}

var adrNumber = regexp.MustCompile(`\d{4}`)

// adrGrants resolves a citation ("0002-deployment-model.md", "ADR-0002", "0002") to an ADR file in
// the decisions directory and reports whether that ADR is ratified or accepted. why explains a no.
func (c *Ctx) adrGrants(cite string) (ok bool, why string) {
	cite = strings.TrimSpace(cite)
	if cite == "" {
		return false, "it cites no ADR"
	}
	dir := filepath.Join(c.Root, filepath.FromSlash(c.Cfg.DecisionsDir))
	var file string
	if strings.HasSuffix(cite, ".md") && cite == filepath.Base(cite) {
		file = filepath.Join(dir, cite)
	} else if n := adrNumber.FindString(cite); n != "" {
		ms, _ := filepath.Glob(filepath.Join(dir, n+"-*.md"))
		if len(ms) == 1 {
			file = ms[0]
		}
	}
	if file == "" {
		return false, fmt.Sprintf("%q is not an ADR in %s", cite, c.Cfg.DecisionsDir)
	}
	st, err := adr.Status(file)
	switch {
	case os.IsNotExist(err):
		return false, fmt.Sprintf("%s does not exist in %s", filepath.Base(file), c.Cfg.DecisionsDir)
	case err != nil:
		return false, fmt.Sprintf("%s cannot be read: %v", filepath.Base(file), err)
	case !adr.Grants(st):
		return false, fmt.Sprintf("%s has status %q; only a ratified or accepted ADR grants an exception", filepath.Base(file), st)
	}
	return true, ""
}

func has(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// checkP1Manifests reads the profile manifests and enforces the planes, the Entra-only SaaS cell,
// and capability symmetry of the two self-hosted profiles.
func (c *Ctx) checkP1Manifests() []Violation {
	var vs []Violation
	add := func(pos, msg string) { vs = append(vs, Violation{"P1", pos, msg}) }
	ms := c.loadManifests()
	byName := map[string]Manifest{}
	for _, m := range ms {
		byName[m.Name] = m
	}
	for _, want := range c.Cfg.Manifests {
		if _, ok := byName[want]; !ok {
			add(c.Cfg.ProfilePackage, fmt.Sprintf("manifest %q not found: the profile package must hold a Manifest literal named %q for every profile in the manifest (windows, linux-oci, saas); a profile cannot lose its manifest", want, want))
		}
	}
	for _, m := range ms {
		for _, p := range m.Processes {
			if len(p.Roles) > 1 {
				for _, iso := range c.Cfg.IsolatedRoles {
					if has(p.Roles, iso) {
						add(p.Pos, fmt.Sprintf("manifest %q composes role %q with %v in process %q; %s runs alone in its process (ADR-0002 rule 2, planes)", m.Name, iso, others(p.Roles, iso), p.Binary, iso))
					}
				}
			}
			if m.Name == c.Cfg.SaaSProfile {
				if has(p.Roles, "t0-connector") {
					add(p.Pos, fmt.Sprintf("manifest %q places role t0-connector in the SaaS cell; Tier-0 reach stays on the customer site (ADR-0002 rule 2)", m.Name))
				}
				if has(p.Providers, c.Cfg.ADProvider) {
					add(p.Pos, fmt.Sprintf("manifest %q: process %q carries the %q directory provider in the SaaS cell; the cell holds Entra only and reaches AD through a customer-site connector (ADR-0002 rule 3)", m.Name, p.Binary, c.Cfg.ADProvider))
				}
			}
		}
		if m.Name == c.Cfg.SaaSProfile && c.Cfg.ADCapability != "" && has(m.Capabilities, c.Cfg.ADCapability) {
			add(m.Pos, fmt.Sprintf("manifest %q enables capability %q; the SaaS cell holds no AD credential (ADR-0002 rule 3)", m.Name, c.Cfg.ADCapability))
		}
		for _, cp := range m.Capabilities {
			if tok := c.profileNamed(cp); tok != "" {
				add(m.Pos, fmt.Sprintf("manifest %q lists capability %q, which is named after a profile (%q)", m.Name, cp, tok))
			}
			if strings.HasPrefix(cp, "<unresolved:") {
				add(m.Pos, fmt.Sprintf("manifest %q lists a capability the job cannot resolve to a constant: %s", m.Name, cp))
			}
		}
		for _, x := range m.Exceptions {
			if ok, why := c.adrGrants(x.ADR); !ok {
				add(x.Pos, fmt.Sprintf("manifest %q exception %q is not valid: %s", m.Name, x.What, why))
			}
		}
	}
	vs = append(vs, c.checkSymmetry(byName)...)
	return vs
}

func others(roles []string, not string) []string {
	var o []string
	for _, r := range roles {
		if r != not {
			o = append(o, r)
		}
	}
	return o
}

// checkSymmetry fails when the self-hosted manifests differ in a capability that no exception
// citing a ratified ADR covers (ADR-0002 rule 1: profiles differ in adapters, never capabilities).
func (c *Ctx) checkSymmetry(byName map[string]Manifest) []Violation {
	if len(c.Cfg.SelfHosted) < 2 {
		return nil
	}
	var ms []Manifest
	for _, n := range c.Cfg.SelfHosted {
		m, ok := byName[n]
		if !ok {
			return nil // reported as a missing manifest
		}
		ms = append(ms, m)
	}
	var vs []Violation
	base := ms[0]
	for _, other := range ms[1:] {
		for _, pair := range [][2]Manifest{{base, other}, {other, base}} {
			for _, cp := range pair[0].Capabilities {
				if has(pair[1].Capabilities, cp) {
					continue
				}
				if c.excepted(cp, base, other) {
					continue
				}
				vs = append(vs, Violation{"P1", pair[0].Pos, fmt.Sprintf("self-hosted manifests differ in capability %q: %q has it, %q does not, and no exception (What: %q) citing a ratified ADR covers it; profiles differ in adapters, never in capabilities (ADR-0002 rule 1)", cp, pair[0].Name, pair[1].Name, cp)})
			}
		}
	}
	return vs
}

func (c *Ctx) excepted(capID string, ms ...Manifest) bool {
	for _, m := range ms {
		for _, x := range m.Exceptions {
			if x.What == capID {
				if ok, _ := c.adrGrants(x.ADR); ok {
					return true
				}
			}
		}
	}
	return false
}

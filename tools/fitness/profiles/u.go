package main

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// goModFile is what U1 needs from a go.mod or go.work: required modules and replacements.
type goModFile struct {
	rel      string
	requires []modLine
	replaces []replLine
	uses     []modLine // go.work "use" directories
}

type modLine struct {
	path string
	line int
}

type replLine struct {
	old, target string
	line        int
}

// parseGoMod reads the directives U1 cares about. It handles block form and comments; anything it
// does not recognise is ignored (go mod tidy and go vet reject a malformed file in the same run).
func parseGoMod(root, rel string) (*goModFile, error) {
	fh, err := os.Open(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	g := &goModFile{rel: rel}
	sc := bufio.NewScanner(fh)
	block, n := "", 0
	for sc.Scan() {
		n++
		line := sc.Text()
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if block != "" {
			if fields[0] == ")" {
				block = ""
				continue
			}
			g.directive(block, fields, n)
			continue
		}
		if len(fields) >= 2 && fields[len(fields)-1] == "(" {
			block = fields[0]
			continue
		}
		g.directive(fields[0], fields[1:], n)
	}
	return g, sc.Err()
}

func unq(s string) string { return strings.Trim(s, "\"`") }

func (g *goModFile) directive(kind string, f []string, line int) {
	switch kind {
	case "require":
		if len(f) >= 1 {
			g.requires = append(g.requires, modLine{unq(f[0]), line})
		}
	case "use":
		if len(f) >= 1 {
			g.uses = append(g.uses, modLine{unq(f[0]), line})
		}
	case "replace":
		for i, tok := range f {
			if tok == "=>" && i+1 < len(f) && i >= 1 {
				g.replaces = append(g.replaces, replLine{old: unq(f[0]), target: unq(f[i+1]), line: line})
			}
		}
	}
}

// listGoMods finds every go.mod and go.work outside the skipped directories (a go.mod in third_party
// or an unlisted nested module is found too).
func listGoMods(root string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != root && skipDir(d.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		if d.Name() == "go.mod" || d.Name() == "go.work" {
			rel, _ := filepath.Rel(root, p)
			out = append(out, filepath.ToSlash(rel))
		}
		return nil
	})
	return out, err
}

// outsideRepo reports whether a replace target or use directory, written in the go.mod at rel,
// lies outside the repository. A target that is not a filesystem path (a module path) lies outside.
func outsideRepo(rel, target string) bool {
	isPath := strings.HasPrefix(target, "./") || strings.HasPrefix(target, "../") || target == "." || target == ".." || filepath.IsAbs(target)
	if !isPath {
		return true
	}
	if filepath.IsAbs(target) {
		return true
	}
	joined := path.Clean(path.Join(path.Dir(rel), target))
	return joined == ".." || strings.HasPrefix(joined, "../")
}

func isDenied(modPath, prefix string) bool {
	prefix = strings.TrimSuffix(prefix, "/")
	return modPath == prefix || strings.HasPrefix(modPath, prefix+"/")
}

// checkU1 is UEM independence: no go.mod requires, no source imports and no replace points at a
// UEM/PatchIQ module, and no replace or workspace use reaches outside the repository. The deep half
// (go list -deps of every binary against the same denylist) is fitness-stack F3, which reads the
// denylist file through its denylistExtends.
func (c *Ctx) checkU1() ([]Violation, error) {
	var vs []Violation
	add := func(pos, msg string) { vs = append(vs, Violation{"U1", pos, msg}) }
	deny, err := loadUEMDeny(c.Root, c.Cfg.UEMDenylist)
	if err != nil {
		return nil, err
	}
	if !c.stackExtends() {
		add(c.Cfg.StackManifest, fmt.Sprintf("the stack manifest's denylistExtends does not list %s, so fitness-stack F3 does not check the shipped binaries' dependency closure against the UEM/PatchIQ denylist", c.Cfg.UEMDenylist))
	}
	mods, err := listGoMods(c.Root)
	if err != nil {
		return nil, err
	}
	for _, rel := range mods {
		g, err := parseGoMod(c.Root, rel)
		if err != nil {
			return nil, err
		}
		for _, r := range g.requires {
			for _, d := range deny.Denylist {
				if isDenied(r.path, d.Prefix) {
					add(fmt.Sprintf("%s:%d", rel, r.line), fmt.Sprintf("requires %s, on the UEM/PatchIQ denylist: %s", r.path, d.Reason))
				}
			}
		}
		for _, r := range g.replaces {
			for _, d := range deny.Denylist {
				if isDenied(r.old, d.Prefix) || isDenied(r.target, d.Prefix) {
					add(fmt.Sprintf("%s:%d", rel, r.line), fmt.Sprintf("replace %s => %s names a UEM/PatchIQ module: %s", r.old, r.target, d.Reason))
				}
			}
			if outsideRepo(rel, r.target) && !c.replaceExcepted(rel, r) {
				add(fmt.Sprintf("%s:%d", rel, r.line), fmt.Sprintf("replace %s => %s points outside the repository; the build must be reproducible from a fresh clone (ADR-0002 U1). A vendored copy belongs in third_party/ with its licence and a ratified ADR", r.old, r.target))
			}
		}
		for _, u := range g.uses {
			if outsideRepo(rel, u.path) {
				add(fmt.Sprintf("%s:%d", rel, u.line), fmt.Sprintf("use %s points outside the repository (ADR-0002 U1)", u.path))
			}
		}
	}
	for _, f := range c.Tree.Files {
		for _, is := range f.AST.Imports {
			ip := unq(is.Path.Value)
			for _, d := range deny.Denylist {
				if isDenied(ip, d.Prefix) {
					add(f.Pos(is.Pos()), fmt.Sprintf("imports %s, on the UEM/PatchIQ denylist: %s", ip, d.Reason))
				}
			}
		}
	}
	for i, e := range c.Cfg.ReplaceExcepts {
		if ok, why := c.adrGrants(e.ADR); !ok {
			add(fmt.Sprintf("manifest replaceExceptions[%d] (%s)", i, e.Path), why)
		}
	}
	return vs, nil
}

func (c *Ctx) replaceExcepted(rel string, r replLine) bool {
	for _, e := range c.Cfg.ReplaceExcepts {
		if e.Path == rel+":"+r.old {
			ok, _ := c.adrGrants(e.ADR)
			return ok
		}
	}
	return false
}

// stackExtends reports whether the stack manifest lists the UEM denylist file in denylistExtends.
func (c *Ctx) stackExtends() bool {
	b, err := os.ReadFile(filepath.Join(c.Root, filepath.FromSlash(c.Cfg.StackManifest)))
	if err != nil {
		return false
	}
	var m struct {
		Extends []string `json:"denylistExtends"`
	}
	d := jsonLoose(b, &m)
	if d != nil {
		return false
	}
	return has(m.Extends, c.Cfg.UEMDenylist)
}

// checkU2 is the extractable platform root: no package under it imports a directory-domain,
// connector, module or composition package (or the generated activediq protos).
func (c *Ctx) checkU2() []Violation {
	var vs []Violation
	for _, f := range c.Tree.Files {
		if !under(f.Dir, c.Cfg.PlatformRoot) {
			continue
		}
		for _, is := range f.AST.Imports {
			dir := c.Tree.Local(unq(is.Path.Value))
			if dir == "" {
				continue
			}
			for _, banned := range c.Cfg.PlatformForbidden {
				if under(dir, banned) {
					vs = append(vs, Violation{"U2", f.Pos(is.Pos()), fmt.Sprintf("platform package %s imports %s; the platform root must stay extractable and imports no directory-domain, connector, module or composition package (ADR-0002 U2)", f.Dir, dir)})
					break
				}
			}
		}
	}
	return vs
}

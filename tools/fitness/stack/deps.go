package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path"
	"sort"
	"strings"
)

// depCache holds `go list -deps` results, run once per binary and target and shared by F3 (the
// denylist) and F4 (the transitive licence scan).
type depCache struct {
	done    bool
	imports map[string]map[string]string // binary name -> import path -> first target that links it
	modules map[string]moduleInfo        // module path -> where it lives on disk
	errs    []Violation
}

type moduleInfo struct {
	Dir     string
	Version string
	gomod   string // go.mod of the binary's module that pulled it in
}

func (c *Ctx) listDeps() *depCache {
	if c.deps != nil {
		return c.deps
	}
	d := &depCache{imports: map[string]map[string]string{}, modules: map[string]moduleInfo{}}
	c.deps = d
	for _, b := range c.M.Binaries {
		dir := b.Module
		if dir == "" {
			dir = "."
		}
		gomod := path.Join(dir, "go.mod")
		d.imports[b.Name] = map[string]string{}
		for _, t := range c.M.BuildMatrix {
			goos, goarch, _ := strings.Cut(t, "/")
			cmd := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}\t{{with .Module}}{{.Path}}\t{{.Version}}\t{{.Dir}}{{end}}", b.Package)
			cmd.Dir = c.abs(dir)
			cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS="+goos, "GOARCH="+goarch)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			out, err := cmd.Output()
			if err != nil {
				d.errs = append(d.errs, Violation{"F3", gomod, fmt.Sprintf("binary %q (%s): go list -deps failed for %s: %s", b.Name, b.Package, t, trimOutput(stderr.Bytes()))})
				break
			}
			for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
				f := strings.Split(line, "\t")
				if len(f) == 0 || f[0] == "" {
					continue
				}
				if _, seen := d.imports[b.Name][f[0]]; !seen {
					d.imports[b.Name][f[0]] = t
				}
				if len(f) >= 4 && f[1] != "" {
					if _, seen := d.modules[f[1]]; !seen {
						d.modules[f[1]] = moduleInfo{Dir: f[3], Version: f[2], gomod: gomod}
					}
				}
			}
		}
	}
	return d
}

// checkDeps is F3 (ADR-0001 rule 3): no shipped binary links a denylisted package, and every
// cmd/ binary is declared so none escapes the check.
func (c *Ctx) checkDeps() []Violation {
	var vs []Violation
	declared := map[string]bool{}
	for _, b := range c.M.Binaries {
		declared[path.Clean(path.Join(orDot(b.Module), b.Package))] = true
	}
	for _, f := range c.Files {
		if !strings.HasPrefix(f, "cmd/") || !strings.HasSuffix(f, ".go") || strings.HasSuffix(f, "_test.go") {
			continue
		}
		if !c.isMainFile(f) {
			continue
		}
		if dir := path.Dir(f); !declared[dir] {
			vs = append(vs, Violation{"F3", f, fmt.Sprintf("package main in %s is not declared in manifest binaries, so its dependencies are not checked against the denylist", dir)})
		}
	}
	d := c.listDeps()
	vs = append(vs, d.errs...)
	names := make([]string, 0, len(c.M.Binaries))
	for _, b := range c.M.Binaries {
		names = append(names, b.Name)
	}
	sort.Strings(names)
	byName := map[string]Binary{}
	for _, b := range c.M.Binaries {
		byName[b.Name] = b
	}
	for _, name := range names {
		b := byName[name]
		for imp, target := range d.imports[name] {
			for _, e := range c.M.Denylist {
				if imp == e.Prefix || strings.HasPrefix(imp, strings.TrimSuffix(e.Prefix, "/")+"/") {
					vs = append(vs, Violation{"F3", path.Join(orDot(b.Module), b.Package), fmt.Sprintf("binary %q (tier %s) links %s, denylisted: %s (first seen building %s). A second stateful service or alternative datastore needs its own ADR", b.Name, b.Tier, imp, e.Reason, target)})
					break
				}
			}
		}
	}
	return vs
}

func orDot(s string) string {
	if s == "" {
		return "."
	}
	return s
}

func (c *Ctx) isMainFile(f string) bool {
	b, err := c.read(f)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "package ") {
			return strings.Fields(line)[1] == "main"
		}
	}
	return false
}

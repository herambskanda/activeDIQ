package scan

import (
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/tools/go/packages"
)

// enteredDirs finds the directories below the root-level skipped ones (rootSkipped) that shipped
// code reaches, as repository-relative slash paths (T-0082). A reached directory is scanned whole,
// every file in its subtree whatever the build tags, so no GOOS-specific file, embedded SQL or
// ignored file escapes. Two independent sources are unioned so neither one's blind spot hides code:
//
//  1. a syntactic pass: the import blocks of every Go file, build constraints ignored, resolved
//     against the module path and followed transitively through the directories it reaches;
//  2. package loads for the shipped platforms (linux and windows), which also see nested modules
//     brought in with `replace x => ./third_party/x` and vendored packages.
//
// It fails closed: a package load that errors makes the scan error rather than skip everything.
func enteredDirs(root, module string) (map[string]bool, error) {
	entered := map[string]bool{}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		return entered, nil
	}
	if err := syntacticImports(root, module, entered); err != nil {
		return nil, err
	}
	for _, goos := range []string{"linux", "windows"} {
		if err := loadedDirs(root, goos, entered); err != nil {
			return nil, err
		}
	}
	return entered, nil
}

// syntacticImports adds the root-skipped directories that module-internal imports name, starting
// from every Go file outside them and following the files inside the directories it enters.
func syntacticImports(root, module string, entered map[string]bool) error {
	if module == "" {
		return nil
	}
	scanned := map[string]bool{} // files already parsed
	for {
		before := len(entered)
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, rerr := filepath.Rel(root, p)
			if rerr != nil {
				return rerr
			}
			rel = filepath.ToSlash(rel)
			if d.IsDir() {
				if rel != "." && skipDirUnless(root, rel, d.Name(), entered) {
					return fs.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(rel, ".go") || scanned[rel] {
				return nil
			}
			if inRootSkipped(rel) && !underEntered(rel, entered) {
				return nil
			}
			scanned[rel] = true
			f, perr := parser.ParseFile(token.NewFileSet(), p, nil, parser.ImportsOnly)
			if perr != nil || f == nil {
				return nil // scanGo reports a file that does not parse
			}
			for _, imp := range f.Imports {
				path, uerr := strconv.Unquote(imp.Path.Value)
				if uerr != nil {
					continue
				}
				if rest, ok := strings.CutPrefix(path, module+"/"); ok {
					if top, _, _ := strings.Cut(rest, "/"); rootSkipped[top] {
						entered[rest] = true
					}
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
		if len(entered) == before {
			return nil
		}
	}
}

// loadedDirs adds the root-skipped package directories that a package load for goos reaches from
// product packages (those outside the skipped roots).
func loadedDirs(root, goos string, entered map[string]bool) error {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles | packages.NeedImports |
			packages.NeedDeps | packages.NeedEmbedFiles,
		Dir:   absRoot,
		Tests: true,
		Env:   append(os.Environ(), "GOOS="+goos, "GOARCH=amd64", "CGO_ENABLED=0"),
	}
	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		return fmt.Errorf("safeprim scan: loading packages for GOOS=%s: %w", goos, err)
	}
	rel := func(f string) (string, bool) {
		r, err := filepath.Rel(absRoot, f)
		if err != nil || strings.HasPrefix(r, "..") {
			return "", false
		}
		return filepath.ToSlash(r), true
	}
	var product []*packages.Package
	for _, p := range pkgs {
		if files := pkgFiles(p); len(files) > 0 {
			if r, ok := rel(files[0]); ok && !inRootSkipped(r) {
				product = append(product, p)
			}
		}
	}
	packages.Visit(product, nil, func(p *packages.Package) {
		for _, f := range pkgFiles(p) {
			if r, ok := rel(f); ok && inRootSkipped(r) {
				entered[filepath.ToSlash(filepath.Dir(r))] = true
			}
		}
	})
	return nil
}

// pkgFiles is every file a package has, compiled for this platform or not.
func pkgFiles(p *packages.Package) []string {
	var out []string
	for _, l := range [][]string{p.GoFiles, p.CompiledGoFiles, p.IgnoredFiles, p.OtherFiles, p.EmbedFiles} {
		out = append(out, l...)
	}
	return out
}

// overlapsEntered: rel is an entered directory, holds one, or lies inside one.
func overlapsEntered(rel string, entered map[string]bool) bool {
	for d := range entered {
		if d == rel || strings.HasPrefix(d, rel+"/") || strings.HasPrefix(rel, d+"/") {
			return true
		}
	}
	return false
}

// underEntered: rel is a file inside an entered directory.
func underEntered(rel string, entered map[string]bool) bool {
	for d := range entered {
		if strings.HasPrefix(rel, d+"/") {
			return true
		}
	}
	return false
}

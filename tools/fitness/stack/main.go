// Command stack is the fitness-stack job of ADR-0001 (checks F1–F5), run by `make ci`. It fails the
// build when the technology stack decision is broken: a language in the wrong zone (F1), cgo or
// platform-specific Go outside an adapter or a failing cross-build (F2), a second stateful service
// in a shipped binary (F3), a dependency missing from the licence register or strong copyleft in a
// shipped closure (F4), or an exception that does not cite a ratified ADR (F5).
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

const defaultManifest = "tools/fitness/stack/manifest.json"

func main() {
	root := flag.String("root", ".", "repository root (the directory holding go.mod)")
	manifest := flag.String("manifest", defaultManifest, "manifest path, relative to -root")
	checks := flag.String("checks", "F1,F2,F3,F4,F5", "comma-separated checks to run")
	skipBuild := flag.Bool("skip-build", false, "skip the F2 cross-build matrix (the source scans still run)")
	flag.BoolVar(&verbose, "v", false, "print each passing cross-build target")
	flag.Parse()

	vs, err := Run(*root, *manifest, strings.Split(*checks, ","), *skipBuild)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fitness-stack:", err)
		os.Exit(2)
	}
	if len(vs) == 0 {
		fmt.Println("fitness-stack: ok (" + *checks + ")")
		return
	}
	for _, v := range vs {
		fmt.Fprintln(os.Stderr, v)
	}
	fmt.Fprintf(os.Stderr, "fitness-stack: %d violation(s); rules: knowledge/development/decisions/0001-technology-stack.md\n", len(vs))
	os.Exit(1)
}

// Run executes the selected checks against the tree at root.
func Run(root, manifestPath string, checks []string, skipBuild bool) ([]Violation, error) {
	m, err := LoadManifest(root, manifestPath)
	if err != nil {
		return nil, err
	}
	files, err := listFiles(root, m.ExemptZones)
	if err != nil {
		return nil, err
	}
	c := &Ctx{Root: root, M: m, ManifestPath: manifestPath, Files: files, SkipBuild: skipBuild}
	want := map[string]bool{}
	for _, k := range checks {
		k = strings.ToUpper(strings.TrimSpace(k))
		if _, ok := checkRule[k]; !ok {
			return nil, fmt.Errorf("unknown check %q (want F1..F5)", k)
		}
		want[k] = true
	}
	var vs []Violation
	if want["F1"] {
		vs = append(vs, c.checkZones()...)
	}
	if want["F5"] {
		vs = append(vs, c.checkExceptions()...)
	}
	if want["F2"] {
		vs = append(vs, c.checkGoSource()...)
		if !skipBuild {
			vs = append(vs, c.checkCrossBuild()...)
		}
	}
	if want["F3"] {
		vs = append(vs, c.checkDeps()...)
	}
	if want["F4"] {
		vs = append(vs, c.checkLicences()...)
	}
	sortViolations(vs)
	return vs, nil
}

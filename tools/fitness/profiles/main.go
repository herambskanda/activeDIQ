// Command profiles is the fitness-profiles job of ADR-0002 (checks P1, P7, U1, U2 and the
// activation table for P2–P6, U3 and U4), run by `make ci`. It fails the build when a deployment
// profile or the UEM boundary is broken: domain code that imports the compose package, reads a
// profile-selecting environment variable, names a profile or declares a profile-named capability;
// self-hosted manifests that differ in a capability; a Tier-0 role composed beside another role;
// a branch other than main and factory/T-NNNN; a UEM/PatchIQ module in a go.mod or an import, or a
// replace outside the repository; a platform package that imports directory-domain code; or a
// subject (installer, connector, updater, agent protos) that has landed without its check.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

const defaultManifest = "tools/fitness/profiles/manifest.json"

// Ctx is what every check shares.
type Ctx struct {
	Root string
	Cfg  *Config
	Tree *Tree
}

// Options tune a run; the zero value is what `make ci` uses.
type Options struct {
	Branches []string // when non-nil, P7 checks these instead of asking git
}

func main() {
	root := flag.String("root", ".", "repository root (the directory holding go.mod)")
	manifest := flag.String("manifest", defaultManifest, "manifest path, relative to -root")
	checks := flag.String("checks", "P1,P7,U1,U2,ACT", "comma-separated checks to run (ACT is the activation table)")
	flag.Parse()

	vs, rows, err := Run(*root, *manifest, strings.Split(*checks, ","), Options{})
	if err != nil {
		fmt.Fprintln(os.Stderr, "fitness-profiles:", err)
		os.Exit(2)
	}
	if rows != nil {
		PrintTable(os.Stdout, rows)
	}
	if len(vs) == 0 {
		fmt.Println("fitness-profiles: ok (" + *checks + ")")
		return
	}
	for _, v := range vs {
		fmt.Fprintln(os.Stderr, v)
	}
	fmt.Fprintf(os.Stderr, "fitness-profiles: %d violation(s); rules: knowledge/development/decisions/0002-deployment-model.md (Fitness function)\n", len(vs))
	os.Exit(1)
}

var known = map[string]bool{"P1": true, "P7": true, "U1": true, "U2": true, "ACT": true}

// Run executes the selected checks against the tree at root. rows is the evaluated activation
// table when ACT ran.
func Run(root, manifestPath string, checks []string, opt Options) ([]Violation, []Row, error) {
	cfg, err := LoadConfig(root, manifestPath)
	if err != nil {
		return nil, nil, err
	}
	want := map[string]bool{}
	for _, k := range checks {
		k = strings.ToUpper(strings.TrimSpace(k))
		if !known[k] {
			return nil, nil, fmt.Errorf("unknown check %q (want P1, P7, U1, U2 or ACT)", k)
		}
		want[k] = true
	}
	tree, err := LoadTree(root)
	if err != nil {
		return nil, nil, err
	}
	c := &Ctx{Root: root, Cfg: cfg, Tree: tree}
	var vs []Violation
	var rows []Row
	if want["P1"] {
		vs = append(vs, c.checkP1Domain()...)
		vs = append(vs, c.checkP1Manifests()...)
	}
	if want["P7"] {
		branches := opt.Branches
		if branches == nil {
			if branches, err = Branches(root); err != nil {
				return nil, nil, fmt.Errorf("P7 needs a git checkout: %w", err)
			}
		}
		vs = append(vs, c.checkP7(branches)...)
	}
	if want["U1"] {
		u1, err := c.checkU1()
		if err != nil {
			return nil, nil, err
		}
		vs = append(vs, u1...)
	}
	if want["U2"] {
		vs = append(vs, c.checkU2()...)
	}
	if want["ACT"] {
		var av []Violation
		rows, av = c.checkActivation()
		vs = append(vs, av...)
	}
	sortViolations(vs)
	return vs, rows, nil
}

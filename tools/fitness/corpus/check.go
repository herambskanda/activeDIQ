// Command corpus is the safe-primitives dynamic fitness job of T-0034: FF-SP4 (the corpus gate),
// FF-SP5 (the corpus-seeded fuzz targets exist and, nightly, run for at least ten minutes each) and
// FF-SP8 (constant argv). `make fitness-corpus` runs it inside `make ci`; `make fitness-nightly`
// runs the long fuzz. The oracles of FF-SP6 are tools/fitness/oracles. Reference:
// knowledge/development/architecture/safe-primitives.md §8 and
// knowledge/development/runbooks/safe-primitives-fitness.md.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/skenzeriq/activediq/internal/platform/corpus"
	"github.com/skenzeriq/activediq/tools/analyzers/policy"
)

// Finding is one violated rule at one place.
type Finding struct {
	Check string // FF-SP4, FF-SP5 or FF-SP8
	Rule  string
	Where string
	Msg   string
}

func (f Finding) String() string {
	return fmt.Sprintf("%s: %s [%s]: %s", f.Where, f.Check, f.Rule, f.Msg)
}

// Runner executes one command in dir with extra environment and returns its combined output.
type Runner func(dir string, env []string, argv []string) (string, error)

// Options configures a gate run.
type Options struct {
	Root   string          // repository root
	Checks map[string]bool // FF-SP4, FF-SP5, FF-SP8
	Run    Runner          // nil: do not execute implementations; reports must already be in ReportDir
	// ReportDir is where the implementation tests write their reports. Empty: a fresh temp dir.
	ReportDir string
}

// corpusDir is the corpus directory of a repository root.
func corpusDir(root string) string { return filepath.Join(root, filepath.FromSlash(corpus.Dir)) }

func rel(root, p string) string {
	if r, err := filepath.Rel(root, p); err == nil {
		return filepath.ToSlash(r)
	}
	return p
}

// Check runs the selected checks over the repository and returns every finding, sorted.
func Check(o Options) ([]Finding, error) {
	dir := corpusDir(o.Root)
	files, problems, err := corpus.LoadAll(dir)
	if err != nil {
		return nil, err
	}
	man, err := loadManifest(dir)
	if err != nil {
		return nil, err
	}
	var fs []Finding
	for _, p := range problems {
		fs = append(fs, Finding{"FF-SP4", "schema", where(o.Root, p), p})
	}
	fs = append(fs, checkManifest(o.Root, man)...)

	if o.Checks["FF-SP4"] {
		lock, err := loadLock(dir)
		if err != nil {
			return nil, err
		}
		fs = append(fs, checkUnits(o.Root, files, man)...)
		fs = append(fs, checkLock(o.Root, files, lock)...)
		fs = append(fs, checkHomes(o.Root, man)...)
	}
	if o.Run != nil || o.ReportDir != "" {
		reports := o.ReportDir
		if reports == "" {
			reports, err = os.MkdirTemp("", "safeprim-reports-")
			if err != nil {
				return nil, err
			}
			defer os.RemoveAll(reports)
		}
		// The implementations' tests run with their package directory as the working directory, so a
		// relative report directory (the Makefile's) would be written under each package instead.
		if reports, err = filepath.Abs(reports); err != nil {
			return nil, err
		}
		if o.Checks["FF-SP4"] || o.Checks["FF-SP8"] {
			fs = append(fs, runImplementations(o, files, man, reports)...)
		}
	}
	if o.Checks["FF-SP5"] {
		fs = append(fs, checkFuzzDeclared(o.Root, man)...)
	}
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Where != fs[j].Where {
			return fs[i].Where < fs[j].Where
		}
		return fs[i].Msg < fs[j].Msg
	})
	return fs, nil
}

// where pulls a "path:line" prefix out of a loader problem, or falls back to the corpus directory.
func where(root, problem string) string {
	if i := strings.Index(problem, ": "); i > 0 && strings.Contains(problem[:i], string(filepath.Separator)) {
		return rel(root, problem[:i])
	}
	return corpus.Dir
}

// checkManifest validates the implementation manifest itself.
func checkManifest(root string, m *Manifest) []Finding {
	var fs []Finding
	at := corpus.Dir + "/" + ManifestFile
	names := map[string]bool{}
	for _, im := range m.Implementations {
		add := func(rule, msg string) {
			fs = append(fs, Finding{"FF-SP4", rule, at, "implementation " + im.Name + ": " + msg})
		}
		switch {
		case im.Name == "":
			fs = append(fs, Finding{"FF-SP4", "manifest", at, "an implementation has no name"})
			continue
		case names[im.Name]:
			add("manifest", "declared twice")
		}
		names[im.Name] = true
		if len(im.Units) == 0 {
			add("manifest", "declares no unit")
		}
		for _, u := range im.Units {
			if !corpus.IsUnit(u) {
				add("manifest", fmt.Sprintf("unit %q is not an FF-SP4 unit", u))
			}
		}
		if im.Language == "go" {
			if im.Package == "" {
				add("manifest", "a Go implementation names its test package")
			} else if st, err := os.Stat(filepath.Join(root, filepath.FromSlash(im.Package))); err != nil || !st.IsDir() {
				add("manifest", fmt.Sprintf("package %s does not exist", im.Package))
			}
		} else if len(im.Command) == 0 {
			add("manifest", fmt.Sprintf("a %s implementation gives the command that runs the corpus and writes the reports", im.Language))
		}
		for _, u := range im.Units {
			if (u == "psx" || u == "proc") && im.ArgvTest == "" && len(im.ArgvCommand) == 0 {
				fs = append(fs, Finding{"FF-SP8", "constant-argv", at, fmt.Sprintf("implementation %s implements %s, so it names its constant-argv test (argvTest)", im.Name, u)})
			}
		}
	}
	return fs
}

// checkUnits is the FF-SP4 count: every unit that has a corpus file or an implementation holds at
// least MinHostile hostile records.
func checkUnits(root string, files map[string]*corpus.File, m *Manifest) []Finding {
	var fs []Finding
	units := map[string]bool{}
	for u := range files {
		units[u] = true
	}
	for _, im := range m.Implementations {
		for _, u := range im.Units {
			if corpus.IsUnit(u) {
				units[u] = true
			}
		}
	}
	for u := range units {
		f := files[u]
		n := 0
		at := corpus.Dir + "/" + u + ".jsonl"
		if f != nil {
			n = f.Hostile()
		}
		if n < corpus.MinHostile {
			who := ""
			if !m.declaresUnit(u) {
				who = " (corpus file present, no implementation yet)"
			}
			fs = append(fs, Finding{"FF-SP4", "min-hostile", at, fmt.Sprintf("unit %s has %d records with \"hostile\": true, needs %d%s", u, n, corpus.MinHostile, who)})
		}
	}
	return fs
}

// checkLock detects a record that disappears without a superseding one, or a hostile record that is
// reclassified, and a corpus that has grown without the lock being updated.
func checkLock(root string, files map[string]*corpus.File, l *Lock) []Finding {
	var fs []Finding
	at := corpus.Dir + "/" + LockFile
	retired := map[string]Retired{}
	for _, r := range l.Retired {
		retired[r.Unit+"\x00"+r.ID] = r
		if r.SupersededBy == "" || r.Reason == "" {
			fs = append(fs, Finding{"FF-SP4", "retired", at, fmt.Sprintf("retired record %s/%s needs supersededBy and reason", r.Unit, r.ID)})
		}
	}
	live := func(unit, id string) (hostile, ok bool) {
		f := files[unit]
		if f == nil {
			return false, false
		}
		for _, r := range f.Records {
			if r.ID == id {
				return r.IsHostile(), true
			}
		}
		return false, false
	}
	for unit, ids := range l.Units {
		for id, wasHostile := range ids {
			hostile, ok := live(unit, id)
			ret, isRetired := retired[unit+"\x00"+id]
			switch {
			case ok && isRetired:
				fs = append(fs, Finding{"FF-SP4", "retired", at, fmt.Sprintf("record %s/%s is retired in the lock but still in the corpus", unit, id)})
			case ok && wasHostile && !hostile:
				fs = append(fs, Finding{"FF-SP4", "reclassified", corpus.Dir + "/" + unit + ".jsonl", fmt.Sprintf("hostile record %s was reclassified to \"hostile\": false; add a replacement hostile record and retire %s in %s", id, id, LockFile)})
			case !ok && !isRetired:
				fs = append(fs, Finding{"FF-SP4", "record-removed", corpus.Dir + "/" + unit + ".jsonl", fmt.Sprintf("record %s disappeared without a superseding record; add \"retired\" {unit, id, supersededBy, reason} to %s, or restore it", id, LockFile)})
			case !ok && isRetired:
				superHostile, superOK := live(unit, ret.SupersededBy)
				switch {
				case !superOK:
					fs = append(fs, Finding{"FF-SP4", "record-removed", at, fmt.Sprintf("record %s/%s is retired, but its superseding record %s is not in the corpus", unit, id, ret.SupersededBy)})
				case wasHostile && !superHostile:
					fs = append(fs, Finding{"FF-SP4", "record-removed", at, fmt.Sprintf("hostile record %s/%s is superseded by %s, which is not hostile", unit, id, ret.SupersededBy)})
				}
			}
		}
	}
	for unit, f := range files {
		for _, r := range f.Records {
			if _, known := l.Units[unit][r.ID]; known {
				continue
			}
			if _, isRetired := retired[unit+"\x00"+r.ID]; isRetired {
				continue
			}
			fs = append(fs, Finding{"FF-SP4", "lock-stale", corpus.Dir + "/" + unit + ".jsonl", fmt.Sprintf("record %s is not in %s; run `go run ./tools/fitness/corpus -update-lock` and commit it", r.ID, LockFile)})
		}
	}
	return fs
}

var homeSkip = map[string]bool{"sqlcdb": true, "exempt": true, "owners": true, "reportsql": true, "testdata": true}

// checkHomes fails when Go code exists in a primitive's home but no implementation declares the unit:
// an implementation cannot exist without running the corpus.
func checkHomes(root string, m *Manifest) []Finding {
	var fs []Finding
	units := make([]string, 0, len(policy.UnitHomes))
	for u := range policy.UnitHomes {
		units = append(units, u)
	}
	sort.Strings(units)
	dirs := goPackageDirs(root)
	for _, u := range units {
		if m.declaresUnit(u) {
			continue
		}
		for _, pattern := range policy.UnitHomes[u] {
			for _, d := range dirs {
				if homeDepth(d, pattern) && !homeSkip[filepath.Base(d)] {
					fs = append(fs, Finding{"FF-SP4", "undeclared-implementation", d, fmt.Sprintf("Go code in the home of unit %s, but no implementation in %s/%s declares %s, so nothing proves it runs the corpus", u, corpus.Dir, ManifestFile, u)})
					break
				}
			}
		}
	}
	return dedupe(fs)
}

// homeDepth reports whether dir is the home itself or one of its direct subpackages.
func homeDepth(dir, pattern string) bool {
	if policy.Match(dir, pattern) {
		trim := strings.TrimPrefix(pattern, "**/")
		i := strings.LastIndex(dir, trim)
		if i < 0 {
			return false
		}
		rest := strings.TrimPrefix(dir[i+len(trim):], "/")
		return rest == "" || !strings.Contains(rest, "/")
	}
	return false
}

// goPackageDirs lists repository-relative directories that hold non-test Go files, skipping the
// trees that are not product code.
func goPackageDirs(root string) []string {
	seen := map[string]bool{}
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		r := rel(root, p)
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "testdata", "vendor", "knowledge", "factory", "garage":
				if r != "." {
					return filepath.SkipDir
				}
			}
			if r == "tools" || r == "lab" || r == "web" {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(d.Name(), ".go") && !strings.HasSuffix(d.Name(), "_test.go") {
			seen[filepath.ToSlash(filepath.Dir(r))] = true
		}
		return nil
	})
	out := make([]string, 0, len(seen))
	for d := range seen {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

func dedupe(fs []Finding) []Finding {
	seen := map[string]bool{}
	var out []Finding
	for _, f := range fs {
		k := f.String()
		if !seen[k] {
			seen[k] = true
			out = append(out, f)
		}
	}
	return out
}

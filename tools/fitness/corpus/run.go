package main

import (
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/skenzeriq/activediq/internal/platform/corpus"
)

// ExecRunner runs the command for real.
func ExecRunner(dir string, env []string, argv []string) (string, error) {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (im *Implementation) corpusCommand() []string {
	if im.Language == "go" {
		return []string{"go", "test", "-count=1", "-run", "^" + im.testName() + "$", "./" + im.Package}
	}
	return im.Command
}

func (im *Implementation) argvCommand() []string {
	switch {
	case len(im.ArgvCommand) > 0:
		return im.ArgvCommand
	case im.ArgvTest != "" && im.Language == "go":
		return []string{"go", "test", "-count=1", "-run", "^" + im.ArgvTest + "$", "./" + im.Package}
	}
	return nil
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n    ")
}

// runImplementations runs every declared implementation's corpus (and constant-argv) test with the
// report directory set, then reads the reports back and compares them with the corpus.
func runImplementations(o Options, files map[string]*corpus.File, m *Manifest, reportDir string) []Finding {
	var fs []Finding
	env := []string{corpus.ReportDirEnv + "=" + reportDir}
	for i := range m.Implementations {
		im := &m.Implementations[i]
		at := im.Package
		if at == "" {
			at = im.Name
		}
		if o.Run != nil {
			if cmd := im.corpusCommand(); len(cmd) > 0 && o.Checks["FF-SP4"] {
				if out, err := o.Run(o.Root, env, cmd); err != nil {
					fs = append(fs, Finding{"FF-SP4", "tests-failed", at, fmt.Sprintf("implementation %s: `%s` failed:\n    %s", im.Name, strings.Join(cmd, " "), tail(out, 25))})
				}
			}
			if cmd := im.argvCommand(); len(cmd) > 0 && o.Checks["FF-SP8"] {
				if out, err := o.Run(o.Root, env, cmd); err != nil {
					fs = append(fs, Finding{"FF-SP8", "tests-failed", at, fmt.Sprintf("implementation %s: `%s` failed:\n    %s", im.Name, strings.Join(cmd, " "), tail(out, 25))})
				}
			}
		}
	}
	if o.Checks["FF-SP4"] {
		reports, err := corpus.ReadReports(reportDir)
		if err != nil {
			return append(fs, Finding{"FF-SP4", "report", corpus.Dir, err.Error()})
		}
		byKey := map[string]corpus.Report{}
		for _, r := range reports {
			byKey[r.Impl+"\x00"+r.Unit] = r
		}
		for _, im := range m.Implementations {
			at := im.Package
			if at == "" {
				at = im.Name
			}
			for _, u := range im.Units {
				fs = append(fs, verifyReport(at, im.Name, u, files[u], byKey[im.Name+"\x00"+u], byKey)...)
			}
		}
	}
	if o.Checks["FF-SP8"] {
		fs = append(fs, verifyArgv(m, reportDir)...)
	}
	return fs
}

func verifyReport(at, impl, unit string, f *corpus.File, rep corpus.Report, all map[string]corpus.Report) []Finding {
	var fs []Finding
	_, have := all[impl+"\x00"+unit]
	if !have {
		return []Finding{{"FF-SP4", "no-report", at, fmt.Sprintf("implementation %s wrote no corpus report for unit %s: its test must call corpustest.Run(t, %q, %q, …) and the manifest must name that test", impl, unit, impl, unit)}}
	}
	if f == nil {
		return nil // reported by the unit count
	}
	if rep.CorpusSHA != f.SHA256 {
		fs = append(fs, Finding{"FF-SP4", "stale-corpus", at, fmt.Sprintf("implementation %s ran unit %s against a different corpus file (digest %.12s…, repository has %.12s…)", impl, unit, rep.CorpusSHA, f.SHA256)})
	}
	ran := map[string]corpus.Ran{}
	for _, r := range rep.Ran {
		ran[r.ID] = r
	}
	skipped := map[string]string{}
	for _, s := range rep.Skipped {
		skipped[s.ID] = s.Why
	}
	want := map[string]bool{}
	for _, id := range f.RuntimeIDs() {
		want[id] = true
		_, isSkipped := skipped[id]
		switch r, ok := ran[id]; {
		case isSkipped:
			fs = append(fs, Finding{"FF-SP4", "skipped-record", at, fmt.Sprintf("implementation %s skips record %s of unit %s (%s): an implementation runs every record of a unit it implements", impl, id, unit, skipped[id])})
		case !ok:
			fs = append(fs, Finding{"FF-SP4", "skipped-record", at, fmt.Sprintf("implementation %s did not run record %s of unit %s", impl, id, unit)})
		case !r.OK:
			fs = append(fs, Finding{"FF-SP4", "record-failed", at, fmt.Sprintf("implementation %s fails record %s of unit %s: %s", impl, id, unit, r.Why)})
		}
	}
	var extra []string
	for id := range ran {
		if !want[id] {
			extra = append(extra, id)
		}
	}
	sort.Strings(extra)
	for _, id := range extra {
		fs = append(fs, Finding{"FF-SP4", "unknown-record", at, fmt.Sprintf("implementation %s reports record %s, which is not a runtime record of unit %s", impl, id, unit)})
	}
	return fs
}

func verifyArgv(m *Manifest, reportDir string) []Finding {
	reports, err := corpus.ReadArgvReports(reportDir)
	if err != nil {
		return []Finding{{"FF-SP8", "report", corpus.Dir, err.Error()}}
	}
	by := map[string]corpus.ArgvReport{}
	for _, r := range reports {
		by[r.Impl] = r
	}
	var fs []Finding
	for _, im := range m.Implementations {
		needs := false
		for _, u := range im.Units {
			if u == "psx" || u == "proc" {
				needs = true
			}
		}
		if !needs {
			continue
		}
		at := im.Package
		if at == "" {
			at = im.Name
		}
		r, ok := by[im.Name]
		switch {
		case !ok:
			fs = append(fs, Finding{"FF-SP8", "no-report", at, fmt.Sprintf("implementation %s wrote no constant-argv report: its argvTest must call corpustest.ConstantArgv", im.Name)})
		case r.Requests < 100:
			fs = append(fs, Finding{"FF-SP8", "too-few-requests", at, fmt.Sprintf("implementation %s drove %d random requests, FF-SP8 needs at least 100", im.Name, r.Requests)})
		case len(r.Mismatches) > 0:
			fs = append(fs, Finding{"FF-SP8", "argv-differs", at, fmt.Sprintf("implementation %s: argv differs from the manifest's constant argv for %d of %d random requests, first: %s", im.Name, len(r.Mismatches), r.Requests, r.Mismatches[0])})
		}
	}
	return fs
}

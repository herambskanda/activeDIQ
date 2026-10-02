package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/corpus"
)

// Usage:
//
//	go run ./tools/fitness/corpus [-root .] [-checks FF-SP4,FF-SP5,FF-SP8] [-no-run]
//	go run ./tools/fitness/corpus -fuzz [-fuzztime 5s] [-nightly] [-parallel N] [-log FILE]
//	go run ./tools/fitness/corpus -update-lock
//	go run ./tools/fitness/corpus -set-verified results.json
//
// Exit status: 0 clean, 1 a rule is violated, 2 the job could not run.
func main() {
	root := flag.String("root", ".", "repository root (the directory holding go.mod)")
	only := flag.String("checks", "", "comma-separated subset of FF-SP4,FF-SP5,FF-SP8 (default: all)")
	reportDir := flag.String("report-dir", "", "keep the implementations' run reports here (cleared first) for the oracles; default a temp dir")
	noRun := flag.Bool("no-run", false, "do not execute the implementations' tests (static checks only)")
	doFuzz := flag.Bool("fuzz", false, "run every declared fuzz target instead of the corpus checks")
	fuzztime := flag.Duration("fuzztime", 0, "fuzz time per target (default 5s; with -nightly default and minimum 10m)")
	nightly := flag.Bool("nightly", false, "count the fuzz run as the FF-SP5 nightly: at least 10 minutes per target")
	parallel := flag.Int("parallel", 1, "fuzz targets to run at once")
	logPath := flag.String("log", "", "write the fuzz log (one line per target) to this file as well as stdout")
	updateLock := flag.Bool("update-lock", false, "add new record IDs to "+LockFile+" (never removes or downgrades one)")
	setVerified := flag.String("set-verified", "", "apply a lab result file {unit:{id:platform}} to the corpus's \"verified\" fields")
	flag.Parse()

	if *updateLock {
		err := doUpdateLock(*root)
		if err == nil {
			fmt.Println("fitness-corpus: wrote", filepath.Join(corpus.Dir, LockFile))
		}
		os.Exit(exit(err))
	}
	if *setVerified != "" {
		os.Exit(exit(doSetVerified(*root, *setVerified)))
	}
	if *doFuzz {
		os.Exit(exit(doFuzzRun(*root, *fuzztime, *nightly, *parallel, *logPath)))
	}

	checks := map[string]bool{"FF-SP4": true, "FF-SP5": true, "FF-SP8": true}
	if *only != "" {
		checks = map[string]bool{}
		for _, c := range strings.Split(*only, ",") {
			c = strings.ToUpper(strings.TrimSpace(c))
			if c != "FF-SP4" && c != "FF-SP5" && c != "FF-SP8" {
				fmt.Fprintf(os.Stderr, "fitness-corpus: unknown check %q\n", c)
				os.Exit(2)
			}
			checks[c] = true
		}
	}
	o := Options{Root: *root, Checks: checks, ReportDir: *reportDir}
	if *reportDir != "" {
		if err := clearReports(*reportDir); err != nil {
			fmt.Fprintln(os.Stderr, "fitness-corpus:", err)
			os.Exit(2)
		}
	}
	if !*noRun {
		o.Run = ExecRunner
	}
	fs, err := Check(o)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fitness-corpus:", err)
		os.Exit(2)
	}
	if len(fs) > 0 {
		for _, f := range fs {
			fmt.Fprintln(os.Stderr, f)
		}
		fmt.Fprintf(os.Stderr, "fitness-corpus: %d violation(s)\n", len(fs))
		os.Exit(1)
	}
	fmt.Println("fitness-corpus: ok (" + summary(*root, checks, *noRun) + ")")
}

func clearReports(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, pat := range []string{"corpus-*.json", "argv-*.json"} {
		old, _ := filepath.Glob(filepath.Join(dir, pat))
		for _, p := range old {
			if err := os.Remove(p); err != nil {
				return err
			}
		}
	}
	return nil
}

func exit(err error) int {
	if err == nil {
		return 0
	}
	if v, ok := err.(violation); ok {
		fmt.Fprintln(os.Stderr, string(v))
		return 1
	}
	fmt.Fprintln(os.Stderr, "fitness-corpus:", err)
	return 2
}

type violation string

func (v violation) Error() string { return string(v) }

func summary(root string, checks map[string]bool, noRun bool) string {
	files, _, _ := corpus.LoadAll(corpusDir(root))
	man, _ := loadManifest(corpusDir(root))
	var names []string
	for _, c := range []string{"FF-SP4", "FF-SP5", "FF-SP8"} {
		if checks[c] {
			names = append(names, c)
		}
	}
	recs := 0
	for _, f := range files {
		recs += len(f.Records)
	}
	run := "implementations run"
	if noRun {
		run = "implementations not run (-no-run)"
	}
	return fmt.Sprintf("%s; %d corpus units, %d records, %d implementations declared, %d fuzz targets, %s", strings.Join(names, ", "), len(files), recs, len(man.Implementations), len(man.Fuzz), run)
}

func doUpdateLock(root string) error {
	dir := corpusDir(root)
	files, problems, err := corpus.LoadAll(dir)
	if err != nil {
		return err
	}
	if len(problems) > 0 {
		return fmt.Errorf("the corpus does not load:\n%s", strings.Join(problems, "\n"))
	}
	lock, err := loadLock(dir)
	if err != nil {
		return err
	}
	retired := map[string]bool{}
	for _, r := range lock.Retired {
		retired[r.Unit+"\x00"+r.ID] = true
	}
	for unit, f := range files {
		if lock.Units[unit] == nil {
			lock.Units[unit] = map[string]bool{}
		}
		for _, r := range f.Records {
			if retired[unit+"\x00"+r.ID] {
				continue
			}
			was, known := lock.Units[unit][r.ID]
			if known && was && !r.IsHostile() {
				return violation(fmt.Sprintf("%s: record %s is hostile in the lock and reclassified here: add a replacement hostile record and retire %s instead", unit, r.ID, r.ID))
			}
			lock.Units[unit][r.ID] = r.IsHostile() || was
		}
	}
	// A retired record whose superseding record exists leaves the lock.
	for _, r := range lock.Retired {
		if ids, ok := lock.Units[r.Unit]; ok {
			if _, still := ids[r.ID]; still {
				if _, exists := files[r.Unit]; exists {
					delete(ids, r.ID)
				}
			}
		}
	}
	b, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, LockFile), append(b, '\n'), 0o644); err != nil {
		return err
	}
	return nil
}

// doSetVerified applies lab results: platform values merge into the record's "verified" field.
func doSetVerified(root, resultsFile string) error {
	b, err := os.ReadFile(resultsFile)
	if err != nil {
		return err
	}
	var results map[string]map[string]string
	if err := json.Unmarshal(b, &results); err != nil {
		return fmt.Errorf("%s: %w", resultsFile, err)
	}
	units := make([]string, 0, len(results))
	for u := range results {
		units = append(units, u)
	}
	sort.Strings(units)
	changed := 0
	for _, u := range units {
		f, err := corpus.Load(corpusDir(root), u)
		if err != nil {
			return err
		}
		touched := false
		for i, r := range f.Records {
			plat, ok := results[u][r.ID]
			if !ok {
				continue
			}
			if merged := corpus.MergeVerified(r.Verified, plat); merged != r.Verified {
				f.Records[i].Verified = merged
				touched = true
				changed++
			}
		}
		if touched {
			if err := corpus.Write(f.Path, f.Records); err != nil {
				return err
			}
		}
	}
	fmt.Printf("fitness-corpus: updated \"verified\" on %d record(s)\n", changed)
	return nil
}

func doFuzzRun(root string, d time.Duration, nightly bool, parallel int, logPath string) error {
	if d == 0 {
		d = 5 * time.Second
		if nightly {
			d = MinNightlyFuzz
		}
	}
	man, err := loadManifest(corpusDir(root))
	if err != nil {
		return err
	}
	var lines []string
	fs := RunFuzz(root, man, d, nightly, parallel, ExecRunner, func(l string) { fmt.Println(l); lines = append(lines, l) })
	if len(man.Fuzz) == 0 {
		fmt.Println("fitness-corpus: no fuzz targets declared (no implementation exists yet)")
	}
	if logPath != "" {
		sort.Strings(lines)
		header := fmt.Sprintf("# FF-SP5 fuzz run %s, %s per target, %d target(s)\n", time.Now().UTC().Format(time.RFC3339), d, len(man.Fuzz))
		if err := os.WriteFile(logPath, []byte(header+strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
			return err
		}
	}
	if len(fs) > 0 {
		for _, f := range fs {
			fmt.Fprintln(os.Stderr, f)
		}
		return violation(fmt.Sprintf("fitness-corpus: %d fuzz violation(s)", len(fs)))
	}
	fmt.Printf("fitness-corpus: fuzz ok (%d target(s), %s each)\n", len(man.Fuzz), d)
	return nil
}

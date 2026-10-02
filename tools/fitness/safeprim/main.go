// Command safeprim is the static safe-primitives fitness job (T-0033): FF-SP1 import boundaries,
// FF-SP2 banned APIs and analyzers, FF-SP3 literal-shape scanner. `make fitness-safeprim` runs it
// inside `make ci`. It exits 1 when any check finds a violation, 2 when it cannot run.
//
//	go run ./tools/fitness/safeprim [-root .] [-checks FF-SP1,FF-SP2,FF-SP3] [-no-analyzers]
//
// The web/ half of FF-SP3 is the ESLint rule set in web/eslint/, run by `make lint-web`.
package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/skenzeriq/activediq/tools/fitness/safeprim/scan"
)

func main() {
	root := flag.String("root", ".", "repository root (the directory holding go.mod)")
	only := flag.String("checks", "", "comma-separated subset of FF-SP1,FF-SP2,FF-SP3 (default: all)")
	noAnalyzers := flag.Bool("no-analyzers", false, "skip the type-aware go/analysis passes of FF-SP2 (they need the module to type-check)")
	flag.Parse()

	checks := scan.AllChecks()
	if *only != "" {
		checks = scan.Checks{}
		for _, c := range strings.Split(*only, ",") {
			c = strings.ToUpper(strings.TrimSpace(c))
			if c != "FF-SP1" && c != "FF-SP2" && c != "FF-SP3" {
				fmt.Fprintf(os.Stderr, "fitness-safeprim: unknown check %q\n", c)
				os.Exit(2)
			}
			checks[c] = true
		}
	}
	fs, err := scan.Scan(*root, checks)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fitness-safeprim:", err)
		os.Exit(2)
	}
	if checks["FF-SP2"] && !*noAnalyzers {
		af, err := scan.Analyze(*root)
		if err != nil {
			fmt.Fprintln(os.Stderr, "fitness-safeprim:", err)
			os.Exit(2)
		}
		fs = append(fs, af...)
	}
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].File != fs[j].File {
			return fs[i].File < fs[j].File
		}
		return fs[i].Line < fs[j].Line
	})
	if len(fs) == 0 {
		var names []string
		for _, c := range []string{"FF-SP1", "FF-SP2", "FF-SP3"} {
			if checks[c] {
				names = append(names, c)
			}
		}
		fmt.Printf("fitness-safeprim: ok (%s)\n", strings.Join(names, ", "))
		return
	}
	for _, f := range fs {
		fmt.Fprintln(os.Stderr, f)
	}
	fmt.Fprintf(os.Stderr, "fitness-safeprim: %d violation(s)\n", len(fs))
	os.Exit(1)
}

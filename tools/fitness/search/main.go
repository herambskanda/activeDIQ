// Command search is the fitness-search job: ADR-0011 (universal search over the inventory, pg_trgm,
// one scope renderer), section "Fitness function" (T-1126).
//
//	SE1  one renderer and one reader of the scope's sources                       (typed, plus SQL)
//	SE2  no string-built search SQL and no stray trigram use                      (static, repo-wide)
//	SE3  search scope equals the oracle                                           (bound tests, PostgreSQL 16 and 18)
//	SE4  hostile, normalisation and secrecy vectors                               (bound tests)
//	SE5  bounded work                                                             (bound tests, PostgreSQL 16 and 18)
//	SE6  latency                                                                  (-nightly, behind the large-dataset switch)
//
// As in fitness-reports, a check whose subject has not landed is printed as pending on every run, which
// is not a pass, and ADR-0011 stays out of `accepted` while any SE1-SE5 part is pending or SE6 has not
// passed once. A bound test that lands without its binding being marked Landed fails the job, so a
// landed test cannot sit unchecked. Each rule has a failing fixture in check_test.go and a throw-away
// tree in tools/ci/proof.sh.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
)

func main() {
	root := flag.String("root", ".", "repository root (the directory holding go.mod)")
	staticOnly := flag.Bool("static-only", false, "skip the bound tests (used by the gate proofs)")
	nightly := flag.Bool("nightly", false, "run only the nightly bindings (SE6), with the large-dataset switch on")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	// The bound tests must run on every PostgreSQL version: a developer's narrowing variable does not
	// apply to the gate, and the bindings require the pg16 and pg18 subtests anyway.
	_ = os.Unsetenv("ACTIVEDIQ_TEST_PG_VERSIONS")
	if *nightly {
		_ = os.Setenv("ACTIVEDIQ_SEARCH_LARGE_OBJECTS", "50000")
	}

	r, err := Run(ctx, Options{Root: *root, StaticOnly: *staticOnly, Nightly: *nightly})
	if err != nil {
		fmt.Fprintln(os.Stderr, "fitness-search:", err)
		os.Exit(2)
	}
	sort.Strings(r.Pending)
	for _, p := range r.Pending {
		fmt.Printf("  pending   %s (not yet checked, not a pass)\n", p)
	}
	for _, p := range r.Passed {
		fmt.Printf("  pass      %s\n", p)
	}
	for _, n := range r.Notes {
		fmt.Printf("  note      %s\n", n)
	}
	if len(r.Violations) == 0 {
		if *nightly {
			fmt.Println("fitness-search -nightly: ok (SE6 ran on PostgreSQL 16 and 18 with the large-dataset switch; a pending part is not a pass)")
			return
		}
		fmt.Println("fitness-search: ok (every check listed as pass ran and passed; pending parts are not a pass; SE6 runs in the nightly job; ADR-0011 stays ratified while any of SE1-SE5 is pending or SE6 has not passed once)")
		return
	}
	for _, v := range r.Violations {
		fmt.Fprintln(os.Stderr, v)
	}
	fmt.Fprintf(os.Stderr, "fitness-search: %d violation(s); rules: ADR-0011 Fitness function (SE1-SE6)\n", len(r.Violations))
	os.Exit(1)
}

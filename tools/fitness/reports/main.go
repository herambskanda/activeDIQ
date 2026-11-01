// Command reports is the fitness-reports job: ADR-0010 (report results are stored as rows, exports
// serialise the stored run) and the reports module contract, knowledge/development/architecture/
// modules/reports.md §9, checks RP1 to RP11 (T-0873).
//
//	RP1  FF-SP2 sqlconst amendment   tools/analyzers/sqlconst (run by fitness-safeprim)
//	RP2  ReadScope.Terms/.Token and NewReadScope have one renderer and one producer       (typed)
//	RP3  only reports/run calls reportsql.Compile, CompileCount or Exec                    (typed)
//	RP7  every file listed in library/LOCK keeps its SHA-256; LOCK is append-only          (hash)
//	RP4, RP5, RP6, RP8, RP9, RP10, RP11  bound tests, run here; absent or skipped fails
//
// A check whose code has not landed is printed as pending on every run, which is not a pass, and
// ADR-0010 stays out of `accepted` while any is pending. The check turns active the moment the
// code appears: a bound test whose binding is not marked Landed fails, so a landed test cannot sit
// unchecked. Each rule has a failing fixture in check_test.go and a throw-away tree in tools/ci/proof.sh.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
)

func main() {
	root := flag.String("root", ".", "repository root (the directory holding go.mod)")
	staticOnly := flag.Bool("static-only", false, "skip the bound tests (used by the gate proofs)")
	lockBase := flag.String("lock-base", "", "git ref whose library/LOCK entries must all still be present and unchanged (append-only); empty skips the comparison")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	r, err := Run(ctx, Options{Root: *root, StaticOnly: *staticOnly, LockBase: *lockBase})
	if err != nil {
		fmt.Fprintln(os.Stderr, "fitness-reports:", err)
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
		fmt.Println("fitness-reports: ok (every check listed as pass ran and passed; pending parts are not a pass; RP1 runs in fitness-safeprim; ADR-0010 is bound to RP3, RP4 and RP5)")
		return
	}
	for _, v := range r.Violations {
		fmt.Fprintln(os.Stderr, v)
	}
	fmt.Fprintf(os.Stderr, "fitness-reports: %d violation(s); rules: reports contract §9 (RP1-RP11), ADR-0010\n", len(r.Violations))
	os.Exit(1)
}

func join(s []string) string { return strings.Join(s, ", ") }

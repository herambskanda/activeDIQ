// Command agenthost is `fitness-agent-host`, the fitness function of ADR-0006 (A1, A4) and ADR-0007
// (P1-P8) and the CI half of TM-F-AGENTCMD for `addc` (agent-host-addc-contract.md §6, rules R1-R5, F1).
// It exits non-zero when a denied verb, an out-of-bounds policy, a wrong-tenant or replayed policy, or
// LocalSystem in the agent installer source gets through. A check whose subject does not exist yet
// prints `inactive (<missing input>)` and never counts as a pass; the ADR is `accepted` only when
// none is inactive.
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	root := flag.String("root", ".", "repository root")
	skipTests := flag.Bool("skip-tests", false, "do not run the P1-P8/F1 Go tests (the proof script uses this on fixture trees)")
	only := flag.String("checks", "", "comma-separated subset of R1,R2,R3,R4,R5,A1,A4,P,F1 (default all)")
	allowFile := flag.String("closure-allow", "", "A4 allowlist file replacing the reviewed closure-allow.txt (the proof script's fixture trees)")
	flag.Parse()
	o := Options{SkipTests: *skipTests, Only: *only}
	if *allowFile != "" {
		b, err := os.ReadFile(*allowFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "fitness-agent-host:", err)
			os.Exit(2)
		}
		o.ClosureAllow = append([]string{}, parseAllow(string(b))...)
	}
	res := Run(*root, o)
	for _, r := range res {
		fmt.Println(r.Line())
	}
	fails := 0
	for _, r := range res {
		fails += len(r.Violations)
	}
	if fails > 0 {
		fmt.Fprintf(os.Stderr, "fitness-agent-host: FAIL: %d violation(s)\n", fails)
		os.Exit(1)
	}
	inactive := 0
	for _, r := range res {
		if r.Inactive != "" {
			inactive++
		}
	}
	fmt.Printf("fitness-agent-host: ok (%d check(s) inactive)\n", inactive)
}

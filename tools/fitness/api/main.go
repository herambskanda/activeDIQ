// Command fitness-api is the ADR-0004 fitness job for the public API contract (A1 to A14). It is
// the one place that says which of the fourteen checks run. A check whose input does not exist yet
// prints "inactive (<missing input>)" on every run and the job still exits 0, but ADR-0004 is
// `accepted` only when no line says inactive. A1, A3 (document half), A4, A5, A6, A7, A8 (linter half), A10, A11, A12, A13 and A14 are
// active; a check with an unfinished part prints "inactive part". A2 and A9 are delegated.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

func main() {
	root := flag.String("root", ".", "repository root (the directory holding go.mod)")
	only := flag.String("checks", "", "comma-separated active checks to run (for example A1,A13); default all. The status table always lists all fourteen")
	flag.Parse()

	var sel map[string]bool
	if *only != "" {
		sel = map[string]bool{}
		for _, id := range strings.Split(*only, ",") {
			id = strings.TrimSpace(id)
			if !isActive(id) {
				fmt.Fprintf(os.Stderr, "fitness-api: -checks %q: not an active check (active: %s)\n", id, strings.Join(activeIDs(), ", "))
				os.Exit(2)
			}
			sel[id] = true
		}
	}

	rep, err := Run(*root, sel)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fitness-api:", err)
		os.Exit(2)
	}
	for _, l := range rep.Lines {
		fmt.Println(l)
	}
	fmt.Println(rep.Summary())
	for _, v := range rep.Violations {
		fmt.Fprintln(os.Stderr, v)
	}
	if len(rep.Violations) > 0 {
		fmt.Fprintf(os.Stderr, "fitness-api: %d violation(s)\n", len(rep.Violations))
		os.Exit(1)
	}
}

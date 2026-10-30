package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	root := flag.String("root", ".", "repository root (the directory holding go.mod)")
	adr := flag.String("adr", DefaultADR, "the ADR whose dag block is the source of the kernel import DAG (relative to -root)")
	flag.Parse()
	rep, err := Check(*root, *adr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fitness-operation:", err)
		os.Exit(2)
	}
	existing, pending := 0, 0
	fmt.Printf("fitness-operation O9: kernel import DAG from %s (%d packages)\n", rep.ADR, len(rep.Pkgs))
	for _, p := range rep.Pkgs {
		state := "existing"
		if p.Existing {
			existing++
		} else {
			state, pending = "pending ", pending+1
		}
		fmt.Printf("  %s  %-18s %s\n", state, p.Name, p.Dir)
	}
	fmt.Printf("fitness-operation O9: %d existing, %d pending (not yet checked), %d import edge(s) among the listed packages checked\n", existing, pending, rep.Edges)
	o1, err := CheckO1(*root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fitness-operation:", err)
		os.Exit(2)
	}
	rep.Violations = append(rep.Violations, o1...)
	o2, err := CheckO2(*root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fitness-operation:", err)
		os.Exit(2)
	}
	rep.Violations = append(rep.Violations, o2...)
	o4, err := CheckO4(*root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fitness-operation:", err)
		os.Exit(2)
	}
	rep.Violations = append(rep.Violations, o4...)
	o1t, err := CheckO1Types(*root)
	if err != nil {
		// Fail closed: a tree that cannot be type-checked never passes. When violations are already
		// known (an import cycle is itself an O9 violation) report them, with the reason O1's
		// type-aware half could not run.
		if len(rep.Violations) == 0 {
			fmt.Fprintln(os.Stderr, "fitness-operation:", err)
			os.Exit(2)
		}
		fmt.Fprintln(os.Stderr, "fitness-operation: type-aware O1 did not run:", err)
	}
	rep.Violations = append(rep.Violations, o1t...)
	for _, p := range pendingChecks {
		fmt.Printf("  pending   %-6s %s (owner %s; not yet checked, not a pass)\n", p.id, p.what, p.ticket)
	}
	if len(rep.Violations) == 0 {
		fmt.Println("fitness-operation: ok (O1, O2, O4 SQL half, O9; pending checks listed above)")
		return
	}
	for _, v := range rep.Violations {
		fmt.Fprintln(os.Stderr, v)
	}
	fmt.Fprintf(os.Stderr, "fitness-operation: %d violation(s); rules: %s (O1/O2 rule 2, O4 rule 3, O9 rule 13)\n", len(rep.Violations), rep.ADR)
	os.Exit(1)
}

// pendingChecks are the ADR-0005 checks whose guarded code has not landed. They are listed on every
// run, never skipped silently; the owning ticket removes its line when it lands the check.
var pendingChecks = []struct{ id, what, ticket string }{
	{"O3", "configuration writes (write-class column and step.Step config writers)", "T-0391"},
	{"O5-O7", "registry completeness, contract coverage, contract behaviour (operationtest.Contract)", "T-0392"},
	{"O8", "pipeline behaviour integration suite", "T-0393"},
}

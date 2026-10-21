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
	if len(rep.Violations) == 0 {
		fmt.Println("fitness-operation: ok (O9; O1-O8 land with the code they inspect)")
		return
	}
	for _, v := range rep.Violations {
		fmt.Fprintln(os.Stderr, v)
	}
	fmt.Fprintf(os.Stderr, "fitness-operation: %d violation(s); rules: %s (rule 13, fitness function O9)\n", len(rep.Violations), rep.ADR)
	os.Exit(1)
}

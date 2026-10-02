package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	root := flag.String("root", ".", "repository root (the directory holding go.mod)")
	flag.Parse()
	vs, err := Check(*root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fitness-modules:", err)
		os.Exit(2)
	}
	if len(vs) == 0 {
		fmt.Println("fitness-modules: ok")
		return
	}
	for _, v := range vs {
		fmt.Fprintln(os.Stderr, v)
	}
	fmt.Fprintf(os.Stderr, "fitness-modules: %d violation(s)\n", len(vs))
	os.Exit(1)
}

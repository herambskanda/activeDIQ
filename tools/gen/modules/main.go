package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

const out = "internal/platform/store/owners/owners.gen.go"

func main() {
	check := flag.Bool("check", false, "fail if "+out+" is stale, hand-edited or missing instead of writing it")
	root := flag.String("root", ".", "repository root")
	flag.Parse()
	if err := run(*root, *check); err != nil {
		fmt.Fprintln(os.Stderr, "gen-modules:", err)
		os.Exit(1)
	}
}

func run(root string, check bool) error {
	entries, err := Parse(os.DirFS(filepath.Join(root, "migrations")))
	if err != nil {
		return err
	}
	want, err := Render(entries)
	if err != nil {
		return err
	}
	path := filepath.Join(root, out)
	if check {
		have, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("%s is missing (run `make gen-modules`): %w", out, err)
		}
		if !bytes.Equal(have, want) {
			return fmt.Errorf("%s is stale or hand-edited: it differs from what the migrations produce (run `make gen-modules` and commit it)", out)
		}
		fmt.Printf("gen-modules: %s is current (%d tables)\n", out, len(entries))
		return nil
	}
	if err := os.WriteFile(path, want, 0o644); err != nil {
		return err
	}
	fmt.Printf("gen-modules: wrote %s (%d tables)\n", out, len(entries))
	return nil
}

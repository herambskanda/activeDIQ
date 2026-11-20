package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/skenzeriq/activediq/tools/gen/modules/modlist"
)

const out = "internal/platform/store/owners/owners.gen.tsv"

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
		return runLists(root, check)
	}
	if err := os.WriteFile(path, want, 0o644); err != nil {
		return err
	}
	fmt.Printf("gen-modules: wrote %s (%d tables)\n", out, len(entries))
	return runLists(root, check)
}

// runLists writes or checks the two module lists of the composition root (ADR-0015 D3, M3a).
func runLists(root string, check bool) error {
	l, err := modlist.Discover(root)
	if err != nil {
		return err
	}
	mod, err := modlist.ModulePath(root)
	if err != nil {
		return err
	}
	server, agent := modlist.Render(mod, l)
	for _, f := range []struct {
		rel  string
		want []byte
	}{{modlist.ServerFile, server}, {modlist.AgentFile, agent}} {
		path := filepath.Join(root, filepath.FromSlash(f.rel))
		if check {
			have, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("%s is missing (run `make gen-modules`): %w", f.rel, err)
			}
			if !bytes.Equal(have, f.want) {
				return fmt.Errorf("%s is stale or hand-edited: it differs from what internal/modules and internal/agentmodules produce (run `make gen-modules` and commit it)", f.rel)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(path, f.want, 0o644); err != nil {
			return err
		}
	}
	fmt.Printf("gen-modules: module lists current (%d server modules, %d agent modules)\n", len(l.Server), len(l.Agent))
	return nil
}

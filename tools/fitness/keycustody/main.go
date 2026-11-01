// Command keycustody is the fitness-keys job: keys-custody-design §7, FF-KEY-1..6.
//
//	FF-KEY-1  schema: tenant_keys guards, grants, declaration (PostgreSQL containers; needs Docker)
//	FF-KEY-2  single owner of tenant_keys and the DEK/wrap calls (AST scan)
//	FF-KEY-3  KEK configuration is read only in the composition root (scan + bound tests)
//	FF-KEY-4/5/6  behaviours, bound by name to the tests that prove them (bindings.go); the parts whose
//	          code has not landed are listed as pending on every run, which is not a pass.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"

	"github.com/skenzeriq/activediq/tools/fitness/pgharness"
)

func main() {
	root := flag.String("root", ".", "repository root (the directory holding go.mod)")
	versions := flag.String("pg", "16,18", "PostgreSQL major versions for FF-KEY-1")
	noTests := flag.Bool("static-only", false, "skip the database and bound-test parts (used by the gate proofs)")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	fail := func(err error) { fmt.Fprintln(os.Stderr, "fitness-keys:", err); os.Exit(2) }

	files, err := loadGo(*root)
	if err != nil {
		fail(err)
	}
	var vs []Violation
	var pending []string
	vs = append(vs, checkDeclarations(files)...)
	vs = append(vs, checkFFKey2(files)...)
	v3, err := checkFFKey3(*root, files)
	if err != nil {
		fail(err)
	}
	vs = append(vs, v3...)
	v5, p5 := checkFFKey5(files)
	vs = append(vs, v5...)
	pending = append(pending, p5...)

	if !*noTests {
		if err := pgharness.DockerAvailable(ctx); err != nil {
			fail(err)
		}
		ms, problems, err := pgharness.ListMigrations(filepath.Join(*root, "migrations"))
		if err != nil {
			fail(err)
		}
		if len(problems) > 0 {
			fail(fmt.Errorf("migration %s: %s", problems[0].File, problems[0].Msg))
		}
		for _, v := range strings.Split(*versions, ",") {
			if v = strings.TrimSpace(v); v == "" {
				continue
			}
			got, pend, err := onPG(ctx, v, ms)
			if err != nil {
				fail(err)
			}
			for _, x := range got {
				x.Msg = "(PostgreSQL " + v + ") " + x.Msg
				vs = append(vs, x)
			}
			if len(pending) == len(p5) { // report the pending catalogue notes once
				pending = append(pending, pend...)
			}
			fmt.Printf("fitness-keys FF-KEY-1: PostgreSQL %s: %d migration(s), %d violation(s)\n", v, len(ms), len(got))
		}
		bv, err := runBindings(ctx, *root, defaultBindings, goTest)
		if err != nil {
			fail(err)
		}
		vs = append(vs, bv...)
	}
	for _, p := range pending {
		fmt.Printf("  pending   %s (not yet checked, not a pass)\n", p)
	}
	for _, p := range pendingChecks {
		fmt.Printf("  pending   %-9s %s (owner: %s; not yet checked, not a pass)\n", p.id, p.what, p.ticket)
	}
	if len(vs) == 0 {
		fmt.Println("fitness-keys: ok (FF-KEY-1..6 as listed; pending parts above)")
		return
	}
	sort.SliceStable(vs, func(i, j int) bool {
		if vs[i].Check != vs[j].Check {
			return vs[i].Check < vs[j].Check
		}
		return vs[i].Where < vs[j].Where
	})
	for _, v := range vs {
		fmt.Fprintln(os.Stderr, v)
	}
	fmt.Fprintf(os.Stderr, "fitness-keys: %d violation(s); rules: keys-custody-design §7\n", len(vs))
	os.Exit(1)
}

func onPG(ctx context.Context, version string, ms []pgharness.Migration) ([]Violation, []string, error) {
	s, err := pgharness.StartServer(ctx, version, nil)
	if err != nil {
		return nil, nil, err
	}
	defer s.Stop()
	d, err := s.NewDatabase(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer d.Drop(ctx)
	failed, msg, err := pgharness.Apply(ctx, d, ms)
	if err != nil {
		return nil, nil, err
	}
	if failed != "" {
		return nil, nil, fmt.Errorf("migration %s does not apply: %s", failed, msg)
	}
	return checkFFKey1(ctx, d)
}

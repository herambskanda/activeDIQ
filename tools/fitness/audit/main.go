// Command audit is the fitness-audit job of ADR-0005 (checks A1–A9) and the proof TM-F-AUDIT of the
// threat model (§11): the runtime role cannot rewrite the audit tables, an edited, deleted or
// reordered event does not verify, and every checkpoint is anchored outside the database and in the
// export.
//
// A1 runs here, against ephemeral PostgreSQL containers (16 and 18) with every migration applied under
// the owner role, reading the catalogue and exercising audit_head's genesis trigger as the runtime
// role. A2, A3, A5, A6 and A9 are behaviours of the audit chain, verifier and retention code; their
// tests live beside that code and are bound here by name (bindings.go): the job runs them and fails
// when one is missing, failed or skipped. A4, A7, A8 and the alerting half of A6 guard code that has
// not landed; every run lists them as pending, which is not a pass.
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
	migrations := flag.String("migrations", "migrations", "migrations directory, relative to -root")
	versions := flag.String("pg", "16,18", "PostgreSQL major versions to run A1 against")
	checks := flag.String("checks", "A1,A2,A3,A5,A6,A9", "comma-separated checks to run (A1..A9)")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	want := map[string]bool{}
	for _, k := range strings.Split(*checks, ",") {
		k = strings.ToUpper(strings.TrimSpace(k))
		if len(k) != 2 || k[0] != 'A' || k[1] < '1' || k[1] > '9' {
			fmt.Fprintf(os.Stderr, "fitness-audit: unknown check %q (want A1..A9)\n", k)
			os.Exit(2)
		}
		want[k] = true
	}
	var vs []Violation
	if want["A1"] {
		a1, err := runA1(ctx, *root, *migrations, strings.Split(*versions, ","))
		if err != nil {
			fmt.Fprintln(os.Stderr, "fitness-audit:", err)
			os.Exit(2)
		}
		vs = append(vs, a1...)
	}
	var bs []binding
	for _, b := range defaultBindings {
		if want[b.Check] {
			bs = append(bs, b)
		}
	}
	if len(bs) > 0 {
		bv, err := runBindings(ctx, *root, bs, goTest)
		if err != nil {
			fmt.Fprintln(os.Stderr, "fitness-audit:", err)
			os.Exit(2)
		}
		vs = append(vs, bv...)
	}
	for _, p := range pendingChecks {
		fmt.Printf("  pending   %-3s %s (owner: %s; not yet checked, not a pass)\n", p.id, p.what, p.ticket)
	}
	if len(vs) == 0 {
		fmt.Println("fitness-audit: ok (" + *checks + "; pending checks listed above)")
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
	fmt.Fprintf(os.Stderr, "fitness-audit: %d violation(s); rules: ADR-0005 § Fitness function, TM-F-AUDIT (threat model §11)\n", len(vs))
	os.Exit(1)
}

// runA1 starts one PostgreSQL container per version, migrates a fresh database and runs checkA1.
func runA1(ctx context.Context, root, migrationsDir string, versions []string) ([]Violation, error) {
	if err := pgharness.DockerAvailable(ctx); err != nil {
		return nil, err
	}
	ms, problems, err := pgharness.ListMigrations(filepath.Join(root, migrationsDir))
	if err != nil {
		return nil, err
	}
	if len(problems) > 0 {
		return nil, fmt.Errorf("migration %s: %s", problems[0].File, problems[0].Msg)
	}
	var vs []Violation
	for _, v := range versions {
		if v = strings.TrimSpace(v); v == "" {
			continue
		}
		got, err := a1On(ctx, v, ms, nil)
		if err != nil {
			return nil, err
		}
		for _, x := range got {
			x.Msg = "(PostgreSQL " + v + ") " + x.Msg
			vs = append(vs, x)
		}
		fmt.Printf("fitness-audit A1: PostgreSQL %s: %d migration(s), %d violation(s)\n", v, len(ms), len(got))
	}
	return vs, nil
}

func a1On(ctx context.Context, version string, ms []pgharness.Migration, mutate func(ctx context.Context, d *pgharness.Database) error) ([]Violation, error) {
	s, err := pgharness.StartServer(ctx, version, nil)
	if err != nil {
		return nil, err
	}
	defer s.Stop()
	return a1Database(ctx, s, ms, mutate)
}

func a1Database(ctx context.Context, s *pgharness.Server, ms []pgharness.Migration, mutate func(ctx context.Context, d *pgharness.Database) error) ([]Violation, error) {
	d, err := s.NewDatabase(ctx)
	if err != nil {
		return nil, err
	}
	defer d.Drop(ctx)
	failed, msg, err := pgharness.Apply(ctx, d, ms)
	if err != nil {
		return nil, err
	}
	if failed != "" {
		return nil, fmt.Errorf("migration %s does not apply: %s", failed, msg)
	}
	if mutate != nil {
		if err := mutate(ctx, d); err != nil {
			return nil, err
		}
	}
	return checkA1(ctx, d)
}

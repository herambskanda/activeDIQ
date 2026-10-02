// Command tenancy is the fitness-tenancy job of ADR-0002 (checks T1–T5) and the one implementation of
// safe-primitives FF-SP7, run by `make ci`. It fails the build when tenant isolation is not enforced by
// construction: migration 1 does not create tenants (T1), the migrated schema breaks the catalog rules
// of RLS, keys, views and functions (T2), the runtime role is too powerful (T3), generated probes with
// two tenants find a leak (T4), or the Go source mints tenant IDs, sets tenant context or touches
// global tables where it may not (T5).
//
// T1–T4 run against ephemeral PostgreSQL containers (16 and 18) with every migration applied under a
// separate owner role. With no migration yet the job still runs and passes. Rules and registry format:
// knowledge/development/architecture/tenancy-fitness.md.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"

	"github.com/skenzeriq/activediq/tools/fitness/tenancy/registry"
	"github.com/skenzeriq/activediq/tools/fitness/tenancy/static"
)

// Options configures one run.
type Options struct {
	Root          string
	MigrationsDir string // relative to Root
	RegistryPath  string // relative to Root
	Versions      []string
	Checks        map[string]bool // T1..T5
	Out           io.Writer
	// ExtraBootstrap is extra superuser SQL run in every new database, with the owner role as %1$I and
	// the runtime role as %2$I. Tests use it to give a role a power the checks must catch.
	ExtraBootstrap []string
	// Servers lets a caller (the tests) supply running servers by major version; they are not stopped.
	Servers map[string]*Server
}

func main() {
	root := flag.String("root", ".", "repository root (the directory holding go.mod)")
	migrations := flag.String("migrations", "migrations", "migrations directory, relative to -root")
	reg := flag.String("registry", registry.DefaultPath, "exemption registry (JSON), relative to -root")
	versions := flag.String("pg", "16,18", "PostgreSQL major versions to run T1–T4 against")
	checks := flag.String("checks", "T1,T2,T3,T4,T5", "comma-separated checks to run")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	o := Options{Root: *root, MigrationsDir: *migrations, RegistryPath: *reg, Out: os.Stdout, Checks: map[string]bool{}}
	for _, v := range strings.Split(*versions, ",") {
		if v = strings.TrimSpace(v); v != "" {
			o.Versions = append(o.Versions, v)
		}
	}
	for _, k := range strings.Split(*checks, ",") {
		k = strings.ToUpper(strings.TrimSpace(k))
		switch k {
		case "T1", "T2", "T3", "T4", "T5":
			o.Checks[k] = true
		default:
			fmt.Fprintf(os.Stderr, "fitness-tenancy: unknown check %q (want T1..T5)\n", k)
			os.Exit(2)
		}
	}
	vs, err := Run(ctx, o)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fitness-tenancy:", err)
		os.Exit(2)
	}
	if len(vs) == 0 {
		fmt.Println("fitness-tenancy: ok (" + *checks + ")")
		return
	}
	for _, v := range vs {
		fmt.Fprintln(os.Stderr, v)
	}
	fmt.Fprintf(os.Stderr, "fitness-tenancy: %d violation(s); rules: knowledge/development/decisions/0002-deployment-model.md (Fitness function)\n", len(vs))
	os.Exit(1)
}

// Run executes the selected checks and returns every violation, sorted.
func Run(ctx context.Context, o Options) ([]Violation, error) {
	out := func(f string, a ...any) { fmt.Fprintf(o.Out, f+"\n", a...) }
	reg, err := registry.Load(filepath.Join(o.Root, o.RegistryPath))
	if err != nil {
		return nil, err
	}
	ms, nameVs, err := ListMigrations(filepath.Join(o.Root, o.MigrationsDir))
	if err != nil {
		return nil, err
	}
	var all []Violation
	byKey := map[string]*Violation{}
	versionsOf := map[string][]string{}
	record := func(version string, vs []Violation) {
		for _, v := range vs {
			k := v.String()
			if _, ok := byKey[k]; !ok {
				vv := v
				byKey[k] = &vv
			}
			versionsOf[k] = append(versionsOf[k], version)
		}
	}

	if o.Checks["T1"] || o.Checks["T2"] || o.Checks["T3"] || o.Checks["T4"] {
		if len(o.Servers) == 0 {
			if err := dockerAvailable(ctx); err != nil {
				return nil, err
			}
		}
		servers, release, err := startServers(ctx, o)
		if err != nil {
			return nil, err
		}
		defer release()
		if len(ms) == 0 {
			out("T1 migration-1: no migration yet (activates with the first file in %s/); T2–T4 run on an empty schema", o.MigrationsDir)
		}
		for _, ver := range o.Versions {
			s := servers[ver]
			out("fitness-tenancy: PostgreSQL %s (%s)", ver, s.Image)
			vs, err := checkVersion(ctx, s, o, reg, ms, nameVs, out)
			if err != nil {
				return nil, fmt.Errorf("PostgreSQL %s: %w", ver, err)
			}
			record(ver, vs)
		}
	}
	if o.Checks["T5"] {
		vs, err := checkT5(ctx, o, reg, out)
		if err != nil {
			return nil, err
		}
		record("", vs)
	}
	for k, v := range byKey {
		if vers := versionsOf[k]; len(vers) > 0 && vers[0] != "" {
			v.Msg += " (PostgreSQL " + strings.Join(vers, ", ") + ")"
		}
		all = append(all, *v)
	}
	sortViolations(all)
	return all, nil
}

func startServers(ctx context.Context, o Options) (map[string]*Server, func(), error) {
	servers := map[string]*Server{}
	var started []*Server
	var mu sync.Mutex
	var wg sync.WaitGroup
	var firstErr error
	for _, ver := range o.Versions {
		if s := o.Servers[ver]; s != nil {
			servers[ver] = s
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, err := StartServer(ctx, ver, o.ExtraBootstrap)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				return
			}
			servers[ver] = s
			started = append(started, s)
		}()
	}
	wg.Wait()
	release := func() {
		for _, s := range started {
			s.Stop()
		}
	}
	if firstErr != nil {
		release()
		return nil, nil, firstErr
	}
	return servers, release, nil
}

// checkVersion runs T1–T4 on one server.
func checkVersion(ctx context.Context, s *Server, o Options, reg *registry.Registry, ms []Migration, nameVs []Violation, out func(string, ...any)) ([]Violation, error) {
	var vs []Violation
	report := func(check, what string, add []Violation) {
		status := "ok"
		if len(add) > 0 {
			status = fmt.Sprintf("FAILED (%d)", len(add))
		}
		out("  %s %-28s %s", check, what, status)
		vs = append(vs, add...)
	}
	if o.Checks["T1"] {
		t1, err := checkT1(ctx, s, ms, nameVs)
		if err != nil {
			return nil, err
		}
		if len(ms) == 0 {
			out("  T1 %-28s skipped (no migration yet)", "migration 1 creates tenants")
			vs = append(vs, t1...)
		} else {
			report("T1", "migration 1 creates tenants", t1)
		}
	}
	if !(o.Checks["T2"] || o.Checks["T3"] || o.Checks["T4"]) {
		return vs, nil
	}
	d, err := s.NewDatabase(ctx)
	if err != nil {
		return nil, err
	}
	defer d.Drop(ctx)
	if av := apply(ctx, d, ms); len(av) > 0 {
		report("T1", "all migrations apply", av)
		return vs, nil
	}
	t2, model, err := checkT2(ctx, d, reg)
	if err != nil {
		return nil, err
	}
	if o.Checks["T2"] {
		report("T2", fmt.Sprintf("catalog (%d tables)", len(model.tables)), t2)
	}
	if o.Checks["T3"] {
		t3, err := checkT3(ctx, d, model)
		if err != nil {
			return nil, err
		}
		report("T3", "roles", t3)
	}
	if o.Checks["T4"] {
		t4, n, err := checkT4(ctx, d, model, reg, out)
		if err != nil {
			return nil, err
		}
		sql20, err := checkSQL20(ctx, o.Root)
		if err != nil {
			return nil, err
		}
		report("T4", fmt.Sprintf("isolation probes (%d)", n), append(t4, sql20...))
	}
	return vs, nil
}

// checkT5 runs the go/analysis rules, the .sql and OpenAPI scans and the registry staleness check.
func checkT5(ctx context.Context, o Options, reg *registry.Registry, out func(string, ...any)) ([]Violation, error) {
	module, err := modulePath(filepath.Join(o.Root, "go.mod"))
	if err != nil {
		return nil, err
	}
	fs, err := static.Run(o.Root, static.DefaultConfig(module, reg))
	if err != nil {
		return nil, err
	}
	var vs []Violation
	for _, f := range fs {
		where := f.File
		if f.Line > 0 {
			where = fmt.Sprintf("%s:%d", f.File, f.Line)
		}
		vs = append(vs, Violation{"T5", f.Rule, where, f.Msg})
	}
	status := "ok"
	if len(vs) > 0 {
		status = fmt.Sprintf("FAILED (%d)", len(vs))
	}
	_, openapi, _ := static.CheckOpenAPI(o.Root)
	note := ""
	if !openapi {
		note = " (OpenAPI rule activates with api/openapi/)"
	}
	out("T5 %-31s %s%s", "static (go/analysis, SQL, OpenAPI)", status, note)
	return vs, nil
}

func modulePath(gomod string) (string, error) {
	f, err := os.Open(gomod)
	if err != nil {
		return "", err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(sc.Text()), "module "); ok {
			return strings.Trim(strings.TrimSpace(rest), `"`), nil
		}
	}
	return "", fmt.Errorf("no module line in %s", gomod)
}

// sql20Test is the test the data-access package must carry (safe-primitives SQL-20): constructing the
// pool from a DSN with default_query_exec_mode=simple_protocol fails.
const sql20Test = "TestPoolRefusesSimpleProtocol"

// checkSQL20 activates when internal/platform/store has Go files: that package must hold the SQL-20
// test and it must pass. The runtime part of SQL-20 belongs to the pool constructor, which this job
// cannot call without knowing its API, so it runs the package's own test and demands that it ran.
func checkSQL20(ctx context.Context, root string) ([]Violation, error) {
	dir := filepath.Join(root, static.DefaultConfig("", nil).StoreDir)
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil
	}
	hasGo := false
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".go") && !strings.HasSuffix(e.Name(), "_test.go") {
			hasGo = true
		}
	}
	if !hasGo {
		return nil, nil
	}
	cmd := exec.CommandContext(ctx, "go", "test", "-count=1", "-json", "-run", "^"+sql20Test+"$", "./"+filepath.ToSlash(static.DefaultConfig("", nil).StoreDir))
	cmd.Dir = root
	b, _ := cmd.Output()
	passed, ran := false, false
	dec := json.NewDecoder(strings.NewReader(string(b)))
	for dec.More() {
		var ev struct{ Action, Test string }
		if dec.Decode(&ev) != nil {
			break
		}
		if ev.Test == sql20Test {
			ran = true
			if ev.Action == "pass" {
				passed = true
			}
			if ev.Action == "fail" {
				passed = false
			}
		}
	}
	where := static.DefaultConfig("", nil).StoreDir
	switch {
	case !ran:
		return []Violation{{"T4", "sql-20", where, "no test " + sql20Test + ": the pool must refuse default_query_exec_mode=simple_protocol (SQL-20)"}}, nil
	case !passed:
		return []Violation{{"T4", "sql-20", where, sql20Test + " fails: the pool accepts default_query_exec_mode=simple_protocol (SQL-20)"}}, nil
	}
	return nil, nil
}

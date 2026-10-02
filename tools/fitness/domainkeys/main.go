// Command domainkeys is the fitness-domain-keys job (T-0050): it makes the cross-cutting invariants of
// the domain model (domain-model.md §0) fail the build instead of relying on review.
//
//	X3  a directory (D) table is never keyed, uniquely indexed or joined on a DN, SID, sAMAccountName,
//	    UPN or name: directory objects are (tenant_id, connection_id, object_guid)
//	X4  no column is named for, or annotated as holding, a SecretAttrs attribute, except the sealed
//	    (bytea) columns a table declares
//	X5  an append-only table (ChangeRecord, AuditEvent, ApprovalDecision, ChainCheckpoint,
//	    ConnectionVerification and its findings, SyncCycle and its DC observations, the insert-only
//	    Tier0Override) is never updated by any role but its owner, is deleted only by the retention
//	    role, and has no lifecycle-state column; and the DM-25.I6 retention property test exists
//	REG every table is declared (kind P, T or D, entity, append-only) in code through
//	    tablekind.Declare, the declarations agree with the domain model's headings and with the tenancy
//	    exemption registry, and nothing declared is stale
//
// The table-to-kind map is the set of tablekind.Declare calls in the Go source, read without building
// it; there is no list in this job. The schema checked is the real migrations applied, as the owner role,
// to throw-away PostgreSQL containers (the harness of fitness-tenancy, tools/fitness/pgharness).
// Rules and the declaration format: knowledge/development/architecture/domain-keys-fitness.md.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"

	"github.com/skenzeriq/activediq/internal/directory/attr/secretattr"
	"github.com/skenzeriq/activediq/tools/fitness/pgharness"
	"github.com/skenzeriq/activediq/tools/fitness/tenancy/registry"
)

// DefaultRetentionRole is the one role allowed to DELETE append-only records (domain-model.md DM-18,
// DM-80: "the retention role"). Nothing creates it yet; the check only exempts the name.
const DefaultRetentionRole = "activediq_retention"

// DefaultDomainModel is where the domain model lives, relative to the repository root.
const DefaultDomainModel = "knowledge/development/domain/domain-model.md"

// Violation is one failed rule. Check is X3, X4, X5 or REG; Rule names the rule; Where is the table,
// column, index or file:line it failed on.
type Violation struct{ Check, Rule, Where, Msg string }

func (v Violation) String() string {
	return fmt.Sprintf("%s %s [%s]: %s", v.Check, v.Where, v.Rule, v.Msg)
}

// Options configures one run.
type Options struct {
	Root            string
	MigrationsDir   string // relative to Root
	RegistryPath    string // tenancy exemption registry, relative to Root
	DomainModelPath string // relative to Root
	RetentionRole   string
	Versions        []string
	Out             io.Writer
	// ExtraBootstrap is superuser SQL run in every new database (owner role %1$I, runtime role %2$I).
	// Tests use it to give a role a power the checks must catch.
	ExtraBootstrap []string
	// Servers lets a caller (the tests) supply running servers by major version; they are not stopped.
	Servers map[string]*pgharness.Server
}

func main() {
	root := flag.String("root", ".", "repository root (the directory holding go.mod)")
	migrations := flag.String("migrations", "migrations", "migrations directory, relative to -root")
	reg := flag.String("registry", registry.DefaultPath, "tenancy exemption registry (JSON), relative to -root")
	model := flag.String("domain-model", DefaultDomainModel, "domain model document, relative to -root")
	retention := flag.String("retention-role", DefaultRetentionRole, "the role that may DELETE append-only records")
	versions := flag.String("pg", "16,18", "PostgreSQL major versions to run against")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	o := Options{Root: *root, MigrationsDir: *migrations, RegistryPath: *reg, DomainModelPath: *model, RetentionRole: *retention, Out: os.Stdout}
	for _, v := range strings.Split(*versions, ",") {
		if v = strings.TrimSpace(v); v != "" {
			o.Versions = append(o.Versions, v)
		}
	}
	vs, err := Run(ctx, o)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fitness-domain-keys:", err)
		os.Exit(2)
	}
	if len(vs) == 0 {
		fmt.Println("fitness-domain-keys: ok (X3, X4, X5, REG)")
		return
	}
	for _, v := range vs {
		fmt.Fprintln(os.Stderr, v)
	}
	fmt.Fprintf(os.Stderr, "fitness-domain-keys: %d violation(s); rules: knowledge/development/architecture/domain-keys-fitness.md\n", len(vs))
	os.Exit(1)
}

// Run executes the check and returns every violation, sorted.
func Run(ctx context.Context, o Options) ([]Violation, error) {
	out := func(f string, a ...any) { fmt.Fprintf(o.Out, f+"\n", a...) }
	module, err := modulePath(filepath.Join(o.Root, "go.mod"))
	if err != nil {
		return nil, err
	}
	reg, err := registry.Load(filepath.Join(o.Root, o.RegistryPath))
	if err != nil {
		return nil, err
	}
	entities, err := LoadEntities(filepath.Join(o.Root, o.DomainModelPath))
	if err != nil {
		return nil, err
	}
	src, vs, err := ScanSource(o.Root, module)
	if err != nil {
		return nil, err
	}
	vs = append(vs, checkDeclarations(src, entities)...)
	status := "ok"
	if len(vs) > 0 {
		status = fmt.Sprintf("FAILED (%d)", len(vs))
	}
	out("fitness-domain-keys: %d declaration(s) in source: %s", len(src.Decls), status)

	ms, nameProblems, err := pgharness.ListMigrations(filepath.Join(o.Root, o.MigrationsDir))
	if err != nil {
		return nil, err
	}
	for _, p := range nameProblems {
		vs = append(vs, Violation{"REG", "migration-name", p.File, p.Msg})
	}
	global := map[string]bool{}
	for _, g := range reg.GlobalTables {
		global[g.Table] = true
	}
	co := catalogOptions{runtimeRole: pgharness.DefaultRuntimeRole, retentionRole: o.RetentionRole, secretAttrs: secretattr.Static(), globalTables: global}

	if len(o.Servers) == 0 {
		if err := pgharness.DockerAvailable(ctx); err != nil {
			return nil, err
		}
	}
	servers, release, err := pgharness.StartServers(ctx, o.Versions, o.Servers, o.ExtraBootstrap)
	if err != nil {
		return nil, err
	}
	defer release()
	seen := map[string]*Violation{}
	versionsOf := map[string][]string{}
	for _, ver := range o.Versions {
		s := servers[ver]
		out("fitness-domain-keys: PostgreSQL %s (%s)", ver, s.Image)
		cv, n, err := checkVersion(ctx, s, ms, src.Decls, co)
		if err != nil {
			return nil, fmt.Errorf("PostgreSQL %s: %w", ver, err)
		}
		st := "ok"
		if len(cv) > 0 {
			st = fmt.Sprintf("FAILED (%d)", len(cv))
		}
		out("  X3/X4/X5 over %d table(s) %s", n, st)
		for _, v := range cv {
			k := v.String()
			if _, ok := seen[k]; !ok {
				vv := v
				seen[k] = &vv
			}
			versionsOf[k] = append(versionsOf[k], ver)
		}
	}
	for k, v := range seen {
		if vers := versionsOf[k]; len(vers) > 0 && len(vers) < len(o.Versions) {
			v.Msg += " (PostgreSQL " + strings.Join(vers, ", ") + ")"
		}
		vs = append(vs, *v)
	}
	sort.SliceStable(vs, func(i, j int) bool {
		a, b := vs[i], vs[j]
		if a.Check != b.Check {
			return a.Check < b.Check
		}
		if a.Where != b.Where {
			return a.Where < b.Where
		}
		return a.Rule < b.Rule
	})
	return vs, nil
}

// checkVersion applies the migrations to a fresh database on s and checks the schema.
func checkVersion(ctx context.Context, s *pgharness.Server, ms []pgharness.Migration, decls []Declaration, co catalogOptions) ([]Violation, int, error) {
	d, err := s.NewDatabase(ctx)
	if err != nil {
		return nil, 0, err
	}
	defer d.Drop(ctx)
	failed, msg, err := pgharness.Apply(ctx, d, ms)
	if err != nil {
		return nil, 0, err
	}
	if failed != "" {
		return []Violation{{"REG", "migrations-apply", failed, "does not apply on an empty database as the migration role: " + msg}}, 0, nil
	}
	return checkCatalog(ctx, d, decls, co)
}

// property is a test the fitness suite demands once its entity has a table (domain-model.md: "listed for
// the T-0050 fitness check"). The test is a top-level function named Test<Prefix> in any _test.go file
// under internal/ or cmd/.
type property struct {
	Entity, Invariant, Test, Text string
}

var requiredProperties = []property{
	{"DM-25", "I6", "TestProperty_DM25_I6",
		"no retention pass, and no crash at any point inside one, changes the derived state of any override still kept (in_force, cleared, superseded, ended), cleared_by_verification_id, superseded_by or ended_at, or the result of DM-10.I9 or I11"},
}

// checkDeclarations applies the rules that need no database: validity, uniqueness, agreement with the
// domain model's headings, and the required property tests.
func checkDeclarations(src *Source, entities map[string]Entity) []Violation {
	var vs []Violation
	names := map[string]string{}
	for _, d := range src.Decls {
		if prev, dup := names[d.Name]; dup {
			vs = append(vs, Violation{"REG", "declaration-duplicate", d.Name, "declared at " + prev + " and again at " + d.Pos})
		}
		names[d.Name] = d.Pos
		e, ok := entities[d.Entity]
		switch {
		case !ok:
			vs = append(vs, Violation{"REG", "entity-unknown", d.Name, d.Pos + ": " + d.Entity + " is not an entity heading of the domain model"})
			continue
		case e.Kind != "" && e.Kind != string(d.Kind):
			vs = append(vs, Violation{"REG", "kind-mismatch", d.Name, fmt.Sprintf("%s: declared kind %s, but the domain model says %s %s is kind %s (a registry entity has no table)", d.Pos, d.Kind, e.ID, e.Name, e.Kind)})
		}
		if e.AppendOnly && !d.AppendOnly {
			vs = append(vs, Violation{"REG", "append-only-missing", d.Name, fmt.Sprintf("%s: %s %s is append-only or insert-only in the domain model (X5), so its tables are declared AppendOnly: true", d.Pos, e.ID, e.Name)})
		}
		if !e.AppendOnly && d.AppendOnly {
			vs = append(vs, Violation{"REG", "append-only-unfounded", d.Name, fmt.Sprintf("%s: declared AppendOnly, but %s %s is not append-only in the domain model; change the model first", d.Pos, e.ID, e.Name)})
		}
	}
	for _, p := range requiredProperties {
		needed := false
		for _, d := range src.Decls {
			needed = needed || d.Entity == p.Entity
		}
		if !needed {
			continue
		}
		found := false
		for name := range src.Tests {
			found = found || name == p.Test || strings.HasPrefix(name, p.Test+"_")
		}
		if !found {
			vs = append(vs, Violation{"X5", "property-missing", p.Entity + "." + p.Invariant,
				fmt.Sprintf("%s has a table but no test function named %s (or %s_…) exists under internal/ or cmd/: the retention property is required (%s)", p.Entity, p.Test, p.Test, p.Text)})
		}
	}
	return vs
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

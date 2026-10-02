// Package storetest is test support for code that talks to PostgreSQL: it starts throw-away PostgreSQL 16
// and 18 containers (ADR-0001: bundled 18, customer-supplied 16 or later) and hands tests an empty
// database provisioned like an install: two roles, activediq_owner and activediq_app, and a database the
// owner owns. Nothing is mocked: PostgreSQL is never mocked (testing-playbook).
//
// Usage, in each test package that needs a database:
//
//	func TestMain(m *testing.M) { os.Exit(storetest.Main(m)) }
//
//	func TestX(t *testing.T) {
//		storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
//			db := s.NewDatabase(t)
//			db.Migrate(t) // the product's own migrations, as the owner role
//			...
//		})
//	}
//
// It needs Docker. With no daemon the tests skip locally and fail when CI is set, so a pipeline can
// never go green by not running them. ACTIVEDIQ_TEST_PG_VERSIONS (for example "18") restricts the
// versions; ACTIVEDIQ_TEST_PG_IMAGE_16 / _18 override an image (a mirror, an air-gapped runner).
//
// The image pins match tools/fitness/tenancy/pgenv.go: bump both together.
package storetest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/skenzeriq/activediq/migrations"
)

// Role names of the bootstrap contract (tenancy-fitness.md). The installer creates the same two roles.
const (
	OwnerRole   = "activediq_owner" // runs migrations, owns every object
	RuntimeRole = "activediq_app"   // the application: owns nothing
)

var images = map[string]string{
	"16": "postgres:16-alpine@sha256:16bc17c64a573ef34162af9298258d1aec548232985b33ed7b1eac33ba35c229",
	"18": "postgres:18@sha256:5a5a84b19854a9ffaa54082c166ff4ec27473a361e496e5ea167f298f2da9722",
}

var (
	mu      sync.Mutex
	servers = map[string]*Server{}
)

// Main runs the package's tests and then removes every container the tests started.
func Main(m *testing.M) int {
	code := m.Run()
	mu.Lock()
	defer mu.Unlock()
	for _, s := range servers {
		s.stop()
	}
	return code
}

// Versions returns the PostgreSQL major versions the tests run against.
func Versions() []string {
	if v := os.Getenv("ACTIVEDIQ_TEST_PG_VERSIONS"); v != "" {
		var out []string
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
		return out
	}
	return []string{"16", "18"}
}

// EachVersion runs fn as a subtest ("pg16", "pg18") against a server of each version.
func EachVersion(t *testing.T, fn func(t *testing.T, s *Server)) {
	t.Helper()
	for _, v := range Versions() {
		t.Run("pg"+v, func(t *testing.T) {
			fn(t, start(t, v))
		})
	}
}

// Server is one PostgreSQL container with the two roles created.
type Server struct {
	Version string
	Image   string

	id, addr  string
	adminPass string
	ownerPass string
	appPass   string
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func start(t *testing.T, version string) *Server {
	t.Helper()
	mu.Lock()
	defer mu.Unlock()
	if s := servers[version]; s != nil {
		return s
	}
	if _, err := exec.LookPath("docker"); err != nil {
		unavailable(t, "docker not found")
	}
	if out, err := exec.Command("docker", "info", "--format", "{{.ServerVersion}}").CombinedOutput(); err != nil {
		unavailable(t, "the Docker daemon is not reachable: "+strings.TrimSpace(string(out)))
	}
	image := os.Getenv("ACTIVEDIQ_TEST_PG_IMAGE_" + version)
	if image == "" {
		image = images[version]
	}
	if image == "" {
		t.Fatalf("storetest: no PostgreSQL image known for major version %q (known: 16, 18)", version)
	}
	s := &Server{Version: version, Image: image, adminPass: randHex(12), ownerPass: randHex(12), appPass: randHex(12)}
	out, err := exec.Command("docker", "run", "-d", "--rm", "-e", "POSTGRES_PASSWORD="+s.adminPass, "-p", "127.0.0.1::5432", image,
		"-c", "fsync=off", "-c", "synchronous_commit=off", "-c", "full_page_writes=off").CombinedOutput()
	if err != nil {
		t.Fatalf("storetest: docker run %s: %s", image, strings.TrimSpace(string(out)))
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	s.id = strings.TrimSpace(lines[len(lines)-1])
	servers[version] = s
	out, err = exec.Command("docker", "port", s.id, "5432/tcp").CombinedOutput()
	if err != nil {
		t.Fatalf("storetest: docker port: %s", strings.TrimSpace(string(out)))
	}
	addr := strings.TrimSpace(strings.Split(string(out), "\n")[0])
	i := strings.LastIndex(addr, ":")
	s.addr = strings.Trim(addr[:i], "[]") + ":" + addr[i+1:]
	s.waitReady(t)
	s.createRoles(t)
	return s
}

func unavailable(t *testing.T, why string) {
	t.Helper()
	if os.Getenv("CI") != "" {
		t.Fatalf("storetest: %s (CI is set: PostgreSQL integration tests must run, not skip)", why)
	}
	t.Skipf("storetest: %s", why)
}

func (s *Server) stop() {
	if s.id != "" {
		_ = exec.Command("docker", "rm", "-f", s.id).Run()
		s.id = ""
	}
}

func (s *Server) dsn(user, pass, db string) string {
	i := strings.LastIndex(s.addr, ":")
	return fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable", s.addr[:i], s.addr[i+1:], user, pass, db)
}

func (s *Server) connect(ctx context.Context, user, pass, db string) (*pgx.Conn, error) {
	cfg, err := pgx.ParseConfig(s.dsn(user, pass, db))
	if err != nil {
		return nil, err
	}
	return pgx.ConnectConfig(ctx, cfg)
}

func (s *Server) waitReady(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	deadline := time.Now().Add(90 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		// The image's entrypoint first runs a temporary server that listens on a socket only, so a TCP
		// connection that answers is the real server.
		c, err := s.connect(ctx, "postgres", s.adminPass, "postgres")
		if err == nil {
			var one int
			err = c.QueryRow(ctx, "SELECT 1").Scan(&one)
			_ = c.Close(ctx)
			if err == nil {
				return
			}
		}
		last = err
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("storetest: PostgreSQL %s did not become ready: %v", s.Version, last)
}

func (s *Server) createRoles(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	c, err := s.connect(ctx, "postgres", s.adminPass, "postgres")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(ctx)
	for _, r := range []struct{ name, pass string }{{OwnerRole, s.ownerPass}, {RuntimeRole, s.appPass}} {
		// CREATE ROLE takes no bind parameters: the name and password are quoted server-side.
		var stmt string
		if err := c.QueryRow(ctx, `SELECT format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD %L', $1::text, $2::text)`,
			r.name, r.pass).Scan(&stmt); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Exec(ctx, stmt); err != nil {
			t.Fatalf("storetest: create role %s: %v", r.name, err)
		}
	}
}

// Database is one empty database owned by the owner role. Nothing is in it until Migrate.
type Database struct {
	Name string
	s    *Server
}

// NewDatabase creates a database for one test and drops it when the test ends.
func (s *Server) NewDatabase(t testing.TB) *Database {
	t.Helper()
	ctx := context.Background()
	name := "t_" + randHex(6)
	a, err := s.connect(ctx, "postgres", s.adminPass, "postgres")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close(ctx)
	var stmt string
	if err := a.QueryRow(ctx, `SELECT format('CREATE DATABASE %I OWNER %I', $1::text, $2::text)`, name, OwnerRole).Scan(&stmt); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Exec(ctx, stmt); err != nil {
		t.Fatalf("storetest: create database: %v", err)
	}
	d := &Database{Name: name, s: s}
	t.Cleanup(func() {
		c, err := s.connect(ctx, "postgres", s.adminPass, "postgres")
		if err != nil {
			return
		}
		defer c.Close(ctx)
		var drop string
		if c.QueryRow(ctx, `SELECT format('DROP DATABASE IF EXISTS %I WITH (FORCE)', $1::text)`, name).Scan(&drop) == nil {
			_, _ = c.Exec(ctx, drop)
		}
	})
	return d
}

// AppDSN connects as the runtime role. OwnerDSN connects as the migration role. AdminDSN connects as the
// superuser, for tests that must break the rules on purpose.
func (d *Database) AppDSN() string   { return d.s.dsn(RuntimeRole, d.s.appPass, d.Name) }
func (d *Database) OwnerDSN() string { return d.s.dsn(OwnerRole, d.s.ownerPass, d.Name) }
func (d *Database) AdminDSN() string { return d.s.dsn("postgres", d.s.adminPass, d.Name) }

// Owner, App and Admin open a single connection as that role. The caller closes it.
func (d *Database) Owner(ctx context.Context) (*pgx.Conn, error) {
	return d.s.connect(ctx, OwnerRole, d.s.ownerPass, d.Name)
}

func (d *Database) App(ctx context.Context) (*pgx.Conn, error) {
	return d.s.connect(ctx, RuntimeRole, d.s.appPass, d.Name)
}

func (d *Database) Admin(ctx context.Context) (*pgx.Conn, error) {
	return d.s.connect(ctx, "postgres", d.s.adminPass, d.Name)
}

// Migrate applies the product's embedded migrations in order, as the owner role, each file as one
// multi-statement execution, exactly as fitness-tenancy does.
func (d *Database) Migrate(t testing.TB) {
	t.Helper()
	if err := d.Apply(context.Background(), migrations.FS); err != nil {
		t.Fatal(err)
	}
}

// Apply runs every *.sql file of fsys, in name order, as the owner role.
func (d *Database) Apply(ctx context.Context, fsys fs.FS) error {
	names, err := fs.Glob(fsys, "*.sql")
	if err != nil {
		return err
	}
	sort.Strings(names)
	c, err := d.Owner(ctx)
	if err != nil {
		return err
	}
	defer c.Close(ctx)
	for _, n := range names {
		b, err := fs.ReadFile(fsys, n)
		if err != nil {
			return err
		}
		// No arguments: pgx sends the whole file through the simple protocol, which allows many
		// statements. The file is repository content, not input.
		if _, err := c.Exec(ctx, string(b)); err != nil {
			return fmt.Errorf("migration %s: %w", n, err)
		}
	}
	return nil
}

// ExecOwner runs one statement as the owner role, which owns every object and runs DDL in tests. The
// statement is test fixture text, never input.
func (d *Database) ExecOwner(ctx context.Context, sql string, args ...any) error {
	c, err := d.Owner(ctx)
	if err != nil {
		return err
	}
	defer c.Close(ctx)
	_, err = c.Exec(ctx, sql, args...)
	return err
}

// OwnerStrings runs one query as the owner role and returns the first column of every row as text.
// The statement is test fixture text, never input.
func (d *Database) OwnerStrings(ctx context.Context, sql string, args ...any) ([]string, error) {
	c, err := d.Owner(ctx)
	if err != nil {
		return nil, err
	}
	defer c.Close(ctx)
	rows, err := c.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// Breach is one way a customer's DBA or installer can break the runtime/migration role split, and a
// fixture to reproduce it. Setup and Teardown are SQL fixture text run as the superuser, one statement
// each; "{db}" stands for the test database's name. Want is what the refusal must say.
type Breach struct {
	Name     string
	Setup    []string
	Teardown []string
	Want     string
}

// Breaches lists the ways the runtime role can reach privilege it must not have, including the ones that
// only work through SET ROLE (a membership WITH INHERIT FALSE) or through ownership and CREATE rather
// than the role's own attributes. Both the migration guard and store.Open must refuse every one.
func Breaches() []Breach {
	return []Breach{
		{Name: "inherits the owner", Setup: []string{`GRANT activediq_owner TO activediq_app WITH INHERIT TRUE`},
			Teardown: []string{`REVOKE activediq_owner FROM activediq_app`}, Want: "member"},
		{Name: "member of the owner WITH INHERIT FALSE", Setup: []string{`GRANT activediq_owner TO activediq_app WITH INHERIT FALSE`},
			Teardown: []string{`REVOKE activediq_owner FROM activediq_app`}, Want: "member"},
		{Name: "member of a superuser WITH INHERIT FALSE", Setup: []string{`CREATE ROLE adq_breach_su NOLOGIN SUPERUSER`, `GRANT adq_breach_su TO activediq_app WITH INHERIT FALSE`},
			Teardown: []string{`DROP ROLE adq_breach_su`}, Want: "superuser"},
		{Name: "member of a BYPASSRLS role WITH INHERIT FALSE", Setup: []string{`CREATE ROLE adq_breach_rls NOLOGIN BYPASSRLS`, `GRANT adq_breach_rls TO activediq_app WITH INHERIT FALSE`},
			Teardown: []string{`DROP ROLE adq_breach_rls`}, Want: "BYPASSRLS"},
		{Name: "member of a role that can create in public", Setup: []string{`CREATE ROLE adq_breach_cr NOLOGIN`, `GRANT CREATE ON SCHEMA public TO adq_breach_cr`, `GRANT adq_breach_cr TO activediq_app WITH INHERIT FALSE`},
			Teardown: []string{`REVOKE CREATE ON SCHEMA public FROM adq_breach_cr`, `DROP ROLE adq_breach_cr`}, Want: "CREATE"},
		{Name: "owns the database", Setup: []string{`ALTER DATABASE {db} OWNER TO activediq_app`},
			Teardown: []string{`ALTER DATABASE {db} OWNER TO activediq_owner`}, Want: "database"},
		{Name: "has CREATE on public", Setup: []string{`GRANT CREATE ON SCHEMA public TO activediq_app`},
			Teardown: []string{`REVOKE CREATE ON SCHEMA public FROM activediq_app`}, Want: "CREATE"},
	}
}

// Break applies the breach as the superuser and registers its teardown for the end of the test, so the
// cluster-level roles and grants it touches never leak into the next test.
func (d *Database) Break(t testing.TB, b Breach) {
	t.Helper()
	ctx := context.Background()
	run := func(stmts []string) error {
		c, err := d.Admin(ctx)
		if err != nil {
			return err
		}
		defer c.Close(ctx)
		for _, s := range stmts {
			// Fixture text; the only substitution is the generated database name (t_ + hex).
			if _, err := c.Exec(ctx, strings.ReplaceAll(s, "{db}", d.Name)); err != nil {
				return fmt.Errorf("%s: %w", s, err)
			}
		}
		return nil
	}
	t.Cleanup(func() { _ = run(b.Teardown) })
	if err := run(b.Setup); err != nil {
		t.Fatal(err)
	}
}

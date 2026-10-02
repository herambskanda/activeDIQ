package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Role names of the bootstrap contract. The installer (T-0037) creates the same two roles; the job
// provisions them the same way so a migration written under the job runs unchanged in production.
const (
	DefaultOwnerRole   = "activediq_owner" // runs migrations, owns every object, is neither superuser nor BYPASSRLS
	DefaultRuntimeRole = "activediq_app"   // the application: owns nothing, has no BYPASSRLS, no TRUNCATE, no CREATE
)

// defaultImages pins the PostgreSQL images by index digest (multi-arch), so a run is reproducible and
// a new minor release is an edit that the review sees. FITNESS_TENANCY_IMAGE_<major> overrides one.
var defaultImages = map[string]string{
	"16": "postgres:16-alpine@sha256:16bc17c64a573ef34162af9298258d1aec548232985b33ed7b1eac33ba35c229",
	"18": "postgres:18@sha256:5a5a84b19854a9ffaa54082c166ff4ec27473a361e496e5ea167f298f2da9722",
}

// Server is one ephemeral PostgreSQL container.
type Server struct {
	Version string
	Image   string

	id        string
	addr      string // host:port on the loopback interface
	adminPass string
	ownerRole string
	appRole   string
	ownerPass string
	appPass   string
	extraBoot []string
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand does not fail on supported platforms
	}
	return hex.EncodeToString(b)
}

// dockerAvailable reports whether a Docker daemon answers.
func dockerAvailable(ctx context.Context) error {
	if _, err := exec.LookPath("docker"); err != nil {
		return errors.New("docker not found: fitness-tenancy runs against ephemeral PostgreSQL containers")
	}
	if out, err := exec.CommandContext(ctx, "docker", "info", "--format", "{{.ServerVersion}}").CombinedOutput(); err != nil {
		return fmt.Errorf("the Docker daemon is not reachable: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// StartServer starts PostgreSQL <version> in a throw-away container on a random loopback port, waits
// until it accepts TCP connections and creates the two roles. The caller must Stop it.
func StartServer(ctx context.Context, version string, extraBootstrap []string) (*Server, error) {
	image := os.Getenv("FITNESS_TENANCY_IMAGE_" + version)
	if image == "" {
		image = defaultImages[version]
	}
	if image == "" {
		return nil, fmt.Errorf("no PostgreSQL image known for major version %q (known: 16, 18)", version)
	}
	s := &Server{
		Version: version, Image: image, adminPass: randHex(12), ownerPass: randHex(12), appPass: randHex(12),
		ownerRole: DefaultOwnerRole, appRole: DefaultRuntimeRole, extraBoot: extraBootstrap,
	}
	// fsync and friends off: the container is thrown away, and the probes write thousands of rows.
	out, err := exec.CommandContext(ctx, "docker", "run", "-d", "--rm",
		"-e", "POSTGRES_PASSWORD="+s.adminPass, "-p", "127.0.0.1::5432", image,
		"-c", "fsync=off", "-c", "synchronous_commit=off", "-c", "full_page_writes=off").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("docker run %s: %s", image, strings.TrimSpace(string(out)))
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	s.id = strings.TrimSpace(lines[len(lines)-1])
	out, err = exec.CommandContext(ctx, "docker", "port", s.id, "5432/tcp").CombinedOutput()
	if err != nil {
		s.Stop()
		return nil, fmt.Errorf("docker port: %s", strings.TrimSpace(string(out)))
	}
	s.addr = strings.TrimSpace(strings.Split(string(out), "\n")[0])
	if err := s.waitReady(ctx); err != nil {
		s.Stop()
		return nil, err
	}
	if err := s.createRoles(ctx); err != nil {
		s.Stop()
		return nil, err
	}
	return s, nil
}

// Stop removes the container (it was started with --rm).
func (s *Server) Stop() {
	if s.id == "" {
		return
	}
	_ = exec.Command("docker", "rm", "-f", s.id).Run()
	s.id = ""
}

func (s *Server) dsn(user, pass, db string) string {
	host, port, _ := strings.Cut(s.addr, ":")
	if i := strings.LastIndex(s.addr, ":"); i >= 0 {
		host, port = s.addr[:i], s.addr[i+1:]
	}
	host = strings.Trim(host, "[]")
	return fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable", host, port, user, pass, db)
}

func (s *Server) connect(ctx context.Context, user, pass, db string) (*pgx.Conn, error) {
	cfg, err := pgx.ParseConfig(s.dsn(user, pass, db))
	if err != nil {
		return nil, err
	}
	return pgx.ConnectConfig(ctx, cfg)
}

func (s *Server) waitReady(ctx context.Context) error {
	deadline := time.Now().Add(90 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		// The image's entrypoint first runs a temporary server that listens on a socket only, so a
		// TCP connection that answers is the real, final server.
		c, err := s.connect(ctx, "postgres", s.adminPass, "postgres")
		if err == nil {
			var one int
			err = c.QueryRow(ctx, "SELECT 1").Scan(&one)
			_ = c.Close(ctx)
			if err == nil {
				return nil
			}
		}
		last = err
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(300 * time.Millisecond):
		}
	}
	return fmt.Errorf("PostgreSQL %s did not become ready: %v", s.Version, last)
}

func (s *Server) createRoles(ctx context.Context) error {
	c, err := s.connect(ctx, "postgres", s.adminPass, "postgres")
	if err != nil {
		return err
	}
	defer c.Close(ctx)
	for _, r := range []struct{ name, pass string }{{s.ownerRole, s.ownerPass}, {s.appRole, s.appPass}} {
		// CREATE ROLE takes no bind parameters: the name is quoted as an identifier, and the password
		// is set through set_config-free server-side quoting with quote_literal.
		var stmt string
		if err := c.QueryRow(ctx,
			`SELECT format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD %L', $1::text, $2::text)`,
			r.name, r.pass).Scan(&stmt); err != nil {
			return err
		}
		if _, err := c.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("create role %s: %w", r.name, err)
		}
	}
	return nil
}

// Database is one fresh database on the server with the bootstrap applied.
type Database struct {
	Name string
	s    *Server
}

// NewDatabase creates an empty database owned by the owner role and applies the bootstrap contract:
// the owner owns schema public; the runtime role may use it, and gets DML (never TRUNCATE) on every
// table and USAGE on every sequence the owner creates there, and nobody but the owner may create
// temporary objects.
func (s *Server) NewDatabase(ctx context.Context) (*Database, error) {
	name := "fit_" + randHex(6)
	a, err := s.connect(ctx, "postgres", s.adminPass, "postgres")
	if err != nil {
		return nil, err
	}
	var stmt string
	if err := a.QueryRow(ctx, `SELECT format('CREATE DATABASE %I OWNER %I', $1::text, $2::text)`, name, s.ownerRole).Scan(&stmt); err != nil {
		_ = a.Close(ctx)
		return nil, err
	}
	_, err = a.Exec(ctx, stmt)
	_ = a.Close(ctx)
	if err != nil {
		return nil, fmt.Errorf("create database: %w", err)
	}
	d := &Database{Name: name, s: s}
	c, err := d.admin(ctx)
	if err != nil {
		return nil, err
	}
	defer c.Close(ctx)
	// TEMPORARY is granted to PUBLIC by default; the contract withholds it from the runtime role. The
	// database name cannot be a bind parameter, so the statement is built with format(%I).
	var revokeTemp string
	if err := c.QueryRow(ctx, `SELECT format('REVOKE TEMPORARY ON DATABASE %I FROM PUBLIC', $1::text)`, name).Scan(&revokeTemp); err != nil {
		return nil, err
	}
	if _, err := c.Exec(ctx, revokeTemp); err != nil {
		return nil, fmt.Errorf("revoke temporary: %w", err)
	}
	boot := []string{
		`ALTER SCHEMA public OWNER TO %1$I`,
		`REVOKE ALL ON SCHEMA public FROM PUBLIC`,
		`GRANT USAGE ON SCHEMA public TO %2$I`,
		`ALTER DEFAULT PRIVILEGES FOR ROLE %1$I IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO %2$I`,
		`ALTER DEFAULT PRIVILEGES FOR ROLE %1$I IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO %2$I`,
	}
	boot = append(boot, s.extraBoot...)
	for _, b := range boot {
		var run string
		if err := c.QueryRow(ctx, `SELECT format($1::text, $2::text, $3::text)`, b, s.ownerRole, s.appRole).Scan(&run); err != nil {
			return nil, err
		}
		if _, err := c.Exec(ctx, run); err != nil {
			return nil, fmt.Errorf("bootstrap %q: %w", b, err)
		}
	}
	return d, nil
}

func (d *Database) admin(ctx context.Context) (*pgx.Conn, error) {
	return d.s.connect(ctx, "postgres", d.s.adminPass, d.Name)
}
func (d *Database) owner(ctx context.Context) (*pgx.Conn, error) {
	return d.s.connect(ctx, d.s.ownerRole, d.s.ownerPass, d.Name)
}
func (d *Database) app(ctx context.Context) (*pgx.Conn, error) {
	return d.s.connect(ctx, d.s.appRole, d.s.appPass, d.Name)
}

// Drop removes the database.
func (d *Database) Drop(ctx context.Context) {
	a, err := d.s.connect(ctx, "postgres", d.s.adminPass, "postgres")
	if err != nil {
		return
	}
	defer a.Close(ctx)
	var stmt string
	if a.QueryRow(ctx, `SELECT format('DROP DATABASE IF EXISTS %I WITH (FORCE)', $1::text)`, d.Name).Scan(&stmt) == nil {
		_, _ = a.Exec(ctx, stmt)
	}
}

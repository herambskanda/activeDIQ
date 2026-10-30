package main

// Every A1 rule has a mutation that breaks only that rule and must be reported (ADR-0005: a check
// without a failing case is not a check). The mutations run on the real migrated schema in a PostgreSQL
// container; without Docker they are skipped locally and fail under CI.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/tools/fitness/pgharness"
)

var (
	srvMu sync.Mutex
	srv   *pgharness.Server
)

func TestMain(m *testing.M) {
	code := m.Run()
	if srv != nil {
		srv.Stop()
	}
	os.Exit(code)
}

func server(t *testing.T) *pgharness.Server {
	t.Helper()
	srvMu.Lock()
	defer srvMu.Unlock()
	if srv != nil {
		return srv
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if err := pgharness.DockerAvailable(ctx); err != nil {
		if os.Getenv("CI") != "" {
			t.Fatalf("Docker is required in CI: %v", err)
		}
		t.Skipf("SKIPPED, NOT PROVEN: %v", err)
	}
	s, err := pgharness.StartServer(ctx, "18", nil)
	if err != nil {
		t.Fatal(err)
	}
	srv = s
	return s
}

func migrations(t *testing.T) []pgharness.Migration {
	t.Helper()
	ms, ps, err := pgharness.ListMigrations(filepath.Join("..", "..", "..", "migrations"))
	if err != nil || len(ps) > 0 || len(ms) == 0 {
		t.Fatalf("migrations: %v %v", err, ps)
	}
	return ms
}

func admin(sql ...string) func(context.Context, *pgharness.Database) error {
	return func(ctx context.Context, d *pgharness.Database) error {
		c, err := d.Admin(ctx)
		if err != nil {
			return err
		}
		defer c.Close(ctx)
		for _, s := range sql {
			if _, err := c.Exec(ctx, s); err != nil {
				return err
			}
		}
		return nil
	}
}

const app = "activediq_app"

func TestA1(t *testing.T) {
	s := server(t)
	ms := migrations(t)
	cases := []struct {
		name   string
		mutate func(context.Context, *pgharness.Database) error
		want   string // substring of the violation; empty means clean
	}{
		{"clean schema", nil, ""},
		{"UPDATE on audit_event", admin(`GRANT UPDATE ON public.audit_event TO ` + app), "audit_event [runtime-privilege]: the runtime role holds UPDATE"},
		{"column UPDATE on audit_event", admin(`GRANT UPDATE (kind) ON public.audit_event TO ` + app), "audit_event [runtime-privilege]: the runtime role holds UPDATE"},
		{"DELETE on audit_event", admin(`GRANT DELETE ON public.audit_event TO ` + app), "audit_event [runtime-privilege]: the runtime role holds DELETE"},
		{"TRUNCATE on audit_checkpoint", admin(`GRANT TRUNCATE ON public.audit_checkpoint TO ` + app), "audit_checkpoint [runtime-privilege]: the runtime role holds TRUNCATE"},
		{"UPDATE on personal_value", admin(`GRANT UPDATE ON public.personal_value TO ` + app), "personal_value [runtime-privilege]: the runtime role holds UPDATE"},
		{"UPDATE on operation_secrets", admin(`GRANT UPDATE ON public.operation_secrets TO ` + app), "operation_secrets [runtime-privilege]: the runtime role holds UPDATE"},
		{"DELETE on audit_head", admin(`GRANT DELETE ON public.audit_head TO ` + app), "audit_head [runtime-privilege]: the runtime role holds DELETE"},
		{"TRUNCATE on audit_head", admin(`GRANT TRUNCATE ON public.audit_head TO ` + app), "audit_head [runtime-privilege]: the runtime role holds TRUNCATE"},
		{"genesis trigger dropped", admin(`DROP TRIGGER audit_head_guard_insert ON public.audit_head`), "audit_head [genesis-trigger]"},
		{"genesis trigger disabled", admin(`ALTER TABLE public.audit_head DISABLE TRIGGER audit_head_guard_insert`), "audit_head [genesis-trigger]"},
		{"trigger accepts any seq", admin(`CREATE OR REPLACE FUNCTION public.audit_head_guard_insert() RETURNS trigger LANGUAGE plpgsql AS $f$ BEGIN NEW.at := now(); RETURN NEW; END $f$`), "audit_head [genesis-seq]"},
		{"trigger accepts any hash", admin(`CREATE OR REPLACE FUNCTION public.audit_head_guard_insert() RETURNS trigger LANGUAGE plpgsql AS $f$ BEGIN IF NEW.seq <> 0 THEN RAISE EXCEPTION 'x' USING ERRCODE='AD403'; END IF; NEW.at := now(); RETURN NEW; END $f$`), "audit_head [genesis-hash]"},
		{"trigger keeps the caller's at", admin(`CREATE OR REPLACE FUNCTION public.audit_head_guard_insert() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $f$ BEGIN
			IF NEW.seq <> 0 OR NEW.hash IS DISTINCT FROM sha256(convert_to('adq-audit-genesis/1', 'UTF8') || '\x00'::bytea || decode(replace(NEW.tenant_id::text, '-', ''), 'hex')) THEN RAISE EXCEPTION 'x' USING ERRCODE='AD403'; END IF;
			RETURN NEW; END $f$`), "audit_head [genesis-at]"},
		{"runtime role owns audit_head", admin(`ALTER TABLE public.audit_head OWNER TO ` + app), "audit_head [owns-audit-head]"},
		{"runtime role is superuser", admin(`ALTER ROLE ` + app + ` SUPERUSER`), activeRole + " [role-superuser]"},
		{"runtime role can set session_replication_role", admin(`GRANT SET ON PARAMETER session_replication_role TO ` + app), app + " [session-replication-role]"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Role attributes and parameter grants are cluster-wide: undo them whatever the case did.
			t.Cleanup(func() {
				ctx := context.Background()
				a, err := s.ConnectAdmin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer a.Close(ctx)
				_, _ = a.Exec(ctx, `ALTER ROLE `+app+` NOSUPERUSER`)
				_, _ = a.Exec(ctx, `REVOKE SET ON PARAMETER session_replication_role FROM `+app)
			})
			vs, err := a1Database(context.Background(), s, ms, c.mutate)
			if err != nil {
				t.Fatal(err)
			}
			var lines []string
			for _, v := range vs {
				lines = append(lines, v.String())
			}
			got := strings.Join(lines, "\n")
			if c.want == "" {
				if len(vs) != 0 {
					t.Fatalf("clean schema reported:\n%s", got)
				}
				return
			}
			if !strings.Contains(got, c.want) {
				t.Fatalf("want a violation containing %q, got:\n%s", c.want, got)
			}
		})
	}
}

const activeRole = app

func TestA1MissingTableFailsClosed(t *testing.T) {
	s := server(t)
	ms := migrations(t)
	vs, err := a1Database(context.Background(), s, ms, admin(`ALTER TABLE public.personal_value RENAME TO personal_value_x`))
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, v := range vs {
		found = found || (v.Rule == "table-missing" && v.Where == "personal_value")
	}
	if !found {
		t.Fatalf("a missing table was not reported: %v", vs)
	}
}

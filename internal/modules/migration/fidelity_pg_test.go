package migration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/modules/migration"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

const (
	tier0OU = "11111111-1111-4111-8111-111111111111"
	plainOU = "22222222-2222-4222-8222-222222222222"
)

// fakeTier0 is the lab's tier0 set: one OU.
type fakeTier0 struct{}

func (fakeTier0) ResolvesTier0(_ context.Context, _ store.Tx, g string) (bool, error) {
	return g == tier0OU, nil
}

var cfg = json.RawMessage(`{"name":"Help desk"}`)

func exact(ref string, grants ...migration.Grant) migration.Item {
	return migration.Item{Ref: ref, Kind: "role", Name: ref, Declared: migration.ClassExact, Config: cfg, Grants: grants}
}

// running submits a job and moves it to running (the release stage is a later ticket).
func (e *env) running(t *testing.T) string { return e.runningAs(t, "ann") }

func (e *env) runningAs(t *testing.T, user string) string {
	t.Helper()
	j, err := e.svc.SubmitJob(context.Background(), e.tid, chain(user), in(e.project(t), 1))
	if err != nil {
		t.Fatal(err)
	}
	e.release(t, j.ID)
	return j.ID
}

// release stands in for the release stage: owner role, inside the tenant (RLS is forced).
func (e *env) release(t *testing.T, jobID string) {
	t.Helper()
	ctx := context.Background()
	c, err := e.d.OwnerForTenant(ctx, e.tid.String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(ctx)
	if tag, err := c.Exec(ctx, `UPDATE public.migration_jobs SET state = 'running' WHERE job_id = $1::uuid`, jobID); err != nil || tag.RowsAffected() != 1 {
		t.Fatalf("release: %v", err)
	}
}

func (e *env) count(t *testing.T, table string) int {
	t.Helper()
	var n int
	err := e.db.WithTenant(context.Background(), e.tid, func(ctx context.Context, tx store.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*)::int FROM public.`+table).Scan(&n) // table is a test constant
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestFidelity(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		ctx := context.Background()

		t.Run("fidelity_script_is_manual", func(t *testing.T) {
			e := setup(t, s)
			job := e.running(t)
			it := exact("auto:1")
			it.Script = `<script>alert(1)</script> Remove-ADUser *`
			out, err := e.svc.RecordFidelity(ctx, e.tid, chain("ann"), migration.RecordFidelityInput{JobID: job, Items: []migration.Item{it}})
			if err != nil {
				t.Fatal(err)
			}
			if out.ByClass["manual"] != 1 || out.Proposals != 0 || e.count(t, "migration_proposals") != 0 {
				t.Fatalf("outcome %+v", out)
			}
			var detail, class string
			_ = e.db.WithTenant(ctx, e.tid, func(ctx context.Context, tx store.Tx) error {
				return tx.QueryRow(ctx, `SELECT class, detail FROM public.migration_fidelity`).Scan(&class, &detail)
			})
			if class != "manual" || strings.Contains(detail, "<script>") || !strings.Contains(detail, "&lt;script&gt;") {
				t.Fatalf("class %q detail %q", class, detail)
			}
			// The audit event never carries the body.
			if b, _ := json.Marshal(e.rec.last()); strings.Contains(string(b), "Remove-ADUser") {
				t.Error("script body reached the audit event")
			}
		})

		t.Run("proposal_never_imports_owner", func(t *testing.T) {
			e := setup(t, s)
			job := e.running(t)
			items := []migration.Item{
				exact("owner", migration.Grant{Permission: "inventory.read", TenantOwner: true}),
				exact("rbac", migration.Grant{Permission: "rbac.assign"}),
				exact("conn", migration.Grant{Permission: "connections.write"}),
				exact("deleg", migration.Grant{Permission: "delegation.manage"}),
				exact("ok", migration.Grant{Permission: "inventory.read", Scope: []string{plainOU}}),
			}
			out, err := e.svc.RecordFidelity(ctx, e.tid, chain("ann"), migration.RecordFidelityInput{JobID: job, Items: items})
			if err != nil {
				t.Fatal(err)
			}
			if out.ByClass["not_supported"] != 4 || out.Proposals != 1 || e.count(t, "migration_proposals") != 1 {
				t.Fatalf("outcome %+v", out)
			}
		})

		t.Run("proposal_tier0_not_supported", func(t *testing.T) {
			e := setup(t, s)
			job := e.running(t)
			out, err := e.svc.RecordFidelity(ctx, e.tid, chain("ann"), migration.RecordFidelityInput{JobID: job, Items: []migration.Item{
				exact("t0", migration.Grant{Permission: "inventory.read", Scope: []string{plainOU, tier0OU}}),
				exact("bad", migration.Grant{Permission: "inventory.read", Scope: []string{"CN=Domain Admins,DC=x"}}),
			}})
			if err != nil {
				t.Fatal(err)
			}
			if out.ByClass["not_supported"] != 2 || out.Proposals != 0 || e.count(t, "migration_proposals") != 0 {
				t.Fatalf("outcome %+v", out)
			}
		})

		t.Run("proposal_is_inert", func(t *testing.T) {
			e := setup(t, s)
			job := e.running(t)
			ev := authz.Evaluator{}
			p := &authz.Principal{ID: "ann"}
			target := authz.Target{}
			before := ev.Authorize(p, nil, "inventory.read", target)
			assignBefore := e.count(t, "authz_assignments")
			if _, err := e.svc.RecordFidelity(ctx, e.tid, chain("ann"), migration.RecordFidelityInput{JobID: job, Items: []migration.Item{
				exact("r", migration.Grant{Permission: "inventory.read", Scope: []string{plainOU}}),
			}}); err != nil {
				t.Fatal(err)
			}
			if e.count(t, "migration_proposals") != 1 {
				t.Fatal("no proposal stored")
			}
			if after := ev.Authorize(p, nil, "inventory.read", target); after.Allowed != before.Allowed || after.Reason != before.Reason || after.Allowed {
				t.Errorf("authz changed: %+v -> %+v", before, after)
			}
			if e.count(t, "authz_assignments") != assignBefore {
				t.Error("an assignment appeared")
			}
			// The proposal is write-once for the runtime role.
			err := e.db.WithTenant(ctx, e.tid, func(ctx context.Context, tx store.Tx) error {
				_, err := tx.Exec(ctx, `UPDATE public.migration_proposals SET grants = '[]'::jsonb`)
				return err
			})
			if err == nil {
				t.Error("proposal updated by the runtime role")
			}
		})

		t.Run("fidelity_export_neutralises_formula", func(t *testing.T) {
			e := setup(t, s)
			job := e.running(t)
			it := exact("=cmd|' /C calc'!A0")
			it.Name = "=cmd|' /C calc'!A0"
			ch := exact("chg")
			ch.Declared = migration.ClassChanged
			ch.Diff = []migration.DiffEntry{{Field: "name", Source: "@SUM(1)", Ours: "-2+3"}}
			if _, err := e.svc.RecordFidelity(ctx, e.tid, chain("ann"), migration.RecordFidelityInput{JobID: job, Items: []migration.Item{it, ch}}); err != nil {
				t.Fatal(err)
			}
			var buf bytes.Buffer
			if _, err := e.svc.ExportFidelityCSV(ctx, e.tid, chain("ann"), job, &buf); err != nil {
				t.Fatal(err)
			}
			out := buf.String()
			for _, line := range strings.Split(out, "\n") {
				for _, f := range strings.Split(line, ",") {
					f = strings.Trim(f, "\"\r")
					if strings.HasPrefix(f, "=") || strings.HasPrefix(f, "@") {
						t.Errorf("formula lead survives: %q", f)
					}
				}
			}
			if !strings.Contains(out, "\t=cmd") {
				t.Errorf("no neutraliser before =cmd: %q", out)
			}
			// Deny by default.
			if _, err := e.svc.ExportFidelityCSV(ctx, e.tid, chain("bob"), job, &buf); !errors.Is(err, migration.ErrDenied) {
				t.Errorf("export without permission: %v", err)
			}
		})

		t.Run("fidelity_export_binds_tenant", func(t *testing.T) {
			e := setup(t, s)
			job := e.running(t)
			// An authorizer like rbac.Authorizer: denies without a tenant on ctx, permits only per tenant.
			e.svc.Authz = tenantScoped{allow: e.tid.String()}
			var buf bytes.Buffer
			if _, err := e.svc.ExportFidelityCSV(ctx, e.tid, chain("ann"), job, &buf); err != nil {
				t.Errorf("permitted export without tenant on ctx: %v", err)
			}
			// A ctx pre-set to another tenant is authorised against the tenant being read.
			other := authority.WithTenant(ctx, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
			if _, err := e.svc.ExportFidelityCSV(other, e.tid, chain("ann"), job, &buf); err != nil {
				t.Errorf("foreign tenant on ctx leaked into authorisation: %v", err)
			}
			// A user permitted only in tenant B is denied reading tenant A.
			e.svc.Authz = tenantScoped{allow: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"}
			if _, err := e.svc.ExportFidelityCSV(other, e.tid, chain("ann"), job, &buf); !errors.Is(err, migration.ErrDenied) {
				t.Errorf("user permitted only in B read A: %v", err)
			}
		})

		t.Run("fidelity_record_guards", func(t *testing.T) {
			e := setup(t, s)
			p := e.project(t)
			j, _ := e.svc.SubmitJob(ctx, e.tid, chain("ann"), in(p, 1))
			one := migration.RecordFidelityInput{JobID: j.ID, Items: []migration.Item{exact("a")}}
			if _, err := e.svc.RecordFidelity(ctx, e.tid, chain("ann"), one); !errors.Is(err, migration.ErrJobNotRunning) {
				t.Errorf("quarantined job: %v", err)
			}
			if _, err := e.svc.RecordFidelity(ctx, e.tid, chain("bob"), migration.RecordFidelityInput{JobID: "33333333-3333-4333-8333-333333333333"}); err == nil {
				t.Error("unknown job accepted")
			}
			e.release(t, j.ID)
			if _, err := e.svc.RecordFidelity(ctx, e.tid, chain("ann"), one); err != nil {
				t.Fatal(err)
			}
			if _, err := e.svc.RecordFidelity(ctx, e.tid, chain("ann"), one); !errors.Is(err, migration.ErrAlreadyRecorded) {
				t.Errorf("second record: %v", err)
			}
			// The database itself refuses a proposal for a manual item, even from the owner role.
			j2 := e.runningAs(t, "bob")
			man := exact("m")
			man.Script = "x"
			if _, err := e.svc.RecordFidelity(ctx, e.tid, chain("ann"), migration.RecordFidelityInput{JobID: j2, Items: []migration.Item{man}}); err != nil {
				t.Fatal(err)
			}
			oc, err := e.d.OwnerForTenant(ctx, e.tid.String())
			if err != nil {
				t.Fatal(err)
			}
			defer oc.Close(ctx)
			if _, err := oc.Exec(ctx, `INSERT INTO public.migration_proposals (tenant_id, job_id, item_seq, class, config)
				SELECT tenant_id, job_id, item_seq, 'exact', '{}' FROM public.migration_fidelity WHERE job_id = $1::uuid`, j2); err == nil {
				t.Error("a proposal for a manual item was stored")
			}
		})
	})
}

// tenantScoped permits migration.import only for the tenant on ctx, and denies when none is set.
type tenantScoped struct{ allow string }

func (tenantScoped) FactsQuery(_ authority.Chain, _ authz.Permission, t authority.TargetRef) authority.FactsQuery {
	return authority.FactsQuery{Target: t}
}

func (a tenantScoped) Authorize(ctx context.Context, _ authority.Chain, p authz.Permission, _ authority.TargetRef, _ authority.Facts) error {
	if tn, ok := authority.TenantFrom(ctx); ok && tn == a.allow && p == migration.PermImport {
		return nil
	}
	return errors.New("not granted")
}

package delegation_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory"
	"github.com/skenzeriq/activediq/internal/modules/delegation"
	"github.com/skenzeriq/activediq/internal/platform"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/module/moduletest"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/rbac"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

func TestMain(m *testing.M) { os.Exit(storetest.Main(m)) }

const (
	owner  = "aaaaaaaa-0000-4000-8000-000000000001"
	admin  = "aaaaaaaa-0000-4000-8000-000000000002"
	member = "aaaaaaaa-0000-4000-8000-000000000003"
	other  = "aaaaaaaa-0000-4000-8000-000000000004"
	conn   = "bbbbbbbb-0000-4000-8000-000000000001"
	group  = "bbbbbbbb-0000-4000-8000-000000000002"
)

func id(n int) string {
	return "dddddddd-0000-4000-8000-0000000000" + string(rune('0'+n/10)) + string(rune('0'+n%10))
}

type recorder struct {
	mu  sync.Mutex
	evs []audit.Event
}

func (r *recorder) Append(_ context.Context, _ store.Tx, ev audit.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.evs = append(r.evs, ev)
	return nil
}

func (r *recorder) last() audit.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.evs) == 0 {
		return audit.Event{}
	}
	return r.evs[len(r.evs)-1]
}

// noFacts: a store target has no directory facts to read.
type noFacts struct{}

func (noFacts) Facts(context.Context, authority.Pins, authority.FactsQuery) (authority.Facts, error) {
	return authority.Facts{Exists: true}, nil
}

// members: who is in which group, as the directory would say.
type members map[string][]authz.Group

func (m members) GroupsOf(_ context.Context, _ string, account string) (authz.Groups, error) {
	return authz.Groups{Groups: m[account], Complete: true}, nil
}

type env struct {
	db     *store.DB
	tid    tenant.ID
	root   rbac.Root
	az     *rbac.Authorizer
	runner *operation.Runner
	rec    *recorder
	n      int
}

func setup(t *testing.T, s *storetest.Server, access bool) *env {
	t.Helper()
	d := s.NewDatabase(t)
	d.Migrate(t)
	tid := tenanttest.Seed(t, d.ExecOwner, "A")
	db, err := store.Open(context.Background(), store.Config{DSN: d.AppDSN()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	root := rbac.Root{Kind: rbac.TenantStore, Connection: tid.String(), GUID: tid.String()}
	if err := db.WithTenant(context.Background(), tid, func(ctx context.Context, tx store.Tx) error {
		if err := rbac.SeedBuiltIns(ctx, tx, tid); err != nil {
			return err
		}
		// The tenant-owner and a delegated admin are seeded the way the first-run does: directly.
		for _, c := range []struct{ role, who string }{{rbac.TenantOwnerRole, owner}} {
			var aid string
			if err := tx.QueryRow(ctx, `INSERT INTO public.authz_assignments (tenant_id, account_id, role_id, valid_from, granted_by)
SELECT $1::uuid, $2::uuid, r.id, now() - interval '1 hour', 'seed' FROM public.authz_roles r WHERE r.tenant_id = $1::uuid AND r.role_name = $3 RETURNING id::text`,
				tid.String(), c.who, c.role).Scan(&aid); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO public.authz_assignment_roots (tenant_id, assignment_id, ordinal, is_exclude, root_kind, connection_id, root_guid)
VALUES ($1::uuid, $2::uuid, 0, false, 'tenant', $1::uuid, $1::uuid)`, tid.String(), aid); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	src, err := rbac.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	az, err := rbac.New(src, rbac.WithMembership(members{member: {{Connection: conn, GUID: group}}}))
	if err != nil {
		t.Fatal(err)
	}
	var deps platform.Deps
	if access {
		if deps.Access, err = rbac.NewGrants(az); err != nil {
			t.Fatal(err)
		}
	}
	c, err := moduletest.Register(delegation.New(deps, directory.Services{}))
	if err != nil {
		t.Fatal(err)
	}
	reg, err := operation.NewRegistry(c.Actions()...)
	if err != nil {
		t.Fatal(err)
	}
	rec := &recorder{}
	runner, err := operation.NewRunner(operation.Config{DB: db, Audit: rec, Authz: az, Facts: noFacts{}, Registry: reg, Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	return &env{db: db, tid: tid, root: root, az: az, runner: runner, rec: rec}
}

func (e *env) run(t *testing.T, who string, via []authority.Principal, a operation.ActionID, in any) error {
	t.Helper()
	b, _ := json.Marshal(in)
	e.n++
	_, err := e.runner.RunStore(context.Background(), operation.Request{
		Tenant: e.tid, Actor: authority.Chain{Requester: authority.Principal{ID: authority.PrincipalID(who), Kind: authority.Human}, Via: via},
		Action: a, Input: b, Operation: step.OperationID("op-" + string(rune('a'+e.n))), FreshStepUp: true,
	})
	return err
}

func (e *env) rootIn() []delegation.RootInput {
	return []delegation.RootInput{{Kind: "tenant", ConnectionID: e.tid.String(), GUID: e.tid.String()}}
}

func (e *env) roleID(t *testing.T, name string) string {
	t.Helper()
	var rid string
	if err := e.db.WithTenant(context.Background(), e.tid, func(ctx context.Context, tx store.Tx) error {
		return tx.QueryRow(ctx, `SELECT id::text FROM public.authz_roles WHERE tenant_id = $1::uuid AND role_name = $2`, e.tid.String(), name).Scan(&rid)
	}); err != nil {
		t.Fatal(err)
	}
	return rid
}

func TestModuleRegisters(t *testing.T) {
	c, err := moduletest.Register(delegation.New(platform.Deps{}, directory.Services{}))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Actions()) != 4 {
		t.Fatalf("want 4 actions, got %d", len(c.Actions()))
	}
}

// Delegated administration end to end, through the runner and the real Authorizer: the owner delegates
// "grant", the delegate cannot grant more than it holds, and a group assignment it makes applies to a
// member of the group (DM-36.I1, I2).
func TestDelegatedGrantEndToEnd(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s, true)
		ctx := context.Background()
		// The owner creates a role that may grant, and holds nothing back.
		if err := e.run(t, owner, nil, delegation.RoleCreateID, delegation.RoleCreateInput{
			RoleID: id(1), Name: "access-delegate", Tier: 1,
			Permissions: []string{string(delegation.PermGrant), string(delegation.PermRevoke), "reports.run"},
		}); err != nil {
			t.Fatalf("create role: %v", err)
		}
		if ev := e.rec.last(); ev.Kind != delegation.AuditRoleCreated || ev.Outcome != audit.Success || ev.Target.Class != delegation.TargetClassRole || ev.Actor.Requester.ID != owner {
			t.Fatalf("audit %+v", ev)
		}
		if err := e.run(t, owner, nil, delegation.RoleCreateID, delegation.RoleCreateInput{
			RoleID: id(2), Name: "desk-plus", Tier: 2, Permissions: []string{"reports.run", "reports.export"},
		}); err != nil {
			t.Fatal(err)
		}
		if err := e.run(t, owner, nil, delegation.RoleCreateID, delegation.RoleCreateInput{
			RoleID: id(7), Name: "report-viewer", Tier: 2, Permissions: []string{"reports.run"},
		}); err != nil {
			t.Fatal(err)
		}
		if err := e.run(t, owner, nil, delegation.GrantID, delegation.GrantInput{
			AssignmentID: id(3), RoleID: id(1), Subject: delegation.SubjectInput{Kind: "account", AccountID: admin}, Roots: e.rootIn(),
		}); err != nil {
			t.Fatalf("delegate: %v", err)
		}
		if ev := e.rec.last(); ev.Kind != delegation.AuditGranted || len(ev.Changes) < 3 {
			t.Fatalf("audit %+v", ev)
		}

		// The delegate cannot hand out a role that holds more than it does.
		err := e.run(t, admin, nil, delegation.GrantID, delegation.GrantInput{
			AssignmentID: id(4), RoleID: id(2), Subject: delegation.SubjectInput{Kind: "account", AccountID: other}, Roots: e.rootIn(),
		})
		if !errors.Is(err, operation.ErrDenied) {
			t.Fatalf("escalation: %v", err)
		}
		if ev := e.rec.last(); ev.Outcome == audit.Success {
			t.Fatalf("escalation audited as success: %+v", ev)
		}
		// ...nor through a token, whose authority is the owner's subset and never control-plane.
		err = e.run(t, admin, []authority.Principal{{ID: "tok", Kind: authority.APIToken}}, delegation.GrantID, delegation.GrantInput{
			AssignmentID: id(4), RoleID: id(1), Subject: delegation.SubjectInput{Kind: "account", AccountID: other}, Roots: e.rootIn(),
		})
		if err == nil {
			t.Fatal("a token administered access")
		}
		// It can hand out a role it holds to a directory group.
		hd := id(7)
		if err := e.run(t, admin, nil, delegation.GrantID, delegation.GrantInput{
			AssignmentID: id(5), RoleID: hd, Subject: delegation.SubjectInput{Kind: "group", ConnectionID: conn, GroupGUID: group}, Roots: e.rootIn(),
		}); err != nil {
			t.Fatalf("group grant: %v", err)
		}
		// It cannot give a group the role that may grant (control-plane authority is personal).
		err = e.run(t, owner, nil, delegation.GrantID, delegation.GrantInput{
			AssignmentID: id(6), RoleID: id(1), Subject: delegation.SubjectInput{Kind: "group", ConnectionID: conn, GroupGUID: group}, Roots: e.rootIn(),
		})
		if !errors.Is(err, operation.ErrDenied) {
			t.Fatalf("control-plane to a group: %v", err)
		}

		// Acceptance 1: the grant applies when a member of the group acts, and not to a stranger.
		target := authority.TargetRef{GUID: e.tid.String(), Class: "settings"}
		az := authority.WithTenant(ctx, e.tid.String())
		chain := func(who string) authority.Chain {
			return authority.Chain{Requester: authority.Principal{ID: authority.PrincipalID(who), Kind: authority.Human}}
		}
		if err := e.az.Authorize(az, chain(member), "reports.run", target, authority.Facts{Exists: true}); err != nil {
			t.Errorf("member of the group: %v", err)
		}
		if err := e.az.Authorize(az, chain(other), "reports.run", target, authority.Facts{Exists: true}); err == nil {
			t.Error("a stranger holds the group's grant")
		}
		if err := e.az.Authorize(az, chain(member), "reports.export", target, authority.Facts{Exists: true}); err == nil {
			t.Error("the group holds a permission its role lacks")
		}

		// Revoke ends it, and the audit event names the assignment.
		if err := e.run(t, admin, nil, delegation.RevokeID, delegation.RevokeInput{AssignmentID: id(5)}); err != nil {
			t.Fatalf("revoke: %v", err)
		}
		if ev := e.rec.last(); ev.Kind != delegation.AuditRevoked || ev.Target.GUID != id(5) {
			t.Fatalf("audit %+v", ev)
		}
		if err := e.az.Authorize(az, chain(member), "reports.run", target, authority.Facts{Exists: true}); err == nil {
			t.Error("a revoked group grant still applies")
		}

		// A role edit that adds a permission the editor lacks is refused; a built-in cannot be edited.
		if err := e.run(t, admin, nil, delegation.RoleUpdateID, delegation.RoleUpdateInput{RoleID: id(1), Permissions: []string{"objects.user.delete"}}); !errors.Is(err, operation.ErrDenied) {
			t.Errorf("update by a user lacking rbac.role.update: %v", err)
		}
		if err := e.run(t, owner, nil, delegation.RoleUpdateID, delegation.RoleUpdateInput{RoleID: e.roleID(t, "helpdesk-operator"), Permissions: []string{"objects.user.delete"}}); !errors.Is(err, operation.ErrDenied) {
			t.Errorf("built-in edit: %v", err)
		}
		if err := e.run(t, owner, nil, delegation.RoleUpdateID, delegation.RoleUpdateInput{RoleID: id(2), Permissions: []string{"reports.run"}}); err != nil {
			t.Errorf("owner narrows a role: %v", err)
		}
	})
}

// Without the access service the module refuses every write instead of writing unproven.
func TestNoAccessServiceFailsClosed(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s, false)
		err := e.run(t, owner, nil, delegation.RoleCreateID, delegation.RoleCreateInput{RoleID: id(1), Name: "x", Tier: 2, Permissions: []string{"objects.user.reset_password"}})
		if err == nil {
			t.Fatal("a write went through without the access service")
		}
		var n int
		if err := e.db.WithTenant(context.Background(), e.tid, func(ctx context.Context, tx store.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM public.authz_roles WHERE role_name = 'x'`).Scan(&n)
		}); err != nil || n != 0 {
			t.Fatalf("role written: %d %v", n, err)
		}
	})
}

package compliance_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory"
	"github.com/skenzeriq/activediq/internal/modules/compliance"
	"github.com/skenzeriq/activediq/internal/platform"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/module/moduletest"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/personal"
	"github.com/skenzeriq/activediq/internal/platform/rbac"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

func TestMain(m *testing.M) { os.Exit(storetest.Main(m)) }

const subj = "dir:11111111-1111-4111-8111-111111111111:22222222-2222-4222-8222-222222222222"

// roles maps a principal to the role it holds; the permissions come from rbac.BuiltInRoles (the shipped
// roles) plus a custom compliance role a tenant would create deliberately.
type roles map[authority.PrincipalID]string

func (h roles) FactsQuery(_ authority.Chain, _ authz.Permission, t authority.TargetRef) authority.FactsQuery {
	return authority.FactsQuery{Target: t}
}

func (h roles) Authorize(_ context.Context, c authority.Chain, p authz.Permission, t authority.TargetRef, _ authority.Facts) error {
	name := h[c.Requester.ID]
	perms := []authz.Permission{compliance.PermSetHold, compliance.PermReleaseHold}
	if name != "compliance-officer" {
		perms = nil
		for _, r := range rbac.BuiltInRoles() {
			if r.Name == name {
				perms = r.Permissions
			}
		}
	}
	if slices.Contains(perms, p) && t.Class == compliance.TargetClassHold {
		return nil
	}
	return errors.New("not granted")
}

type facts struct{}

func (facts) Facts(context.Context, authority.Pins, authority.FactsQuery) (authority.Facts, error) {
	return authority.Facts{Exists: true}, nil
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

func (r *recorder) last() (audit.Event, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.evs) == 0 {
		return audit.Event{}, 0
	}
	return r.evs[len(r.evs)-1], len(r.evs)
}

type env struct {
	db     *store.DB
	tid    tenant.ID
	runner *operation.Runner
	rec    *recorder
}

func setup(t *testing.T, s *storetest.Server) *env {
	t.Helper()
	d := s.NewDatabase(t)
	d.Migrate(t)
	tid := tenanttest.Seed(t, d.ExecOwner, "A")
	db, err := store.Open(context.Background(), store.Config{DSN: d.AppDSN()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	var acts []operation.Action
	for _, b := range []func() (operation.Action, error){compliance.SetHold, compliance.ReleaseHold} {
		a, err := b()
		if err != nil {
			t.Fatal(err)
		}
		acts = append(acts, a)
	}
	reg, err := operation.NewRegistry(acts...)
	if err != nil {
		t.Fatal(err)
	}
	rec := &recorder{}
	runner, err := operation.NewRunner(operation.Config{DB: db, Audit: rec, Facts: facts{}, Registry: reg, Now: time.Now,
		Authz: roles{"alice": "compliance-officer", "helen": "helpdesk-operator", "paula": "platform-administrator"}})
	if err != nil {
		t.Fatal(err)
	}
	return &env{db: db, tid: tid, runner: runner, rec: rec}
}

func (e *env) req(action operation.ActionID, actor string, kind authority.PrincipalKind, stepUp bool) operation.Request {
	in, _ := json.Marshal(compliance.HoldInput{Subject: subj})
	return operation.Request{Tenant: e.tid, Actor: authority.Chain{Requester: authority.Principal{ID: authority.PrincipalID(actor), Kind: kind}},
		Action: action, Input: in, Operation: step.OperationID("op-" + string(action) + "-" + actor), FreshStepUp: stepUp}
}

func (e *env) held(t *testing.T) bool {
	t.Helper()
	var h bool
	if err := e.db.WithTenant(context.Background(), e.tid, func(ctx context.Context, tx store.Tx) (err error) {
		h, err = personal.New().Held(ctx, tx, e.tid, subj)
		return
	}); err != nil {
		t.Fatal(err)
	}
	return h
}

func TestModuleRegisters(t *testing.T) {
	if _, err := moduletest.Register(compliance.New(platform.Deps{}, directory.Services{})); err != nil {
		t.Fatal(err)
	}
}

// No shipped role holds a hold permission, and in particular no help-desk role does.
func TestNoBuiltInRoleHoldsHoldPermission(t *testing.T) {
	for _, r := range rbac.BuiltInRoles() {
		for _, p := range []authz.Permission{compliance.PermSetHold, compliance.PermReleaseHold} {
			if slices.Contains(r.Permissions, p) {
				t.Errorf("built-in role %q holds %q", r.Name, p)
			}
		}
	}
}

// Acceptance 2: releasing needs the dedicated compliance permission (a Tier-2 help-desk role is refused),
// a fresh step-up and a human; a refusal changes nothing and is audited; a release names the human.
func TestReleaseHoldGatedAndAudited(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		ctx := context.Background()
		if _, err := e.runner.RunStore(ctx, e.req(compliance.SetHoldActionID, "alice", authority.Human, true)); err != nil {
			t.Fatal(err)
		}
		if ev, _ := e.rec.last(); ev.Kind != compliance.AuditHoldSet || ev.Outcome != audit.Success || ev.Actor.Requester.ID != "alice" {
			t.Fatalf("set event %+v", ev)
		}
		if !e.held(t) {
			t.Fatal("hold not stored")
		}

		for _, c := range []struct {
			name string
			req  operation.Request
		}{
			{"tier-2 help desk", e.req(compliance.ReleaseHoldActionID, "helen", authority.Human, true)},
			{"platform admin", e.req(compliance.ReleaseHoldActionID, "paula", authority.Human, true)},
			{"unknown principal", e.req(compliance.ReleaseHoldActionID, "mallory", authority.Human, true)},
			{"no step-up", e.req(compliance.ReleaseHoldActionID, "alice", authority.Human, false)},
		} {
			if _, err := e.runner.RunStore(ctx, c.req); !errors.Is(err, operation.ErrDenied) {
				t.Errorf("%s: %v", c.name, err)
			}
			if ev, _ := e.rec.last(); ev.Outcome != audit.Denied || ev.Kind != compliance.AuditHoldReleased {
				t.Errorf("%s: last event %+v", c.name, ev)
			}
			if !e.held(t) {
				t.Fatalf("%s released the hold", c.name)
			}
		}
		// The same refusal for placing a hold.
		if _, err := e.runner.RunStore(ctx, e.req(compliance.SetHoldActionID, "helen", authority.Human, true)); !errors.Is(err, operation.ErrDenied) {
			t.Errorf("help desk set hold: %v", err)
		}
		// A non-human requester holding the permission is refused too.
		if _, err := e.runner.RunStore(ctx, e.req(compliance.ReleaseHoldActionID, "alice", authority.Automation, true)); err == nil {
			t.Error("automation released a hold")
		}
		if !e.held(t) {
			t.Fatal("hold lost to a refused request")
		}

		before := time.Now().Add(-time.Second)
		_, n := e.rec.last()
		if _, err := e.runner.RunStore(ctx, e.req(compliance.ReleaseHoldActionID, "alice", authority.Human, true)); err != nil {
			t.Fatal(err)
		}
		if e.held(t) {
			t.Fatal("hold still in force")
		}
		ev, n2 := e.rec.last()
		if n2 != n+1 || ev.Kind != compliance.AuditHoldReleased || ev.Outcome != audit.Success || ev.Actor.Requester.ID != "alice" ||
			ev.Actor.Requester.Kind != authority.Human || ev.Target.Class != compliance.TargetClassHold || ev.At.Before(before) {
			t.Fatalf("release event %+v", ev)
		}
		if len(ev.Changes) != 2 || ev.Changes[0].After[0] != subj || ev.Changes[1].Before[0] != "true" || ev.Changes[1].After[0] != "false" {
			t.Fatalf("release changes %+v", ev.Changes)
		}

		// Releasing again is idempotent and audited as false to false; and a refused requester learns nothing
		// about the state: the denial is the same whether or not the subject is held.
		if _, err := e.runner.RunStore(ctx, e.req(compliance.ReleaseHoldActionID, "alice", authority.Human, true)); err != nil {
			t.Fatalf("second release: %v", err)
		}
		if ev, _ := e.rec.last(); ev.Outcome != audit.Success || ev.Changes[1].Before[0] != "false" {
			t.Fatalf("second release event %+v", ev)
		}
		if _, err := e.runner.RunStore(ctx, e.req(compliance.ReleaseHoldActionID, "helen", authority.Human, true)); !errors.Is(err, operation.ErrDenied) {
			t.Fatalf("help desk release of a non-held subject: %v", err)
		}
	})
}

func TestHoldInputValidated(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		r := e.req(compliance.SetHoldActionID, "alice", authority.Human, true)
		r.Input = operation.Input(`{"subject":"CN=Ann,DC=x"}`)
		if _, err := e.runner.RunStore(context.Background(), r); !errors.Is(err, operation.ErrInvalid) {
			t.Fatalf("DN as subject: %v", err)
		}
		if e.held(t) {
			t.Fatal("invalid input placed a hold")
		}
	})
}

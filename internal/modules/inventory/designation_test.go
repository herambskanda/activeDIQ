package inventory_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory"
	"github.com/skenzeriq/activediq/internal/directory/connection"
	dirinv "github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/modules/inventory"
	"github.com/skenzeriq/activediq/internal/platform"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/module/moduletest"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

func TestMain(m *testing.M) { os.Exit(storetest.Main(m)) }

const (
	cred = "11111111-1111-4111-8111-111111111111"
	obj  = "aaaaaaaa-0000-4000-8000-0000000000c1"
)

// holders are the principals that hold the Tier-0 scope permission.
type holders map[authority.PrincipalID]bool

func (h holders) FactsQuery(_ authority.Chain, _ authz.Permission, t authority.TargetRef) authority.FactsQuery {
	return authority.FactsQuery{Target: t}
}

func (h holders) Authorize(_ context.Context, c authority.Chain, p authz.Permission, t authority.TargetRef, _ authority.Facts) error {
	// "owner" holds the permission at Tier-0 scope; "ouadmin" holds it only on the object's OU, which
	// never covers a tier0_scope target.
	if p == inventory.DesignationPermission && h[c.Requester.ID] && t.Class == inventory.TargetClassScope {
		return nil
	}
	return errors.New("not granted")
}

// tier0Facts reports the designated object itself as tier0, as a real Facts provider would once it is
// designated (runner rule 7). The Action must not depend on the object being non-tier0.
type tier0Facts struct{}

func (tier0Facts) Facts(_ context.Context, _ authority.Pins, q authority.FactsQuery) (authority.Facts, error) {
	return authority.Facts{Exists: true, Tier0: q.Target.GUID == obj}, nil
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
	conn   dirinv.ConnectionID
	runner *operation.Runner
	rec    *recorder
	reader *dirinv.Reader
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
	c, err := connection.NewRegistry(db).Create(context.Background(), tid,
		connection.New{Kind: connection.KindADForest, DisplayName: "corp", CredentialID: cred, Transport: connection.TransportLDAPS})
	if err != nil {
		t.Fatal(err)
	}
	act, err := inventory.SetDesignation()
	if err != nil {
		t.Fatal(err)
	}
	reg, err := operation.NewRegistry(act)
	if err != nil {
		t.Fatal(err)
	}
	rec := &recorder{}
	runner, err := operation.NewRunner(operation.Config{DB: db, Audit: rec, Authz: holders{"owner": true}, Facts: tier0Facts{}, Registry: reg, Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	return &env{db: db, tid: tid, conn: dirinv.ConnectionID(c.ID), runner: runner, rec: rec, reader: dirinv.NewReader(db, dirinv.NewGroups(db))}
}

func (e *env) req(actor string, kind authority.PrincipalKind, stepUp, designated bool) operation.Request {
	in, _ := json.Marshal(inventory.DesignationInput{ConnectionID: string(e.conn), ObjectGUID: obj, Designated: designated})
	return operation.Request{Tenant: e.tid, Actor: authority.Chain{Requester: authority.Principal{ID: authority.PrincipalID(actor), Kind: kind}},
		Action: inventory.SetDesignationActionID, Input: in, Operation: step.OperationID("op-" + actor), FreshStepUp: stepUp}
}

func (e *env) designated(t *testing.T) bool {
	t.Helper()
	d, err := e.reader.DesignationsFor(context.Background(), e.tid, e.conn, []dirinv.GUID{obj})
	if err != nil {
		t.Fatal(err)
	}
	return len(d) == 1
}

func TestModuleRegisters(t *testing.T) {
	if _, err := moduletest.Register(inventory.New(platform.Deps{}, directory.Services{})); err != nil {
		t.Fatal(err)
	}
}

// Acceptance 3: a designation change needs step-up and the Tier-0 scope permission, and a human; a
// denial changes nothing and is audited; a success records actor, object and time.
func TestDesignationChangeGated(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		ctx := context.Background()
		denied := []struct {
			name string
			req  operation.Request
		}{
			{"no step-up", e.req("owner", authority.Human, false, true)},
			{"no permission", e.req("bob", authority.Human, true, true)},
		}
		for _, c := range denied {
			if _, err := e.runner.RunStore(ctx, c.req); !errors.Is(err, operation.ErrDenied) {
				t.Errorf("%s: %v", c.name, err)
			}
			if ev, _ := e.rec.last(); ev.Outcome != audit.Denied || ev.Kind != inventory.AuditDesignationChanged {
				t.Errorf("%s: last event %+v", c.name, ev)
			}
			if e.designated(t) {
				t.Fatalf("%s changed state", c.name)
			}
		}
		if _, err := e.runner.RunStore(ctx, e.req("owner", authority.Automation, true, true)); err == nil {
			t.Error("automation changed Tier-0 scope")
		}
		if e.designated(t) {
			t.Fatal("automation changed state")
		}

		before := time.Now().Add(-time.Second)
		if _, err := e.runner.RunStore(ctx, e.req("owner", authority.Human, true, true)); err != nil {
			t.Fatal(err)
		}
		if !e.designated(t) {
			t.Fatal("designation not stored")
		}
		ev, _ := e.rec.last()
		if ev.Kind != inventory.AuditDesignationChanged || ev.Outcome != audit.Success || ev.Actor.Requester.ID != "owner" ||
			ev.Target.Class != inventory.TargetClassScope || ev.Target.Connection != string(e.conn) || ev.At.Before(before) {
			t.Fatalf("audit event %+v", ev)
		}
		if len(ev.Changes) != 2 || ev.Changes[0].After[0] != obj || ev.Changes[1].Before[0] != "false" || ev.Changes[1].After[0] != "true" {
			t.Fatalf("audit changes %+v", ev.Changes)
		}

		// Acceptance 4 through the Action: removal needs the same gate, is audited, and is a soft delete.
		if _, err := e.runner.RunStore(ctx, e.req("bob", authority.Human, true, false)); !errors.Is(err, operation.ErrDenied) {
			t.Fatalf("removal without permission: %v", err)
		}
		if !e.designated(t) {
			t.Fatal("a denied removal removed the designation")
		}
		_, n := e.rec.last()
		if _, err := e.runner.RunStore(ctx, e.req("owner", authority.Human, true, false)); err != nil {
			t.Fatal(err)
		}
		if e.designated(t) {
			t.Fatal("designation still in force")
		}
		if ev, n2 := e.rec.last(); n2 != n+1 || ev.Outcome != audit.Success || ev.Changes[1].After[0] != "false" || ev.Actor.Requester.ID != "owner" {
			t.Fatalf("removal audit %+v", ev)
		}
		var by string
		err := e.db.WithTenant(ctx, e.tid, func(ctx context.Context, tx store.Tx) error {
			return tx.QueryRow(ctx, `SELECT removed_by FROM public.tier0_designations WHERE object_guid = $1::uuid AND removed_at IS NOT NULL`, obj).Scan(&by)
		})
		if err != nil || by != "owner" {
			t.Fatalf("row not soft-deleted: %q %v", by, err)
		}
		// Removing what is not designated is refused at Plan.
		if _, err := e.runner.RunStore(ctx, e.req("owner", authority.Human, true, false)); err == nil {
			t.Error("removing a non-designation was accepted")
		}
	})
}

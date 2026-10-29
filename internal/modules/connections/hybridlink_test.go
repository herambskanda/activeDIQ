package connections_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/modules/connections"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

const ncGUID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"

// scopes grants HybridLinkPermission per principal and per side (the target class).
type scopes map[authority.PrincipalID]map[string]bool

func (scopes) FactsQuery(_ authority.Chain, _ authz.Permission, t authority.TargetRef) authority.FactsQuery {
	return authority.FactsQuery{Target: t}
}

func (s scopes) Authorize(_ context.Context, c authority.Chain, p authz.Permission, t authority.TargetRef, _ authority.Facts) error {
	if p == connections.HybridLinkPermission && s[c.Requester.ID][t.Class] {
		return nil
	}
	return errors.New("not granted")
}

type linkEnv struct {
	reg    *connection.Registry
	tid    tenant.ID
	runner *operation.Runner
	rec    *recorder
	ad     connection.Connection
	entra  connection.Connection
	n      int
}

func newLinkEnv(t *testing.T, s *storetest.Server) *linkEnv {
	t.Helper()
	d := s.NewDatabase(t)
	d.Migrate(t)
	tid := tenanttest.Seed(t, d.ExecOwner, "A")
	db, err := store.Open(context.Background(), store.Config{DSN: d.AppDSN()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	reg, rec := connection.NewRegistry(db), &recorder{}
	ctx := context.Background()
	ad, err := reg.Create(ctx, tid, connection.New{Kind: connection.KindADForest, DisplayName: "corp", CredentialID: cred, Transport: connection.TransportLDAPS})
	if err != nil {
		t.Fatal(err)
	}
	en, err := reg.Create(ctx, tid, connection.New{Kind: connection.KindEntraTenant, DisplayName: "tenant", CredentialID: cred})
	if err != nil {
		t.Fatal(err)
	}
	acts, err := connections.HybridLinkActions()
	if err != nil {
		t.Fatal(err)
	}
	r, err := operation.NewRegistry(acts...)
	if err != nil {
		t.Fatal(err)
	}
	both := map[string]bool{"naming_context": true, "entra_tenant": true}
	runner, err := operation.NewRunner(operation.Config{DB: db, Audit: rec, Registry: r, Now: time.Now, Authz: scopes{
		"both": both, "adonly": {"naming_context": true}, "entraonly": {"entra_tenant": true}, "none": {},
		"tok": both,
	}})
	if err != nil {
		t.Fatal(err)
	}
	return &linkEnv{reg: reg, tid: tid, runner: runner, rec: rec, ad: ad, entra: en}
}

func (e *linkEnv) run(actor string, kind authority.PrincipalKind, act operation.ActionID, in connections.HybridLinkInput) (operation.Result, error) {
	e.n++
	raw, _ := json.Marshal(in)
	return e.runner.RunStore(context.Background(), operation.Request{Tenant: e.tid, Action: act, Input: raw, FreshStepUp: true,
		Actor:     authority.Chain{Requester: authority.Principal{ID: authority.PrincipalID(actor), Kind: kind}},
		Operation: step.OperationID("op-" + string(rune('a'+e.n)))})
}

func (e *linkEnv) declareIn() connections.HybridLinkInput {
	return connections.HybridLinkInput{ADConnectionID: string(e.ad.ID), NCGUID: ncGUID, EntraConnectionID: string(e.entra.ID)}
}

func (e *linkEnv) discover(t *testing.T) connection.HybridLink {
	t.Helper()
	l, err := e.reg.DiscoverHybridLink(context.Background(), e.tid, connection.NewHybridLink{ADConnectionID: e.ad.ID, NCGUID: ncGUID, EntraConnectionID: e.entra.ID})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func (e *linkEnv) state(t *testing.T, id connection.HybridLinkID) connection.LinkState {
	t.Helper()
	l, err := e.reg.GetHybridLink(context.Background(), e.tid, id)
	if err != nil {
		t.Fatal(err)
	}
	return l.State
}

func (e *linkEnv) has(t *testing.T) bool {
	t.Helper()
	ok, err := e.reg.HasHybridLink(context.Background(), e.tid, e.ad.ID)
	if err != nil {
		t.Fatal(err)
	}
	return ok
}

// Acceptance 1: holding the permission over both scopes, confirm and declare succeed and are audited
// with actor, both connections and the transition.
func TestHybridLinkConfirmAndDeclare(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := newLinkEnv(t, s)
		l := e.discover(t)
		if _, err := e.run("both", authority.Human, connections.HybridLinkConfirmActionID, connections.HybridLinkInput{LinkID: string(l.ID)}); err != nil {
			t.Fatal(err)
		}
		if got := e.state(t, l.ID); got != connection.LinkConfirmed {
			t.Fatalf("state %s", got)
		}
		var found bool
		for _, ev := range e.rec.all() {
			if ev.Kind != connections.AuditHybridLinkConfirmed || ev.Outcome != audit.Success || ev.Actor.Requester.ID != "both" {
				continue
			}
			found = true
			attrs := map[string][]string{}
			for _, c := range ev.Changes {
				attrs[c.Attribute] = c.After
				if c.Attribute == "state" && (len(c.Before) != 1 || c.Before[0] != "proposed") {
					t.Errorf("before %v", c.Before)
				}
			}
			if attrs["state"][0] != "confirmed" || attrs["ad_connection_id"][0] != string(e.ad.ID) || attrs["entra_connection_id"][0] != string(e.entra.ID) {
				t.Errorf("changes %v", attrs)
			}
		}
		if !found {
			t.Fatal("no confirm audit event")
		}
		// Declare on a second domain.
		in := e.declareIn()
		in.NCGUID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
		res, err := e.run("both", authority.Human, connections.HybridLinkDeclareActionID, in)
		if err != nil {
			t.Fatal(err)
		}
		var out connections.HybridLinkOutcome
		if err := json.Unmarshal(res.Steps[0].Outcome.Payload, &out); err != nil || out.State != connection.LinkConfirmed {
			t.Fatalf("outcome %+v %v", out, err)
		}
		ok, err := e.reg.Confirmed(context.Background(), e.tid, e.ad.ID, connection.NCGUID(in.NCGUID), e.entra.ID)
		if err != nil || !ok {
			t.Fatalf("declared link not confirmed: %v %v", ok, err)
		}
	})
}

// Acceptance 2 and 3: missing either scope refuses confirm, declare and remove and changes nothing;
// automation is refused too.
func TestHybridLinkRefusedWithoutBothScopes(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := newLinkEnv(t, s)
		proposed := e.discover(t)
		for _, who := range []string{"adonly", "entraonly", "none"} {
			if _, err := e.run(who, authority.Human, connections.HybridLinkConfirmActionID, connections.HybridLinkInput{LinkID: string(proposed.ID)}); !errors.Is(err, operation.ErrDenied) {
				t.Errorf("%s confirm: %v", who, err)
			}
			if _, err := e.run(who, authority.Human, connections.HybridLinkDeclareActionID, e.declareIn()); !errors.Is(err, operation.ErrDenied) {
				t.Errorf("%s declare: %v", who, err)
			}
			if _, err := e.run(who, authority.Human, connections.HybridLinkRemoveActionID, connections.HybridLinkInput{LinkID: string(proposed.ID)}); !errors.Is(err, operation.ErrDenied) {
				t.Errorf("%s remove: %v", who, err)
			}
			if ev := e.rec.last(); ev.Outcome != audit.Denied {
				t.Errorf("%s: last event %+v", who, ev)
			}
			if got := e.state(t, proposed.ID); got != connection.LinkProposed || !e.has(t) {
				t.Fatalf("%s changed the link: %s", who, got)
			}
		}
		if _, err := e.run("tok", authority.APIToken, connections.HybridLinkConfirmActionID, connections.HybridLinkInput{LinkID: string(proposed.ID)}); err == nil {
			t.Error("an API token confirmed a link")
		}
		if got := e.state(t, proposed.ID); got != connection.LinkProposed {
			t.Fatalf("state %s", got)
		}
	})
}

// Acceptance 3 and 4: removal needs the permission, is audited, and HasHybridLink flips only after it.
func TestHybridLinkRemoveFlipsHasHybridLinkAfterAuditedTransition(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := newLinkEnv(t, s)
		for _, fromConfirmed := range []bool{false, true} {
			l := e.discover(t)
			if fromConfirmed {
				if _, err := e.run("both", authority.Human, connections.HybridLinkConfirmActionID, connections.HybridLinkInput{LinkID: string(l.ID)}); err != nil {
					t.Fatal(err)
				}
			}
			if !e.has(t) {
				t.Fatal("HasHybridLink false before removal")
			}
			if _, err := e.run("adonly", authority.Human, connections.HybridLinkRemoveActionID, connections.HybridLinkInput{LinkID: string(l.ID)}); err == nil || !e.has(t) {
				t.Fatal("remove without both scopes")
			}
			if _, err := e.run("both", authority.Human, connections.HybridLinkRemoveActionID, connections.HybridLinkInput{LinkID: string(l.ID)}); err != nil {
				t.Fatal(err)
			}
			if e.has(t) || e.state(t, l.ID) != connection.LinkRemoved {
				t.Fatal("link not removed")
			}
			if ev := e.rec.last(); ev.Kind != connections.AuditHybridLinkRemoved || ev.Outcome != audit.Success || ev.Actor.Requester.ID != "both" {
				t.Fatalf("event %+v", ev)
			}
			// A removed link is terminal.
			if _, err := e.run("both", authority.Human, connections.HybridLinkConfirmActionID, connections.HybridLinkInput{LinkID: string(l.ID)}); err == nil {
				t.Fatal("confirmed a removed link")
			}
		}
	})
}

func TestHybridLinkInputsAreStrict(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := newLinkEnv(t, s)
		l := e.discover(t)
		bad := map[operation.ActionID]connections.HybridLinkInput{
			connections.HybridLinkConfirmActionID: {LinkID: string(l.ID), NCGUID: ncGUID},
			connections.HybridLinkRemoveActionID:  {LinkID: "nope"},
			connections.HybridLinkDeclareActionID: {LinkID: string(l.ID), ADConnectionID: string(e.ad.ID)},
		}
		for act, in := range bad {
			if _, err := e.run("both", authority.Human, act, in); err == nil {
				t.Errorf("%s accepted %+v", act, in)
			}
		}
		if got := e.state(t, l.ID); got != connection.LinkProposed {
			t.Fatalf("state %s", got)
		}
	})
}

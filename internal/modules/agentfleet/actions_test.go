package agentfleet_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"github.com/skenzeriq/activediq/internal/directory/attr/secretattr"
	"sync"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/modules/agentfleet"
	"github.com/skenzeriq/activediq/internal/platform/agentpolicy"
	"github.com/skenzeriq/activediq/internal/platform/agentpolicy/signer"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/keys"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

type keySource struct {
	mu   sync.Mutex
	deks map[tenant.ID][]byte
}

func (k *keySource) DEK(_ context.Context, _ store.Tx, id tenant.ID, version uint32) (keys.DEK, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.deks == nil {
		k.deks = map[tenant.ID][]byte{}
	}
	if k.deks[id] == nil {
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		k.deks[id] = b
	}
	if version == 0 {
		version = 1
	}
	return keys.DEKFromBytes(version, append([]byte(nil), k.deks[id]...))
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

func (r *recorder) kinds() (out []audit.Kind) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.evs {
		out = append(out, e.Kind)
	}
	return
}

// grantAll grants both permissions to the listed principals.
type grantAll map[authority.PrincipalID]bool

func (grantAll) FactsQuery(_ authority.Chain, _ authz.Permission, t authority.TargetRef) authority.FactsQuery {
	return authority.FactsQuery{Target: t}
}

func (g grantAll) Authorize(_ context.Context, c authority.Chain, p authz.Permission, _ authority.TargetRef, _ authority.Facts) error {
	if (p == agentfleet.PolicyEditPermission || p == agentfleet.KeyRotatePermission) && g[c.Requester.ID] {
		return nil
	}
	return errors.New("not granted")
}

const (
	ownerID  = "0a0a0a0a-0000-4000-8000-000000000001"
	robotID  = "0b0b0b0b-0000-4000-8000-000000000002"
	nobodyID = "0c0c0c0c-0000-4000-8000-000000000003"
)

type env struct {
	db     *store.DB
	tid    tenant.ID
	sg     *signer.Signer
	rec    *recorder
	runner *operation.Runner
	n      int
}

func newEnv(t *testing.T, s *storetest.Server) *env {
	t.Helper()
	d := s.NewDatabase(t)
	d.Migrate(t)
	tid := tenanttest.Seed(t, d.ExecOwner, "A")
	db, err := store.Open(context.Background(), store.Config{DSN: d.AppDSN()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	rec := &recorder{}
	sg := &signer.Signer{Keys: &keySource{}, Audit: rec}
	var acts []operation.Action
	for _, build := range []func(agentfleet.PolicySigner) (operation.Action, error){agentfleet.PolicyEdit, agentfleet.KeyRotate} {
		a, err := build(sg)
		if err != nil {
			t.Fatal(err)
		}
		acts = append(acts, a)
	}
	reg, err := operation.NewRegistry(acts...)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := operation.NewRunner(operation.Config{SecretAttr: secretattr.IsStatic, DB: db, Audit: rec, Registry: reg, Now: time.Now,
		Authz: grantAll{ownerID: true, robotID: true}})
	if err != nil {
		t.Fatal(err)
	}
	return &env{db: db, tid: tid, sg: sg, rec: rec, runner: runner}
}

func (e *env) tx(t *testing.T, f func(ctx context.Context, tx store.Tx) error) {
	t.Helper()
	if err := e.db.WithTenant(context.Background(), e.tid, f); err != nil {
		t.Fatal(err)
	}
}

func (e *env) run(id operation.ActionID, in any, actor string, kind authority.PrincipalKind, stepUp bool) (operation.Result, error) {
	e.n++
	raw, _ := json.Marshal(in)
	return e.runner.RunStore(context.Background(), operation.Request{Tenant: e.tid, Action: id, Input: raw, FreshStepUp: stepUp,
		Actor:     authority.Chain{Requester: authority.Principal{ID: authority.PrincipalID(actor), Kind: kind}},
		Operation: step.OperationID("op-af-" + string(rune('a'+e.n)))})
}

func edit() agentfleet.PolicyEditInput {
	return agentfleet.PolicyEditInput{
		Password: agentfleet.PasswordInput{MinLength: 14, MaxLength: 128, MinClasses: 3, ClassesRequired: []string{"upper", "lower"}, BannedTerms: []string{"winter2026"}},
		Events:   agentfleet.EventsInput{CollectionEnabled: true, Channels: []string{"security"}, EventIDs: []uint32{4740, 4624}, MaxEventsPerSecond: 100, BatchMaxBytes: 65536, OutboxMaxBytes: 1 << 20},
	}
}

// Acceptance 1: with the permission and a fresh step-up, a rotation publishes a new keyset that an agent
// holding the anchor accepts, and a policy signed afterwards by the new key follows; both are audited.
func Test_rotate_publishes_chain_agents_accept(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := newEnv(t, s)
		actor := authority.Chain{Requester: authority.Principal{ID: ownerID, Kind: authority.Human}}
		var anchor agentpolicy.SignedKeyset
		e.tx(t, func(ctx context.Context, tx store.Tx) (err error) {
			anchor, err = e.sg.EnsureKeyset(ctx, tx, e.tid, actor)
			return
		})

		if _, err := e.run(agentfleet.KeyRotateActionID, agentfleet.KeyRotateInput{Reason: agentfleet.ReasonSuspectedExposure}, ownerID, authority.Human, true); err != nil {
			t.Fatal(err)
		}
		if _, err := e.run(agentfleet.PolicyEditActionID, edit(), ownerID, authority.Human, true); err != nil {
			t.Fatal(err)
		}
		v, err := agentpolicy.NewVerifier(e.tid, agentpolicy.KindADDC)
		if err != nil {
			t.Fatal(err)
		}
		if err := v.Anchor(anchor); err != nil {
			t.Fatal(err)
		}
		e.tx(t, func(ctx context.Context, tx store.Tx) error {
			chain, err := e.sg.Chain(ctx, tx, anchor.Seq)
			if err != nil || len(chain) != 1 {
				t.Fatalf("chain after anchor: %d %v", len(chain), err)
			}
			for _, k := range chain {
				if err := v.ApplyKeyset(k); err != nil {
					t.Fatalf("agent refuses the published keyset: %v", err)
				}
			}
			sp, ok, err := e.sg.CurrentPolicy(ctx, tx, agentpolicy.KindADDC)
			if err != nil || !ok {
				t.Fatalf("policy: %v %v", ok, err)
			}
			if _, err := v.ApplyPolicy(sp, time.Now()); err != nil {
				t.Fatalf("agent refuses the policy signed with the new key: %v", err)
			}
			return nil
		})
		got := e.rec.kinds()
		for _, want := range []audit.Kind{agentfleet.AuditKeyRotate, agentfleet.AuditPolicyEdit, signer.KindKeysetPublished, signer.KindPolicySigned} {
			found := false
			for _, k := range got {
				found = found || k == want
			}
			if !found {
				t.Errorf("no %s audit event in %v", want, got)
			}
		}
	})
}

// Refusals: no step-up, an automation, a principal without the permission, an unknown reason and an
// out-of-bounds policy all fail and change nothing.
func Test_actions_refused_change_nothing(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := newEnv(t, s)
		actor := authority.Chain{Requester: authority.Principal{ID: ownerID, Kind: authority.Human}}
		e.tx(t, func(ctx context.Context, tx store.Tx) error {
			_, err := e.sg.EnsureKeyset(ctx, tx, e.tid, actor)
			return err
		})
		bad := edit()
		bad.Password.MaxLength = 100000
		unknownClass := edit()
		unknownClass.Password.ClassesRequired = []string{"emoji"}
		cases := []struct {
			name string
			id   operation.ActionID
			in   any
			who  string
			kind authority.PrincipalKind
			stUp bool
		}{
			{"rotate without step-up", agentfleet.KeyRotateActionID, agentfleet.KeyRotateInput{Reason: agentfleet.ReasonSuspectedExposure}, ownerID, authority.Human, false},
			{"rotate by automation", agentfleet.KeyRotateActionID, agentfleet.KeyRotateInput{Reason: agentfleet.ReasonSuspectedExposure}, robotID, authority.Automation, true},
			{"rotate without permission", agentfleet.KeyRotateActionID, agentfleet.KeyRotateInput{Reason: agentfleet.ReasonSuspectedExposure}, nobodyID, authority.Human, true},
			{"rotate free-text reason", agentfleet.KeyRotateActionID, agentfleet.KeyRotateInput{Reason: "because"}, ownerID, authority.Human, true},
			{"edit without step-up", agentfleet.PolicyEditActionID, edit(), ownerID, authority.Human, false},
			{"edit by automation", agentfleet.PolicyEditActionID, edit(), robotID, authority.Automation, true},
			{"edit without permission", agentfleet.PolicyEditActionID, edit(), nobodyID, authority.Human, true},
			{"edit out of bounds", agentfleet.PolicyEditActionID, bad, ownerID, authority.Human, true},
			{"edit unknown class", agentfleet.PolicyEditActionID, unknownClass, ownerID, authority.Human, true},
		}
		for _, c := range cases {
			if _, err := e.run(c.id, c.in, c.who, c.kind, c.stUp); err == nil {
				t.Errorf("%s: accepted", c.name)
			}
		}
		e.tx(t, func(ctx context.Context, tx store.Tx) error {
			if chain, err := e.sg.Chain(ctx, tx, 0); err != nil || len(chain) != 1 {
				t.Errorf("keyset chain changed: %d %v", len(chain), err)
			}
			if _, ok, _ := e.sg.CurrentPolicy(ctx, tx, agentpolicy.KindADDC); ok {
				t.Error("a policy was signed")
			}
			return nil
		})
	})
}

// An unconfigured signer (compose has not wired the DEK source) refuses every run.
func Test_unconfigured_signer_refuses(t *testing.T) {
	a, err := agentfleet.KeyRotate(&signer.Signer{})
	if err != nil {
		t.Fatal(err)
	}
	if a.Describe().ID != agentfleet.KeyRotateActionID || !a.Describe().StepUp || !a.Describe().ControlPlane {
		t.Fatalf("descriptor: %+v", a.Describe())
	}
	if _, err := agentfleet.KeyRotate(nil); err == nil {
		t.Error("nil signer accepted")
	}
}

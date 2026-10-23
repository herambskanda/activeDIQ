package client

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// A Step can only be minted by the operation runner, so the tests obtain one the production way: a
// Store Action whose Apply runs the code under test with the live Step.

const (
	opID    = "6f1c2a40-0000-4000-8000-000000000001"
	account = "6f1c2a40-0000-4000-8000-0000000000aa"
)

var (
	testTarget = authority.TargetRef{Connection: "c1", GUID: "g1", Class: "user"}
	testAttrs  = []step.Attr{{Name: "description", Values: []string{"new"}}}
)

type fakeDB struct{}

func (fakeDB) WithTenant(ctx context.Context, _ tenant.ID, fn func(context.Context, store.Tx) error) error {
	return fn(ctx, &storetest.FakeTx{})
}

type sink struct{}

func (sink) Append(_ context.Context, tx store.Tx, ev audit.Event) error {
	ft := tx.(*storetest.FakeTx)
	ft.Records = append(ft.Records, ev)
	return nil
}

type allowAll struct{}

func (allowAll) FactsQuery(_ authority.Chain, _ authz.Permission, t authority.TargetRef) authority.FactsQuery {
	return authority.FactsQuery{Target: t}
}
func (allowAll) Authorize(context.Context, authority.Chain, authz.Permission, authority.TargetRef, authority.Facts) error {
	return nil
}

type facts struct{ n int }

func (f *facts) Facts(context.Context, authority.Pins, authority.FactsQuery) (authority.Facts, error) {
	f.n++
	return authority.Facts{Exists: true}, nil
}

// withStep runs fn inside the Apply of a runner-minted Step whose digest covers testTarget/testAttrs.
func withStep(t *testing.T, fn func(ctx context.Context, s step.Step)) {
	t.Helper()
	type none struct{}
	a, err := operation.Define(operation.Typed[none, none, none]{
		Descriptor: operation.Descriptor{ID: "settings.thing.set", Version: 1, Permission: "settings.thing.set",
			Input: "#/components/schemas/Thing", Target: operation.TargetStore, Reversibility: operation.Irreversible, AuditKind: "settings.thing.changed"},
		Plan: func(context.Context, operation.PlanContext, none) ([]operation.TypedStep[none], error) {
			return []operation.TypedStep[none]{{Plan: operation.StepPlan{Target: testTarget, Kind: "user.set", Reversibility: operation.Reversible,
				Diff: []operation.Change{{Attribute: "description", Before: []string{"old"}, After: []string{"new"}}}}}}, nil
		},
		Apply: func(ctx context.Context, s step.Step, _ operation.TypedStep[none]) (none, error) {
			fn(ctx, s)
			return none{}, nil
		},
		Verify: func(context.Context, step.Step, operation.TypedStep[none], none) (operation.Verdict, error) {
			return operation.Verdict{OK: true}, nil
		},
		Inverse: func(operation.TypedStep[none], none) (none, error) { return none{}, operation.ErrIrreversible },
	})
	if err != nil {
		t.Fatal(err)
	}
	reg, err := operation.NewRegistry(a)
	if err != nil {
		t.Fatal(err)
	}
	r, err := operation.NewRunner(operation.Config{DB: fakeDB{}, Audit: sink{}, Authz: allowAll{}, Registry: reg,
		Now: func() time.Time { return time.Unix(1_700_000_000, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.RunStore(context.Background(), operation.Request{Tenant: tenant.New(), Operation: opID, Action: "settings.thing.set",
		Input: operation.Input(`{}`), Actor: authority.Chain{Requester: authority.Principal{ID: account, Kind: authority.Human}}})
	if err != nil {
		t.Fatal(err)
	}
}

func goodOp() WriteOp {
	return WriteOp{DigestKind: "user.set", Target: testTarget, Attrs: testAttrs,
		Connection: &connectorv1.ConnectionRef{ConnectionId: "c1"}, WireTarget: &connectorv1.WriteTarget{}}
}

type builder struct {
	stages []Stage
	err    error
	nilCtx bool
}

func (b *builder) Build(_ context.Context, st Stage, _ WriteOp) (*connectorv1.Tier0Context, error) {
	b.stages = append(b.stages, st)
	if b.err != nil || b.nilCtx {
		return nil, b.err
	}
	return &connectorv1.Tier0Context{}, nil
}

type transport struct {
	plans, applies int
	noOp           bool
	planErr        error
	applyReq       *connectorv1.ApplyRequest
}

func (tr *transport) Plan(context.Context, *connectorv1.PlanRequest) (*connectorv1.PlanResponse, error) {
	tr.plans++
	if tr.planErr != nil {
		return nil, tr.planErr
	}
	return &connectorv1.PlanResponse{NoOp: tr.noOp, Precondition: &connectorv1.TargetPrecondition{StateDigest: []byte{1}}}, nil
}
func (tr *transport) Apply(_ context.Context, r *connectorv1.ApplyRequest) (*connectorv1.ApplyResponse, error) {
	tr.applies++
	tr.applyReq = r
	return &connectorv1.ApplyResponse{Outcome: connectorv1.ApplyOutcome_APPLY_OUTCOME_APPLIED}, nil
}

func TestZeroStepRefusedBeforeTransport(t *testing.T) {
	var zero step.Step
	tr, b := &transport{}, &builder{}
	c := New(WithTransport(tr), WithFacts(&facts{}), WithTier0Builder(b))
	if _, err := c.Write(context.Background(), zero, goodOp()); !errors.Is(err, step.ErrZeroStep) {
		t.Fatalf("got %v, want ErrZeroStep", err)
	}
	if tr.plans+tr.applies != 0 || len(b.stages) != 0 {
		t.Fatal("transport or builder reached with a zero step")
	}
}

func TestRevokedStepRefused(t *testing.T) {
	var kept step.Step
	tr := &transport{}
	withStep(t, func(_ context.Context, s step.Step) { kept = s })
	c := New(WithTransport(tr), WithFacts(&facts{}), WithTier0Builder(&builder{}))
	if _, err := c.Write(context.Background(), kept, goodOp()); !errors.Is(err, step.ErrRevoked) {
		t.Fatalf("got %v, want ErrRevoked", err)
	}
	if tr.plans != 0 {
		t.Fatal("transport reached with a revoked step")
	}
}

func TestFailClosedWithoutBuilder(t *testing.T) {
	tr, f := &transport{}, &facts{}
	c := New(WithTransport(tr), WithFacts(f))
	withStep(t, func(ctx context.Context, s step.Step) {
		if _, err := c.Write(ctx, s, goodOp()); !errors.Is(err, ErrNoTier0Builder) {
			t.Errorf("got %v, want ErrNoTier0Builder", err)
		}
	})
	if tr.plans != 0 || f.n != 0 {
		t.Fatal("something ran with no builder wired")
	}
}

func TestFailClosedBuilderErrorAndNilContext(t *testing.T) {
	for name, b := range map[string]*builder{"error": {err: errors.New("boom")}, "nil": {nilCtx: true}} {
		tr := &transport{}
		c := New(WithTransport(tr), WithFacts(&facts{}), WithTier0Builder(b))
		withStep(t, func(ctx context.Context, s step.Step) {
			if _, err := c.Write(ctx, s, goodOp()); err == nil {
				t.Errorf("%s: write succeeded", name)
			}
		})
		if tr.plans != 0 {
			t.Errorf("%s: plan sent without a Tier0Context", name)
		}
	}
}

func TestDigestMismatchRefused(t *testing.T) {
	tr := &transport{}
	c := New(WithTransport(tr), WithFacts(&facts{}), WithTier0Builder(&builder{}))
	withStep(t, func(ctx context.Context, s step.Step) {
		op := goodOp()
		op.Attrs = []step.Attr{{Name: "description", Values: []string{"other"}}}
		if _, err := c.Write(ctx, s, op); !errors.Is(err, ErrDigest) {
			t.Errorf("got %v, want ErrDigest", err)
		}
	})
	if tr.plans != 0 {
		t.Fatal("transport reached on digest mismatch")
	}
}

func TestWritePlansThenAppliesWithTier0AtBothStages(t *testing.T) {
	tr, b := &transport{}, &builder{}
	c := New(WithTransport(tr), WithFacts(&facts{}), WithTier0Builder(b))
	var res Result
	withStep(t, func(ctx context.Context, s step.Step) {
		var err error
		if res, err = c.Write(ctx, s, goodOp()); err != nil {
			t.Fatal(err)
		}
		d := s.Digest()
		if string(tr.applyReq.GetPlanDigest()) != string(d[:]) || tr.applyReq.GetTier0() == nil || tr.applyReq.GetPrecondition() == nil {
			t.Error("apply request lacks digest, Tier0Context or the plan's precondition")
		}
		if tr.applyReq.GetActingPrincipal().GetAccountId() == nil || tr.applyReq.GetStep().GetItem() != uint32(s.Key().Item) {
			t.Error("apply request lacks the acting principal or step key")
		}
	})
	if res.Apply == nil || tr.plans != 1 || tr.applies != 1 {
		t.Fatalf("plans=%d applies=%d", tr.plans, tr.applies)
	}
	if len(b.stages) != 2 || b.stages[0] != StagePlan || b.stages[1] != StageApply {
		t.Fatalf("builder stages %v", b.stages)
	}
}

func TestNoOpPlanSkipsApply(t *testing.T) {
	tr := &transport{noOp: true}
	c := New(WithTransport(tr), WithFacts(&facts{}), WithTier0Builder(&builder{}))
	withStep(t, func(ctx context.Context, s step.Step) {
		res, err := c.Write(ctx, s, goodOp())
		if err != nil || !res.NoOp {
			t.Errorf("res=%+v err=%v", res, err)
		}
	})
	if tr.applies != 0 {
		t.Fatal("apply sent for a no-op plan")
	}
}

func TestTransportErrorPassesThroughForMapper(t *testing.T) {
	re := &RemoteError{Err: &connectorv1.ConnectorError{Code: connectorv1.ErrorCode_ERROR_CODE_TIER0_REFUSED}}
	c := New(WithTransport(&transport{planErr: re}), WithFacts(&facts{}), WithTier0Builder(&builder{}))
	withStep(t, func(ctx context.Context, s step.Step) {
		_, err := c.Write(ctx, s, goodOp())
		if o := MapError(err); o == nil || o.Status != StatusRefused {
			t.Errorf("outcome %+v", o)
		}
	})
}

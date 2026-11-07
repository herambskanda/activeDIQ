package client

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/writechange"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/secret"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// A Step can only be minted by the operation runner, so the tests obtain one the production way: a
// Store Action whose Apply runs the code under test with the live Step.

const (
	opID    = "6f1c2a40-0000-4000-8000-000000000001"
	account = "6f1c2a40-0000-4000-8000-0000000000aa"
	objGUID = "6f1c2a40-0000-4000-8000-0000000000bb"
	ncGUID  = "6f1c2a40-0000-4000-8000-0000000000cc"

	otherNC  = authority.NamingContextID("6f1c2a40-0000-4000-8000-0000000000dd")
	testKind = connectorv1.WriteKind_WRITE_KIND_OBJECT_UPDATE
)

var (
	testTarget = authority.TargetRef{Connection: "c1", GUID: objGUID, NC: ncGUID}
	testAttrs  = []step.Attr{{Name: "set:description", Values: []string{"s:new"}}}
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
	withStepOf(t, testTarget, authority.Pins{ncGUID: "dc1.corp.example"}, fn)
}

const dsaGUID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

func dsasFor(pins authority.Pins) authority.DSAPins {
	d := authority.DSAPins{}
	for nc := range pins {
		d[nc] = dsaGUID
	}
	return d
}

// withStepOf is withStep for a chosen digested target and DC pin set.
func withStepOf(t *testing.T, target authority.TargetRef, pins authority.Pins, fn func(ctx context.Context, s step.Step)) {
	t.Helper()
	withStepDSA(t, target, pins, dsasFor(pins), fn)
}

// withStepDSA is withStepOf with an explicit DSA pin set.
func withStepDSA(t *testing.T, target authority.TargetRef, pins authority.Pins, dsas authority.DSAPins, fn func(ctx context.Context, s step.Step)) {
	t.Helper()
	withStepKind(t, target, pins, dsas, "ad.object.update", []operation.Change{{Attribute: "set:description", Before: []string{"old"}, After: []string{"s:new"}}}, fn)
}

// withStepKind is withStepDSA for a chosen digest kind and diff.
func withStepKind(t *testing.T, target authority.TargetRef, pins authority.Pins, dsas authority.DSAPins, kind string, diff []operation.Change, fn func(ctx context.Context, s step.Step)) {
	t.Helper()
	type none struct{}
	a, err := operation.Define(operation.Typed[none, none, none]{
		Descriptor: operation.Descriptor{ID: "settings.thing.set", Version: 1, Permission: "settings.thing.set",
			Input: "#/components/schemas/Thing", Target: operation.TargetStore, Reversibility: operation.Irreversible, AuditKind: "settings.thing.changed"},
		Plan: func(context.Context, operation.PlanContext, none) ([]operation.TypedStep[none], error) {
			return []operation.TypedStep[none]{{Plan: operation.StepPlan{Target: target, Kind: kind, Reversibility: operation.Reversible,
				Diff: diff}}}, nil
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
		Input: operation.Input(`{}`), Pins: pins, DSAs: dsas, Actor: authority.Chain{Requester: authority.Principal{ID: account, Kind: authority.Human}}})
	if err != nil {
		t.Fatal(err)
	}
}

func goodOp() WriteOp {
	return WriteOp{DigestKind: "ad.object.update", Target: testTarget, Attrs: testAttrs}
}

type builder struct {
	stages []Stage
	err    error
	nilCtx bool
}

func (b *builder) Build(_ context.Context, st Stage, _ WriteOp) (Tier0, error) {
	b.stages = append(b.stages, st)
	if b.err != nil || b.nilCtx {
		return Tier0{}, b.err
	}
	return Tier0{Context: &connectorv1.Tier0Context{}}, nil
}

type transport struct {
	plans, applies int
	noOp           bool
	planErr        error
	planReq        *connectorv1.PlanRequest
	// otherDC makes the connector answer with a precondition from a different DC.
	otherDC  bool
	applyReq *connectorv1.ApplyRequest
}

func (tr *transport) Plan(_ context.Context, r *connectorv1.PlanRequest) (*connectorv1.PlanResponse, error) {
	tr.plans++
	tr.planReq = r
	if tr.planErr != nil {
		return nil, tr.planErr
	}
	dsa := r.GetDc().GetPinnedDsaGuid()
	if tr.otherDC {
		dsa = &connectorv1.Guid{Value: []byte("0123456789abcdef")}
	}
	return &connectorv1.PlanResponse{NoOp: tr.noOp, Precondition: &connectorv1.TargetPrecondition{
		Dc: &connectorv1.DcIdentity{DsaGuid: dsa}, StateDigest: []byte{1}}}, nil
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
	//fitness:allow-step-escape proves a smuggled copy is refused after the runner revokes it (O1 is the static half)
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
		op.Attrs = []step.Attr{{Name: "set:description", Values: []string{"s:other"}}}
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

func TestWireFieldsDerivedFromTheDigestedTarget(t *testing.T) {
	tr := &transport{}
	c := New(WithTransport(tr), WithFacts(&facts{}), WithTier0Builder(&builder{}))
	withStep(t, func(ctx context.Context, s step.Step) {
		if _, err := c.Write(ctx, s, goodOp()); err != nil {
			t.Fatal(err)
		}
	})
	r := tr.planReq
	if r.GetConnection().GetConnectionId() != "c1" || r.GetKind() != testKind || r.GetChange().GetObjectUpdate() == nil || r.GetTier0Override() != nil {
		t.Errorf("plan request %+v", r)
	}
	want, _ := parseUUID(objGUID)
	if string(r.GetTarget().GetObject().GetValue()) != string(want) {
		t.Error("wire object is not the digested target GUID")
	}
}

func TestMismatchedOpRefusedBeforeTransport(t *testing.T) {
	cases := map[string]struct {
		mut  func(*WriteOp)
		want error
	}{
		"other connection": {func(o *WriteOp) { o.Target.Connection = "other" }, ErrDigest},
		"other object":     {func(o *WriteOp) { o.Target.GUID = ncGUID }, ErrDigest},
		"unknown kind":     {func(o *WriteOp) { o.DigestKind = "user.unknown" }, ErrUnknownKind},
		"wrong case":       {func(o *WriteOp) { o.DigestKind = "AD.object.update" }, ErrUnknownKind},
		"spelled like":     {func(o *WriteOp) { o.DigestKind = "ad.object.createUser" }, ErrUnknownKind},
		"empty kind":       {func(o *WriteOp) { o.DigestKind = "" }, ErrInvalidOp},
		"listed, unwired":  {func(o *WriteOp) { o.DigestKind = "ad.object.move" }, ErrUnknownKind},
		"no connection":    {func(o *WriteOp) { o.Target.Connection = "" }, ErrInvalidOp},
		"other nc":         {func(o *WriteOp) { o.Target.NC = otherNC }, ErrDigest},
		"empty nc":         {func(o *WriteOp) { o.Target.NC = "" }, ErrDigest},
	}
	for name, tc := range cases {
		tr := &transport{}
		c := New(WithTransport(tr), WithFacts(&facts{}), WithTier0Builder(&builder{}))
		withStep(t, func(ctx context.Context, s step.Step) {
			op := goodOp()
			tc.mut(&op)
			if _, err := c.Write(ctx, s, op); !errors.Is(err, tc.want) {
				t.Errorf("%s: got %v, want %v", name, err, tc.want)
			}
		})
		if tr.plans != 0 {
			t.Errorf("%s: transport reached", name)
		}
	}
}

func TestADOpWithoutDCPinRefused(t *testing.T) {
	tr, f := &transport{}, &facts{}
	c := New(WithTransport(tr), WithFacts(f), WithTier0Builder(&builder{}))
	withStepOf(t, testTarget, nil, func(ctx context.Context, s step.Step) {
		op := goodOp()
		if _, err := c.Write(ctx, s, op); !errors.Is(err, ErrNoDCPin) {
			t.Errorf("got %v, want ErrNoDCPin", err)
		}
	})
	if tr.plans != 0 || f.n != 0 {
		t.Fatal("facts or transport reached with no DC pin")
	}
}

type overrideBuilder struct{ builder }

func (overrideBuilder) Build(context.Context, Stage, WriteOp) (Tier0, error) {
	return Tier0{Context: &connectorv1.Tier0Context{}, Override: &connectorv1.WriteGateOverride{}}, nil
}

func TestOverrideComesOnlyFromTheBuilder(t *testing.T) {
	tr := &transport{}
	c := New(WithTransport(tr), WithFacts(&facts{}), WithTier0Builder(overrideBuilder{}))
	withStep(t, func(ctx context.Context, s step.Step) {
		if _, err := c.Write(ctx, s, goodOp()); err != nil {
			t.Fatal(err)
		}
	})
	if tr.planReq.GetTier0Override() == nil || tr.applyReq.GetTier0Override() == nil {
		t.Error("builder's override not carried")
	}
}

func TestTransportErrorTextNeverLeaks(t *testing.T) {
	const dn = "CN=Domain Admins,CN=Users,DC=corp,DC=example"
	st, err := status.New(codes.PermissionDenied, dn).WithDetails(&connectorv1.ConnectorError{Code: connectorv1.ErrorCode_ERROR_CODE_TIER0_REFUSED})
	if err != nil {
		t.Fatal(err)
	}
	for name, terr := range map[string]error{"status with detail": st.Err(), "plain": errors.New(dn)} {
		c := New(WithTransport(&transport{planErr: terr}), WithFacts(&facts{}), WithTier0Builder(&builder{}))
		withStep(t, func(ctx context.Context, s step.Step) {
			_, err := c.Write(ctx, s, goodOp())
			if err == nil || strings.Contains(err.Error(), "CN=") {
				t.Errorf("%s: error %v", name, err)
			}
			if o := MapError(err); name == "status with detail" && (o == nil || o.Status != StatusRefused) {
				t.Errorf("%s: outcome %+v", name, o)
			}
		})
	}
}

// A Step built over a target with no NC cannot be written: the empty NC never means "unpinned".
func TestStepWithoutNCRefused(t *testing.T) {
	tr, f := &transport{}, &facts{}
	c := New(WithTransport(tr), WithFacts(f), WithTier0Builder(&builder{}))
	noNC := testTarget
	noNC.NC = ""
	withStepOf(t, noNC, authority.Pins{ncGUID: "dc1.corp.example"}, func(ctx context.Context, s step.Step) {
		op := goodOp()
		op.Target.NC = ""
		if _, err := c.Write(ctx, s, op); !errors.Is(err, ErrNoNC) {
			t.Errorf("got %v, want ErrNoNC", err)
		}
	})
	if tr.plans != 0 || f.n != 0 {
		t.Fatal("facts or transport reached with no NC")
	}
}

// An NC the Step also happens to pin is still refused when it is not the NC the Step was minted for.
func TestOpNCOtherThanStepNCRefused(t *testing.T) {
	tr, f := &transport{}, &facts{}
	c := New(WithTransport(tr), WithFacts(f), WithTier0Builder(&builder{}))
	withStepOf(t, testTarget, authority.Pins{ncGUID: "dc1.corp.example", otherNC: "dc2.corp.example"}, func(ctx context.Context, s step.Step) {
		op := goodOp()
		op.Target.NC = otherNC
		if _, err := c.Write(ctx, s, op); !errors.Is(err, ErrDigest) {
			t.Errorf("got %v, want ErrDigest", err)
		}
	})
	if tr.plans != 0 || f.n != 0 {
		t.Fatal("facts or transport reached with a foreign NC")
	}
}

func TestPinReadsFactsOnStepNC(t *testing.T) {
	tr := &transport{}
	var got authority.Pins
	c := New(WithTransport(tr), WithFacts(factsFunc(func(p authority.Pins) { got = p })), WithTier0Builder(&builder{}))
	withStep(t, func(ctx context.Context, s step.Step) {
		if _, err := c.Write(ctx, s, goodOp()); err != nil {
			t.Fatal(err)
		}
	})
	if len(got) != 1 || got[ncGUID] != "dc1.corp.example" {
		t.Errorf("facts read on pins %v", got)
	}
	if nc, _ := parseUUID(ncGUID); string(tr.planReq.GetTarget().GetNcGuid().GetValue()) != string(nc) {
		t.Error("wire nc_guid is not the step's NC")
	}
}

type factsFunc func(authority.Pins)

func (f factsFunc) Facts(_ context.Context, p authority.Pins, _ authority.FactsQuery) (authority.Facts, error) {
	f(p)
	return authority.Facts{Exists: true}, nil
}

func TestPinsMutatedAfterMintDoNotRepointStep(t *testing.T) {
	tr := &transport{}
	var got authority.Pins
	c := New(WithTransport(tr), WithFacts(factsFunc(func(p authority.Pins) { got = p })), WithTier0Builder(&builder{}))
	pins := authority.Pins{ncGUID: "dc1.corp.example"}
	withStepOf(t, testTarget, pins, func(ctx context.Context, s step.Step) {
		pins[ncGUID] = "rogue.attacker.example"
		if h, _ := s.DC(ncGUID); h != "dc1.corp.example" {
			t.Errorf("step DC re-pointed to %q", h)
		}
		if _, err := c.Write(ctx, s, goodOp()); err != nil {
			t.Fatal(err)
		}
	})
	if got[ncGUID] != "dc1.corp.example" {
		t.Errorf("facts read on pins %v", got)
	}
}

func TestPlanSendsPinnedDSAGUID(t *testing.T) {
	tr := &transport{}
	c := New(WithTransport(tr), WithFacts(&facts{}), WithTier0Builder(&builder{}))
	withStep(t, func(ctx context.Context, s step.Step) {
		if _, err := c.Write(ctx, s, goodOp()); err != nil {
			t.Fatal(err)
		}
	})
	want, _ := parseUUID(dsaGUID)
	if got := tr.planReq.GetDc().GetPinnedDsaGuid().GetValue(); string(got) != string(want) {
		t.Errorf("PlanRequest.Dc.PinnedDsaGuid = %x, want %x", got, want)
	}
}

func TestApplyRefusedWhenPlanPreconditionNamesAnotherDC(t *testing.T) {
	tr := &transport{otherDC: true}
	c := New(WithTransport(tr), WithFacts(&facts{}), WithTier0Builder(&builder{}))
	withStep(t, func(ctx context.Context, s step.Step) {
		if _, err := c.Write(ctx, s, goodOp()); !errors.Is(err, ErrDCMismatch) {
			t.Fatalf("got %v, want ErrDCMismatch", err)
		}
	})
	if tr.plans != 1 || tr.applies != 0 {
		t.Fatalf("plans %d applies %d, want 1 and 0", tr.plans, tr.applies)
	}
}

func TestApplyRefusedWhenPlanPreconditionHasNoDC(t *testing.T) {
	tr := &noDCTransport{}
	c := New(WithTransport(tr), WithFacts(&facts{}), WithTier0Builder(&builder{}))
	withStep(t, func(ctx context.Context, s step.Step) {
		if _, err := c.Write(ctx, s, goodOp()); !errors.Is(err, ErrDCMismatch) {
			t.Fatalf("got %v, want ErrDCMismatch", err)
		}
	})
	if tr.applies != 0 {
		t.Fatalf("applies %d, want 0", tr.applies)
	}
}

type noDCTransport struct {
	transport
}

func (tr *noDCTransport) Plan(context.Context, *connectorv1.PlanRequest) (*connectorv1.PlanResponse, error) {
	return &connectorv1.PlanResponse{Precondition: &connectorv1.TargetPrecondition{StateDigest: []byte{1}}}, nil
}

func TestPlanWithoutDSAGUIDRefusedBeforeTransport(t *testing.T) {
	for name, dsas := range map[string]authority.DSAPins{
		"absent":    nil,
		"empty":     {ncGUID: ""},
		"malformed": {ncGUID: "not-a-guid"},
		"nil":       {ncGUID: "00000000-0000-0000-0000-000000000000"},
	} {
		tr, f := &transport{}, &facts{}
		c := New(WithTransport(tr), WithFacts(f), WithTier0Builder(&builder{}))
		withStepDSA(t, testTarget, authority.Pins{ncGUID: "dc1.corp.example"}, dsas, func(ctx context.Context, s step.Step) {
			if _, err := c.Write(ctx, s, goodOp()); !errors.Is(err, ErrNoDSAPin) {
				t.Errorf("%s: got %v, want ErrNoDSAPin", name, err)
			}
		})
		if tr.plans != 0 || tr.applies != 0 || f.n != 0 {
			t.Errorf("%s: facts or transport reached without a DSA pin", name)
		}
	}
}

func TestDSAPinMutatedAfterMintDoesNotRepointStep(t *testing.T) {
	tr := &transport{}
	c := New(WithTransport(tr), WithFacts(&facts{}), WithTier0Builder(&builder{}))
	pins := authority.Pins{ncGUID: "dc1.corp.example"}
	dsas := authority.DSAPins{ncGUID: dsaGUID}
	withStepDSA(t, testTarget, pins, dsas, func(ctx context.Context, s step.Step) {
		dsas[ncGUID] = "11111111-1111-1111-1111-111111111111"
		if g, _ := s.DSA(ncGUID); g != dsaGUID {
			t.Errorf("step DSA re-pointed to %q", g)
		}
		if _, err := c.Write(ctx, s, goodOp()); err != nil {
			t.Fatal(err)
		}
	})
	want, _ := parseUUID(dsaGUID)
	if got := tr.planReq.GetDc().GetPinnedDsaGuid().GetValue(); string(got) != string(want) {
		t.Errorf("wire DSA GUID %x, want original %x", got, want)
	}
}

func TestKindTableClosed(t *testing.T) {
	allowed := map[string]bool{"ad.object.create": true, "ad.object.update": true, "ad.object.delete": true, "ad.object.move": true,
		"ad.object.rename": true, "ad.object.restore": true, "ad.user.resetPassword": true, "ad.user.unlock": true,
		"ad.account.enable": true, "ad.account.disable": true}
	seen := map[connectorv1.WriteKind]string{}
	for k, row := range kindTable {
		if !allowed[k] || row.Class == "" || row.Kind == connectorv1.WriteKind_WRITE_KIND_UNSPECIFIED {
			t.Errorf("kindTable row %q is outside the list, has no class or is UNSPECIFIED", k)
		}
		if prev, dup := seen[row.Kind]; dup {
			t.Errorf("kindTable keys %q and %q share a WriteKind", prev, k)
		}
		seen[row.Kind] = k
	}
}

// The wire copy of a create's secret is wiped once Write returns, success or not.
func TestWriteWipesTheWireSecretCopy(t *testing.T) {
	_, attrs, err := writechange.Encode(&connectorv1.WriteChange{Change: &connectorv1.WriteChange_ObjectCreate{ObjectCreate: &connectorv1.ObjectCreate{
		ObjectClass: connectorv1.DirectoryObjectClass_DIRECTORY_OBJECT_CLASS_USER, RdnValue: "x", HasSecretInput: true}}})
	if err != nil {
		t.Fatal(err)
	}
	target := authority.TargetRef{Connection: "c1", Parent: objGUID, Class: "user", RDN: "x", NC: ncGUID}
	tr := &transport{}
	c := New(WithTransport(tr), WithFacts(&facts{}), WithTier0Builder(&builder{}))
	pins := authority.Pins{ncGUID: "dc1.corp.example"}
	var diff []operation.Change
	for _, a := range attrs {
		diff = append(diff, operation.Change{Attribute: a.Name, After: a.Values, Secret: a.Secret})
	}
	withStepKind(t, target, pins, dsasFor(pins), "ad.object.create", diff, func(ctx context.Context, s step.Step) {
		op := WriteOp{DigestKind: "ad.object.create", Target: target, Attrs: attrs, SecretInput: secret.FromBytes([]byte("Sup3r-secret-pw"))}
		if _, err := c.Write(ctx, s, op); err != nil {
			t.Fatal(err)
		}
	})
	m := tr.applyReq.GetSecretInput().GetMaterial()
	if len(m) == 0 {
		t.Fatal("apply carried no secret material")
	}
	for i, b := range m {
		if b != 0 {
			t.Fatalf("wire secret byte %d not wiped", i)
		}
	}
}

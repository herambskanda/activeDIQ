package write

import (
	"context"
	"testing"

	"google.golang.org/protobuf/proto"

	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// ADR-0005 rule 5 at the connector: Plan and Apply run only on the pinned DC. The fake provider has
// no write method, so "no directory write" is structural; "no directory call" is calls == 0 and
// dcReads == 0.

func ruleID(t *testing.T, err error) string {
	t.Helper()
	return connErr(t, err).GetRejectedInput().GetRuleId()
}

// AC1: the bound DC's DSA GUID is not the pin -> typed error, on both transports; no classification.
func TestPlanRefusedWhenBoundDCIsNotThePinnedOne(t *testing.T) {
	run := passRun(nil)
	r := newRig(t, &run)
	r.prov.bound = proto.Clone(testDC()).(*connectorv1.DcIdentity)
	r.prov.bound.DsaGuid = toWire(mk(99))
	id := mk(10)
	for tname, tr := range transports(t, r.h) {
		_, err := tr.Plan(context.Background(), planReq(id, ctxFor(id)))
		if c := connErr(t, err).GetCode(); c != connectorv1.ErrorCode_ERROR_CODE_UNREACHABLE_DC {
			t.Errorf("%s: plan code %v", tname, c)
		}
		_, err = tr.Apply(context.Background(), applyReq(id, ctxFor(id)))
		if c := connErr(t, err).GetCode(); c != connectorv1.ErrorCode_ERROR_CODE_UNREACHABLE_DC {
			t.Errorf("%s: apply code %v", tname, c)
		}
	}
	if n := r.prov.n(); n != 0 {
		t.Fatalf("directory reads after a pin mismatch: %d", n)
	}
}

func TestPlanRefusedWhenBoundDCUnreadableOrProviderCannotSay(t *testing.T) {
	run := passRun(nil)
	r := newRig(t, &run)
	r.prov.boundErr = context.DeadlineExceeded
	id := mk(10)
	_, err := r.h.Plan(context.Background(), planReq(id, ctxFor(id)))
	if c := connErr(t, err).GetCode(); c != connectorv1.ErrorCode_ERROR_CODE_UNREACHABLE_DC {
		t.Fatalf("unreadable: %v", c)
	}
	// An AD provider with no Bound configured fails closed too.
	h, err := New(&ADProvider{ID: adIdentity()}, r.gate)
	if err != nil {
		t.Fatal(err)
	}
	_, err = h.Plan(context.Background(), planReq(id, ctxFor(id)))
	if c := connErr(t, err).GetCode(); c != connectorv1.ErrorCode_ERROR_CODE_UNREACHABLE_DC {
		t.Fatalf("no binder: %v", c)
	}
}

// AC2: Dc unset, PinnedDsaGuid unset, wrong length or nil -> INVALID_ARGUMENT before any directory call.
func TestPlanWithoutAUsablePinIsInvalidBeforeAnyDirectoryCall(t *testing.T) {
	run := passRun(nil)
	r := newRig(t, &run)
	id := mk(10)
	cases := map[string]*connectorv1.DcSelection{
		"unset":     nil,
		"no guid":   {PreferredSite: strptr("Default-First-Site-Name")},
		"nil guid":  {PinnedDsaGuid: &connectorv1.Guid{Value: make([]byte, 16)}},
		"short":     {PinnedDsaGuid: &connectorv1.Guid{Value: []byte{1, 2}}},
		"empty val": {PinnedDsaGuid: &connectorv1.Guid{}},
	}
	for name, dc := range cases {
		for tname, tr := range transports(t, r.h) {
			q := planReq(id, ctxFor(id))
			q.Dc = dc
			_, err := tr.Plan(context.Background(), q)
			if c := connErr(t, err).GetCode(); c != connectorv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT {
				t.Errorf("%s/%s: code %v", name, tname, c)
			} else if rid := ruleID(t, err); rid != "DcRequired" {
				t.Errorf("%s/%s: rule %q", name, tname, rid)
			}
		}
	}
	if r.prov.n() != 0 || r.prov.dcReads != 0 {
		t.Fatalf("directory reached: calls %d dc reads %d", r.prov.n(), r.prov.dcReads)
	}
}

// Apply with a precondition that names no DC, or a nil one, is INVALID_ARGUMENT before any call.
func TestApplyWithoutPreconditionDCIsInvalid(t *testing.T) {
	run := passRun(nil)
	r := newRig(t, &run)
	id := mk(10)
	for name, dc := range map[string]*connectorv1.DcIdentity{"unset": nil, "nil": {DsaGuid: &connectorv1.Guid{Value: make([]byte, 16)}}} {
		q := applyReq(id, ctxFor(id))
		q.Precondition.Dc = dc
		_, err := r.h.Apply(context.Background(), q)
		if connErr(t, err).GetCode() != connectorv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT || ruleID(t, err) != "DcRequired" {
			t.Errorf("%s: %v", name, err)
		}
	}
	if r.prov.n() != 0 || r.prov.dcReads != 0 {
		t.Fatalf("directory reached: calls %d dc reads %d", r.prov.n(), r.prov.dcReads)
	}
}

// The matching pin passes the DC check: the call proceeds to the later steps (the target is an
// ordinary user, so it reaches the kind check).
func TestMatchingPinReachesTheKindCheck(t *testing.T) {
	run := passRun(nil)
	r := newRig(t, &run)
	id := mk(10)
	_, err := r.h.Plan(context.Background(), planReq(id, ctxFor(id)))
	if c := connErr(t, err).GetCode(); c != connectorv1.ErrorCode_ERROR_CODE_CAPABILITY_UNSUPPORTED {
		t.Fatalf("got %v", c)
	}
	if r.prov.dcReads != 1 {
		t.Fatalf("dc reads %d", r.prov.dcReads)
	}
}

// PlanResponse.precondition.dc is the bound DC and equals the pin; a kind that answers with another
// DC is refused. Driven through a registered test kind.
func TestPlanPreconditionDCEqualsThePin(t *testing.T) {
	run := passRun(nil)
	r := newRig(t, &run)
	rec := withTestOp(r)
	id := mk(10)
	q := planReq(id, ctxFor(id))
	q.Kind = 1
	resp, err := r.h.Plan(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	if rec.plan != 1 || !proto.Equal(resp.GetPrecondition().GetDc().GetDsaGuid(), q.GetDc().GetPinnedDsaGuid()) {
		t.Fatalf("plans %d precondition.dc = %v, pin %v", rec.plan, resp.GetPrecondition().GetDc(), q.GetDc())
	}
	// A kind that answers with another DC is refused, not corrected silently.
	op := r.h.ops[1]
	op.Plan = func(context.Context, Authorised, *connectorv1.PlanRequest) (*connectorv1.PlanResponse, error) {
		return &connectorv1.PlanResponse{Precondition: &connectorv1.TargetPrecondition{Dc: &connectorv1.DcIdentity{DsaGuid: toWire(mk(98))}}}, nil
	}
	r.h.ops[1] = op
	_, err = r.h.Plan(context.Background(), q)
	if c := connErr(t, err).GetCode(); c != connectorv1.ErrorCode_ERROR_CODE_UNREACHABLE_DC {
		t.Fatalf("op answered another DC: %v", c)
	}
}

func strptr(s string) *string { return &s }

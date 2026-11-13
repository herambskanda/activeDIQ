package opapi_test

import (
	"bytes"
	"context"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/apihost/apitypes"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/keys"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/operation/opapi"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

func TestMain(m *testing.M) { os.Exit(storetest.Main(m)) }

func TestProblemMapping(t *testing.T) {
	cases := []struct {
		err    error
		status int64
		code   string
	}{
		{operation.ErrNotFound, 404, ""},
		{&operation.NotUndoableError{Code: operation.UndoSuperseded}, 409, "superseded"},
		{fmt.Errorf("x: %w: %w", &operation.NotUndoableError{Code: operation.UndoPlanRefused}, &operation.PlanRefusal{Code: "owner_only"}), 409, "plan_refused"},
		{fmt.Errorf("%w: step_up_required: %w", operation.ErrDenied, operation.ErrStepUpRequired), 401, ""},
		{fmt.Errorf("%w: denied", operation.ErrDenied), 403, ""},
		{errors.New("pq: secret detail"), 500, ""},
	}
	for _, c := range cases {
		p, ok := opapi.Problem(c.err).(*apitypes.Problem)
		if !ok || p.Status != c.status {
			t.Fatalf("%v -> %+v", c.err, opapi.Problem(c.err))
		}
		if c.code != "" && (len(p.Errors) != 1 || p.Errors[0].Code != c.code) {
			t.Fatalf("%v errors = %+v", c.err, p.Errors)
		}
		if p.Detail != nil && (*p.Detail == "pq: secret detail") {
			t.Fatal("driver text leaked")
		}
	}
}

func TestPreviewOf(t *testing.T) {
	p := opapi.PreviewOf(operation.Preview{Action: "a.b.c", Version: 1, PlanHash: "00", Outcome: operation.PreviewRefused,
		Reversibility: operation.Lossy,
		Steps: []operation.StepPlan{{Target: authority.TargetRef{GUID: "g", Class: "reports.schedule"}, Reversibility: operation.Lossy,
			Diff: []operation.Change{{Attribute: "state", Before: []string{"active"}, After: []string{"paused"}}, {Attribute: "secret", Secret: true}}}},
		Blocked:       []operation.Blocked{{Code: "owner_only"}},
		Confirmations: []operation.Confirmation{{Kind: "external_recipients", Items: []string{"x@y.z"}}}})
	if p.HoldReason != apitypes.OperationHoldReasonValueNone || p.Steps[0].Changes[0].After.Text == nil ||
		p.Steps[0].Changes[1].After.Redacted == nil || p.Steps[0].Target.Store.Resource != "reports.schedule" ||
		p.Blocked[0].Target.Store.Resource != "store.object" || p.RequiredConfirmations[0].Items[0] != "x@y.z" || p.Undo.Reversibility != "lossy" {
		t.Fatalf("%+v", p)
	}
}

// ---- end to end through Family over the real runner ----

type kv struct {
	mu sync.Mutex
	v  map[string]string
}
type in struct{ Name, Value string }
type pl struct{ Name, Before, After string }
type out struct{ N int }

type grantAll struct{}

func (grantAll) FactsQuery(_ authority.Chain, _ authz.Permission, t authority.TargetRef) authority.FactsQuery {
	return authority.FactsQuery{Target: t}
}
func (grantAll) Authorize(context.Context, authority.Chain, authz.Permission, authority.TargetRef, authority.Facts) error {
	return nil
}

type inv struct{ operation.Action }

func (i inv) Inverse(p operation.StepPlan, _ operation.Outcome) (operation.Input, error) {
	var x pl
	if err := jsonv2Unmarshal(p.Payload, &x); err != nil {
		return nil, err
	}
	return operation.Input(fmt.Sprintf(`{"Name":%q,"Value":%q}`, x.Name, x.Before)), nil
}

func (k *kv) action(t *testing.T, id operation.ActionID) operation.Action {
	a, err := operation.Define(operation.Typed[in, pl, out]{
		Descriptor: operation.Descriptor{ID: id, Version: 1, Permission: "p.write", Input: "#/x", Target: operation.TargetStore,
			Reversibility: operation.Reversible, AuditKind: "p.thing.changed"},
		Plan: func(_ context.Context, _ operation.PlanContext, i in) ([]operation.TypedStep[pl], error) {
			k.mu.Lock()
			cur := k.v[i.Name]
			k.mu.Unlock()
			if cur == i.Value {
				return nil, nil
			}
			return []operation.TypedStep[pl]{{Plan: operation.StepPlan{Target: authority.TargetRef{GUID: i.Name, Class: "p.thing"}, Kind: "p.set",
				Reversibility: operation.Reversible, Diff: []operation.Change{{Attribute: "value", Before: []string{cur}, After: []string{i.Value}}}},
				Payload: pl{i.Name, cur, i.Value}}}, nil
		},
		Apply: func(_ context.Context, _ step.Step, p operation.TypedStep[pl]) (out, error) {
			k.mu.Lock()
			k.v[p.Payload.Name] = p.Payload.After
			k.mu.Unlock()
			return out{1}, nil
		},
		Verify: func(context.Context, step.Step, operation.TypedStep[pl], out) (operation.Verdict, error) {
			return operation.Verdict{OK: true}, nil
		},
		Inverse: func(operation.TypedStep[pl], out) (in, error) { return in{}, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return inv{a}
}

type storetestKeys struct{}

func (storetestKeys) DEK(context.Context, store.Tx, tenant.ID, uint32) (keys.DEK, error) {
	return keys.DEKFromBytes(1, bytes.Repeat([]byte{7}, keys.DEKSize))
}

func jsonv2Unmarshal(b []byte, v any) error { return jsonv2.Unmarshal(b, v) }

func TestFamilyUndoAndPreview(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, srv *storetest.Server) {
		d := srv.NewDatabase(t)
		d.Migrate(t)
		ctx := context.Background()
		db, err := store.Open(ctx, store.Config{DSN: d.AppDSN()})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(db.Close)
		tn := tenanttest.Seed(t, d.ExecOwner, "A")
		ch := audit.NewChainer(db)
		cp := audit.NewCheckpointer(ch, storetestKeys{})
		if err := db.WithTenant(ctx, tn, func(ctx context.Context, tx store.Tx) error { return cp.InitTenant(ctx, tx, tn) }); err != nil {
			t.Fatal(err)
		}
		k := &kv{v: map[string]string{}}
		reg, err := operation.NewRegistry(k.action(t, "p.thing.set"), k.action(t, "p.thing.restore"))
		if err != nil {
			t.Fatal(err)
		}
		rn, err := operation.NewRunner(operation.Config{DB: db, Audit: ch, Authz: grantAll{}, Registry: reg})
		if err != nil {
			t.Fatal(err)
		}
		who := authority.Chain{Requester: authority.Principal{ID: "alice", Kind: authority.Human}}
		fam := opapi.Family{Prefix: "p.thing", Base: "p.base", Runner: rn,
			Caller: func(context.Context) (tenant.ID, authority.Chain, bool, error) { return tn, who, false, nil }}
		res, err := rn.SubmitStore(ctx, operation.Request{Tenant: tn, Actor: who, Action: "p.thing.set", Input: operation.Input(`{"Name":"a","Value":"1"}`),
			Operation: "00000000-0000-4000-8000-000000000001"})
		if err != nil {
			t.Fatal(err)
		}
		id, _ := apitypes.ParseUUID(string(res.Operation))
		pv, err := fam.PreviewUndo(ctx, id)
		if err != nil || pv.Action != "p.thing.restore" || pv.Outcome != apitypes.OperationPreviewOutcomeReady || k.v["a"] != "1" {
			t.Fatalf("preview %+v %v", pv, err)
		}
		ref, err := fam.Undo(ctx, id, apitypes.OperationUndoRequest{Confirmations: []apitypes.OperationConfirmation{}})
		if err != nil || ref.State != apitypes.OperationStateValueSucceeded || ref.Undoes == nil || ref.Undoes.String() != id.String() || k.v["a"] != "" {
			t.Fatalf("undo %+v %v", ref, err)
		}
		_, err = fam.Undo(ctx, id, apitypes.OperationUndoRequest{})
		if p, ok := err.(*apitypes.Problem); !ok || p.Status != 409 || p.Errors[0].Code != "already_undone" {
			t.Fatalf("second undo: %v", err)
		}
		missing, _ := apitypes.ParseUUID("00000000-0000-4000-8000-0000000000ff")
		if _, err := fam.PreviewUndo(ctx, missing); err == nil {
			t.Fatal("unknown operation previewed")
		} else if p, ok := err.(*apitypes.Problem); !ok || p.Status != 404 {
			t.Fatalf("unknown: %v", err)
		}
	})
}

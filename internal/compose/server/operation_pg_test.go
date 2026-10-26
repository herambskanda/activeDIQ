package server

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/audit/chain"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/keys"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

type fixedKeys struct{}

func (fixedKeys) DEK(context.Context, store.Tx, tenant.ID, uint32) (keys.DEK, error) {
	return keys.DEKFromBytes(1, bytes.Repeat([]byte{9}, keys.DEKSize))
}

type noAnchor struct{}

func (noAnchor) Anchor(context.Context, chain.Checkpoint) error { return nil }

type allowAuthz struct{}

func (allowAuthz) FactsQuery(_ authority.Chain, _ authz.Permission, t authority.TargetRef) authority.FactsQuery {
	return authority.FactsQuery{Target: t}
}

func (allowAuthz) Authorize(context.Context, authority.Chain, authz.Permission, authority.TargetRef, authority.Facts) error {
	return nil
}

type rin struct{ Name string }
type rpayload struct{}
type rout struct{}

func chainedAction(t *testing.T, applyErr error) operation.Action {
	t.Helper()
	a, err := operation.Define(operation.Typed[rin, rpayload, rout]{
		Descriptor: operation.Descriptor{ID: "settings.thing.set", Version: 1, Permission: "settings.thing.set",
			Input: "#/components/schemas/Thing", Target: operation.TargetStore, Reversibility: operation.Irreversible, AuditKind: "settings.thing.changed"},
		Plan: func(context.Context, operation.PlanContext, rin) ([]operation.TypedStep[rpayload], error) {
			return []operation.TypedStep[rpayload]{{Plan: operation.StepPlan{Target: authority.TargetRef{GUID: "row-1", Class: "thing"}, Kind: "set",
				Reversibility: operation.Reversible}}}, nil
		},
		Apply: func(context.Context, step.Step, operation.TypedStep[rpayload]) (rout, error) { return rout{}, applyErr },
		Verify: func(context.Context, step.Step, operation.TypedStep[rpayload], rout) (operation.Verdict, error) {
			return operation.Verdict{OK: true}, nil
		},
		Inverse: func(operation.TypedStep[rpayload], rout) (rin, error) { return rin{}, operation.ErrIrreversible },
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// T-0176 acceptance 1 and 2: the runner built by buildOperation has its events chained by the commit
// hook, a failed run is chained too, and the chain read back verifies.
func TestRunnerEventsAreChainedAtCommit(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		ctx := context.Background()
		var k *operationKernel
		run := func(applyErr error, opID string) error {
			reg, err := operation.NewRegistry(chainedAction(t, applyErr))
			if err != nil {
				t.Fatal(err)
			}
			if k == nil {
				if k, err = buildOperation(operation.HoldsMinter, e.db, directoryFacts(nil), allowAuthz{}, reg); err != nil {
					t.Fatal(err)
				}
			}
			// Each run uses its own registry, so build a runner over it against the same chainer.
			rn, err := operation.NewRunner(operation.Config{DB: e.db, Audit: k.Chainer, Authz: allowAuthz{}, Registry: reg, Component: "test"})
			if err != nil {
				t.Fatal(err)
			}
			_, err = rn.RunStore(ctx, operation.Request{Tenant: e.ten, Operation: step.OperationID(opID), Action: "settings.thing.set",
				Input: operation.Input(`{"Name":"n"}`), Actor: authority.Chain{Requester: authority.Principal{ID: "u1", Kind: authority.Human}}})
			return err
		}
		if err := run(nil, "op-ok"); err == nil {
			// first call only builds the kernel; init the tenant before the first append
			t.Fatal("expected ErrNoHead before InitTenant")
		} else if !errors.Is(err, audit.ErrNoHead) {
			t.Fatalf("run before InitTenant: %v", err)
		}
		cp := audit.NewCheckpointer(k.Chainer, fixedKeys{}, noAnchor{})
		if err := e.db.WithTenant(ctx, e.ten, func(ctx context.Context, tx store.Tx) error { return cp.InitTenant(ctx, tx, e.ten) }); err != nil {
			t.Fatal(err)
		}
		if err := run(nil, "op-ok2"); err != nil {
			t.Fatalf("successful run: %v", err)
		}
		if err := run(errors.New("boom"), "op-bad"); err == nil {
			t.Fatal("failing run reported success")
		}
		human := authority.Chain{Requester: authority.Principal{ID: "u1", Kind: authority.Human}}
		b, err := audit.NewExporter(cp).Export(ctx, e.db, e.ten, human, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		var pinned []string
		if err := e.db.WithTenant(ctx, e.ten, func(ctx context.Context, tx store.Tx) error {
			rows, err := tx.Query(ctx, `SELECT key_id FROM audit_checkpoint_key WHERE tenant_id = $1::uuid ORDER BY ordinal`, e.ten.String())
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var id string
				if err := rows.Scan(&id); err != nil {
					return err
				}
				pinned = append(pinned, id)
			}
			return rows.Err()
		}); err != nil {
			t.Fatal(err)
		}
		if res := chain.Verify(b, chain.Options{Pinned: pinned}); res.Status != chain.OK {
			t.Fatalf("verify = %+v", res)
		}
		var outcomes []string
		for _, ev := range b.Events {
			env, err := chain.ParseEnvelope(ev.Envelope)
			if err != nil {
				t.Fatal(err)
			}
			if env.Component == "test" {
				outcomes = append(outcomes, env.Outcome)
			}
		}
		if len(outcomes) != 2 || outcomes[0] != "success" || outcomes[1] != "failure" {
			t.Fatalf("runner events = %v; want [success failure]", outcomes)
		}
	})
}

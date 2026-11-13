package connection_test

import (
	"context"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

type hookRec struct {
	got  []connection.ID
	fail error
}

func (h *hookRec) ConnectionActivated(_ context.Context, _ store.Tx, _ tenant.ID, c connection.Connection) error {
	if h.fail != nil {
		return h.fail
	}
	h.got = append(h.got, c.ID)
	return nil
}

// The activation hook runs in the activation's transaction, only when the connection becomes active: a
// refused activation tells nobody, and a hook that fails rolls the activation back.
func TestActivationHookRunsOnlyForARealActivation(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		ctx := context.Background()
		cl := &fakeClient{}
		h := &hookRec{}
		svc, err := connection.NewService(e.reg, cl, &recorder{}, connection.WithActivationHook(h))
		if err != nil {
			t.Fatal(err)
		}
		c, err := e.reg.Create(ctx, e.a, forest("corp"))
		if err != nil {
			t.Fatal(err)
		}

		cl.set(overPriv("a"), nil)
		if _, err := svc.Activate(ctx, e.a, c.ID, human("alice")); err == nil {
			t.Fatal("an over-privileged activation was accepted")
		}
		if len(h.got) != 0 {
			t.Fatalf("a refused activation told the hook: %v", h.got)
		}

		cl.set(passing(), nil)
		h.fail = context.DeadlineExceeded
		if _, err := svc.Activate(ctx, e.a, c.ID, human("alice")); err == nil {
			t.Fatal("a failing hook did not fail the activation")
		}
		if got, err := e.reg.Get(ctx, e.a, c.ID); err != nil || got.State == connection.StateActive {
			t.Fatalf("the activation was not rolled back with its hook: %v %v", got.State, err)
		}

		// The stranded run is returned to draft (the sweep does this in production); the next activation
		// succeeds and the hook hears of it exactly once.
		h.fail = nil
		if _, err := e.reg.Transition(ctx, e.a, c.ID, connection.StateVerifying, connection.StateDraft); err != nil {
			t.Fatal(err)
		}
		cl.set(passing(), nil)
		if _, err := svc.Activate(ctx, e.a, c.ID, human("alice")); err != nil {
			t.Fatal(err)
		}
		if len(h.got) != 1 || h.got[0] != c.ID {
			t.Fatalf("hook calls = %v, want one for %s", h.got, c.ID)
		}
	})
}

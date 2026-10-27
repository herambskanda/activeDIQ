package connection_test

import (
	"context"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

// strand puts a draft into verifying as a crashed run leaves it: claimed, never recorded.
func (e *svcEnv) strand(t *testing.T, age time.Duration) connection.Connection {
	t.Helper()
	ctx := context.Background()
	c := e.draft(t)
	if _, err := e.reg.Transition(ctx, e.a, c.ID, connection.StateDraft, connection.StateVerifying); err != nil {
		t.Fatal(err)
	}
	// Through the tenant transaction: row-level security is forced, the owner role sees no rows.
	if n, err := e.raw(e.a, `UPDATE public.connections SET updated_at = now() - make_interval(secs => $2) WHERE id = $1::uuid`,
		string(c.ID), age.Seconds()); err != nil || n != 1 {
		t.Fatalf("backdating: %d %v", n, err)
	}
	return c
}

// Acceptance 1: a connection in verifying with no live run returns to draft with a failed run recorded.
func TestSweepReturnsStrandedConnectionToDraftWithFailedRun(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := newSvc(t, s)
		ctx := context.Background()
		c := e.strand(t, time.Hour)
		swept, err := e.svc.SweepStranded(ctx, e.a, 0)
		if err != nil || len(swept) != 1 || swept[0] != c.ID {
			t.Fatalf("swept %v, %v", swept, err)
		}
		got, err := e.reg.Get(ctx, e.a, c.ID)
		if err != nil || got.State != connection.StateDraft || got.LastVerificationID == "" {
			t.Fatalf("connection: %+v %v", got, err)
		}
		var verdict, outcome string
		err = e.db.WithTenant(ctx, e.a, func(ctx context.Context, tx store.Tx) error {
			return tx.QueryRow(ctx, `SELECT verdict, outcomes->>'V7' FROM public.connection_verifications WHERE id = $1::uuid`,
				got.LastVerificationID).Scan(&verdict, &outcome)
		})
		if err != nil || verdict != "failed" || outcome != "not_run" {
			t.Fatalf("run: %q %q %v", verdict, outcome, err)
		}
		if h, err := e.reg.Health(ctx, e.a, c.ID, false, time.Now()); err != nil || h.WriteGateOpen {
			t.Fatalf("the write gate must stay shut: %+v %v", h, err)
		}
		if k := e.rec.kinds(); len(k) != 1 || k[0] != connection.AuditVerificationCompleted {
			t.Fatalf("audit: %v", k)
		}
		// A second sweep finds nothing.
		if swept, err := e.svc.SweepStranded(ctx, e.a, 0); err != nil || len(swept) != 0 {
			t.Fatalf("second sweep: %v %v", swept, err)
		}
	})
}

// A run that may still be live (verifying for less than the grace) is left alone.
func TestSweepLeavesALiveRunAlone(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := newSvc(t, s)
		ctx := context.Background()
		c := e.strand(t, time.Minute)
		swept, err := e.svc.SweepStranded(ctx, e.a, 0)
		if err != nil || len(swept) != 0 {
			t.Fatalf("swept %v, %v", swept, err)
		}
		if got, _ := e.reg.Get(ctx, e.a, c.ID); got.State != connection.StateVerifying {
			t.Fatalf("state %s", got.State)
		}
	})
}

// The sweep is tenant-scoped: another tenant's stranded connection is untouched.
func TestSweepIsTenantScoped(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := newSvc(t, s)
		ctx := context.Background()
		c := e.strand(t, time.Hour)
		if swept, err := e.svc.SweepStranded(ctx, e.b, 0); err != nil || len(swept) != 0 {
			t.Fatalf("swept %v, %v", swept, err)
		}
		if got, _ := e.reg.Get(ctx, e.a, c.ID); got.State != connection.StateVerifying {
			t.Fatalf("state %s", got.State)
		}
	})
}

package fleetsql_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/fleet"
	"github.com/skenzeriq/activediq/internal/platform/fleet/fleetsql"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

type bothAuthz struct{ revoke, issue bool }

func (a bothAuthz) Allow(_ context.Context, _ apihost.Principal, perm, scope string) (bool, error) {
	if scope != "tenant" {
		return false, nil
	}
	return (perm == fleetsql.PermissionRevoke && a.revoke) || (perm == fleetsql.PermissionIssue && a.issue), nil
}

func TestReenrolAddc(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		ctx := context.Background()
		e := setupEnroll(t, s)
		cl := &closer{}
		mk := func(az bothAuthz, fresh bool) *fleetsql.Reenroller {
			return &fleetsql.Reenroller{DB: e.db, Authz: az, StepUp: fakeStepUp{fresh}, Audit: e.sink, Streams: cl}
		}
		dc1 := e.enrolled(t, e.a, fleetsql.KindADDC)
		dc2 := e.enrolled(t, e.a, fleetsql.KindADDC)
		conn := e.enrolled(t, e.a, fleetsql.KindConnector)
		foreign := e.enrolled(t, e.b, fleetsql.KindADDC)
		time.Sleep(20 * time.Millisecond)
		cutoff := time.Now() // the new key became active now; the agents above predate it
		req := fleetsql.ReenrolRequest{Reason: fleetsql.ReasonKeyExposure, EnrolledBefore: cutoff}

		// Refusals write nothing: no step-up, missing right, bad reason.
		before := len(e.sink.evs)
		if _, err := mk(bothAuthz{true, true}, false).ReenrolAddc(ctx, e.a, admin, req); !errors.Is(err, fleetsql.ErrStepUpRequired) {
			t.Fatalf("no step-up: %v", err)
		}
		if _, err := mk(bothAuthz{true, false}, true).ReenrolAddc(ctx, e.a, admin, req); !errors.Is(err, fleetsql.ErrReenrolForbidden) {
			t.Fatalf("missing issue right: %v", err)
		}
		if _, err := mk(bothAuthz{true, true}, true).ReenrolAddc(ctx, e.a, admin, fleetsql.ReenrolRequest{Reason: "because", EnrolledBefore: cutoff}); !errors.Is(err, fleetsql.ErrReenrolReason) {
			t.Fatalf("bad reason: %v", err)
		}
		for _, bad := range []time.Time{{}, time.Now().Add(time.Hour)} {
			if _, err := mk(bothAuthz{true, true}, true).ReenrolAddc(ctx, e.a, admin, fleetsql.ReenrolRequest{Reason: fleetsql.ReasonKeyExposure, EnrolledBefore: bad}); !errors.Is(err, fleetsql.ErrReenrolCutoff) {
				t.Fatalf("bad cutoff %v: %v", bad, err)
			}
		}
		if len(e.sink.evs) != before {
			t.Fatal("a refused sweep wrote audit events")
		}
		if ok, _ := (&fleetsql.Lifecycle{DB: e.db}).Usable(ctx, dc1); !ok {
			t.Fatal("refused sweep revoked an agent")
		}

		res, err := mk(bothAuthz{true, true}, true).ReenrolAddc(ctx, e.a, admin, req)
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Items) != 2 || res.Succeeded() != 2 {
			t.Fatalf("items: %+v", res.Items)
		}
		sweepEvs := append([]audit.Event(nil), e.sink.evs[before:]...)
		lc := &fleetsql.Lifecycle{DB: e.db}
		for _, id := range []string{dc1.ComponentID, dc2.ComponentID} {
			if st, _ := e.state(t, e.a, id); st != "revoked" {
				t.Fatalf("old agent state %s", st)
			}
		}
		if ok, _ := lc.Usable(ctx, dc1); ok {
			t.Fatal("old agent still usable")
		}
		for _, id := range []fleet.Identity{conn, foreign} {
			if ok, _ := lc.Usable(ctx, id); !ok {
				t.Fatal("sweep touched a connector or another tenant")
			}
		}
		if len(cl.calls) != 2 {
			t.Fatalf("streams closed for %v", cl.calls)
		}
		var redeemed []fleet.Identity
		// Each successor is pending and its token redeems; the agent then holds a new certificate.
		for _, it := range res.Items {
			if it.Token.String() == "" || it.NewComponentID == "" {
				t.Fatalf("no successor: %+v", it)
			}
			if st, _ := e.state(t, e.a, it.NewComponentID); st != "pending" {
				t.Fatalf("successor state %s", st)
			}
			csr, _ := csrFor(t, nil)
			got, err := e.enr.Enroll(ctx, peerIP, it.Token.String(), csr)
			if err != nil {
				t.Fatalf("re-enrol: %v", err)
			}
			redeemed = append(redeemed, got.Identity)
			if got.Identity.ComponentID != it.NewComponentID || got.Identity.Kind != string(fleetsql.KindADDC) {
				t.Fatalf("re-enrolled as %+v", got.Identity)
			}
		}
		// Audit: one event per agent plus the summary, all by the human.
		evs := sweepEvs
		if len(evs) != 3 {
			t.Fatalf("audit events: %d", len(evs))
		}
		for _, ev := range evs[:2] {
			if ev.Kind != "fleet.component.revoked" || ev.Reason != fleetsql.ReasonKeyExposure || ev.Actor.Requester.ID != "human-1" {
				t.Fatalf("agent event: %+v", ev)
			}
		}
		if ev := evs[2]; ev.Kind != "fleet.agents.reenrol_sweep" || ev.Outcome != "success" {
			t.Fatalf("summary: %+v", ev)
		}

		// Rerun with the same cutoff: the redeemed successors are newer than the cutoff, so
		// nothing is swept and they stay usable (idempotent).
		res2, err := mk(bothAuthz{true, true}, true).ReenrolAddc(ctx, e.a, admin, req)
		if err != nil || len(res2.Items) != 0 {
			t.Fatalf("second sweep: %v %+v", err, res2.Items)
		}
		for _, id := range redeemed {
			if ok, _ := lc.Usable(ctx, id); !ok {
				t.Fatal("rerun revoked a re-enrolled agent")
			}
		}
	})
}

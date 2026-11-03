package connection_test

import (
	"context"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

// broadWarn is a V7 run whose only findings are warn-severity broad-principal exposure on tier0
// objects (T-0237, T-1245): the customer's own ACL, such as Certificate-Enrollment for Authenticated
// Users on stock AD CS objects. The connector's verdict for it is pass with V7 = warn.
func broadWarn(n int) connection.VerifyResult {
	r := passing()
	r.Outcomes = map[connection.Check]connection.Outcome{
		"V1": connection.OutcomePass, "V5": connection.OutcomePass, "V7": connection.OutcomeWarn, "V8": connection.OutcomePass,
	}
	for i := 0; i < n; i++ {
		r.Findings = append(r.Findings, connection.Finding{Check: "V7", Code: "exposure.tier0_broad_principal",
			Kind: connection.FindingExcessiveRight, Severity: connection.SeverityWarn, ObjectGUID: idA, Fingerprint: fp(string(rune('a' + i)))})
	}
	return r
}

// T-1245 AC1: a pass verdict with V7 = warn activates (the database trigger agrees), the write gate
// is open without any acknowledgement, no override or Tier-0 banner appears, and Health says the
// connection needs attention with the count; the details need the verify permission (FR-16).
func TestActivationOnV7WarnActivates(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := newSvc(t, s)
		ctx := context.Background()
		c := e.draft(t)
		e.cl.set(broadWarn(8), nil)
		out, err := e.svc.Activate(ctx, e.a, c.ID, human("alice"))
		if err != nil {
			t.Fatalf("activation on V7 warn: %v", err)
		}
		if out.Connection.State != connection.StateActive {
			t.Fatalf("state %s", out.Connection.State)
		}
		h, err := e.reg.Health(ctx, e.a, c.ID, false, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if h.Status != connection.HealthAttention || h.ExcessiveCount != 8 || len(h.Excessive) != 0 || h.Tier0Installation || h.Override != nil || !h.WriteGateOpen {
			t.Fatalf("health: %+v", h)
		}
		h, _ = e.reg.Health(ctx, e.a, c.ID, true, time.Now())
		if len(h.Excessive) != 8 {
			t.Fatalf("details for the verify permission: %d", len(h.Excessive))
		}
	})
}

// A scheduled run that turns pass into warn leaves the write gate open; one that turns warn into a
// fail closes it. The override covers a fail only: warn fingerprints are never acknowledged.
func TestScheduledV7WarnKeepsTheWriteGateOpen(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := newSvc(t, s)
		ctx := context.Background()
		c := e.draft(t)
		e.cl.set(passing(), nil)
		if _, err := e.svc.Activate(ctx, e.a, c.ID, human("alice")); err != nil {
			t.Fatal(err)
		}
		e.cl.set(broadWarn(2), nil)
		if res, err := e.svc.RunScheduled(ctx, e.a); err != nil || len(res) != 1 || res[0].Err != nil {
			t.Fatalf("scheduled: %+v %v", res, err)
		}
		h, _ := e.reg.Health(ctx, e.a, c.ID, false, time.Now())
		if !h.WriteGateOpen || h.Status != connection.HealthAttention || h.ExcessiveCount != 2 {
			t.Fatalf("after warn: %+v", h)
		}
		e.cl.set(overPriv("x"), nil)
		if _, err := e.svc.RunScheduled(ctx, e.a); err != nil {
			t.Fatal(err)
		}
		if h, _ = e.reg.Health(ctx, e.a, c.ID, false, time.Now()); h.WriteGateOpen {
			t.Fatalf("a V7 fail left the gate open: %+v", h)
		}
	})
}

// DM-25.I4: a later run whose V7 is warn (not a fail) clears an override, as a pass does, so the
// "activeDIQ is Tier 0" banner does not stay up for a customer who has only broad-principal warns.
func TestV7WarnClearsAnOverride(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := newSvc(t, s)
		ctx := context.Background()
		c := e.draft(t)
		e.cl.set(overPriv("a"), nil)
		out, _ := e.svc.Activate(ctx, e.a, c.ID, human("alice"))
		if _, err := e.ack(t, c.ID, out.Verification.ID); err != nil {
			t.Fatal(err)
		}
		if err := e.activate(t, c.ID); err != nil {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond) // the clearing run completes after the acknowledgement
		e.cl.set(broadWarn(1), nil)
		if _, err := e.svc.RunScheduled(ctx, e.a); err != nil {
			t.Fatal(err)
		}
		if o, err := e.reg.Tier0OverrideInForce(ctx, e.a, c.ID); err != nil || o != nil {
			t.Fatalf("override still in force: %+v %v", o, err)
		}
		h, _ := e.reg.Health(ctx, e.a, c.ID, false, time.Now())
		if h.Tier0Installation || !h.WriteGateOpen {
			t.Fatalf("health: %+v", h)
		}
	})
}

// The gate functions read the over-privilege check through one rule for AD and Entra: pass and warn
// are clear, fail is not (without an override), could_not_verify and not_run never are.
func TestOverPrivilegeWarnIsClearForBothKinds(t *testing.T) {
	cases := []struct {
		kind connection.Kind
		oc   map[connection.Check]connection.Outcome
		chk  connection.Check
	}{
		{connection.KindADForest, map[connection.Check]connection.Outcome{"V5": connection.OutcomePass, "V8": connection.OutcomePass}, "V7"},
		{connection.KindEntraTenant, map[connection.Check]connection.Outcome{"EV2": connection.OutcomePass, "EV4": connection.OutcomePass}, "EV3"},
	}
	for _, tc := range cases {
		for o, want := range map[connection.Outcome]bool{
			connection.OutcomePass: true, connection.OutcomeWarn: true,
			connection.OutcomeFail: false, connection.OutcomeCouldNotVerify: false, connection.OutcomeNotRun: false,
		} {
			oc := map[connection.Check]connection.Outcome{tc.chk: o}
			for k, v := range tc.oc {
				oc[k] = v
			}
			v := connection.Verification{Verdict: connection.VerdictPass, Outcomes: oc}
			if ok, _ := connection.Qualifies(tc.kind, v, nil); ok != want {
				t.Errorf("%s %s: Qualifies = %v, want %v", tc.kind, o, ok, want)
			}
			if got := connection.WriteGateOpen(tc.kind, &v, nil); got != want {
				t.Errorf("%s %s: WriteGateOpen = %v, want %v", tc.kind, o, got, want)
			}
		}
	}
}

package connection_test

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

func (e *svcEnv) ack(t *testing.T, id connection.ID, ver connection.VerificationID) (connection.Tier0Override, error) {
	t.Helper()
	var o connection.Tier0Override
	err := e.db.WithTenant(context.Background(), e.a, func(ctx context.Context, tx store.Tx) (err error) {
		o, err = connection.Store{}.AcknowledgeTier0Override(ctx, tx, connection.AcknowledgeInput{ConnectionID: id, VerificationID: ver, By: "alice"})
		return
	})
	return o, err
}

func (e *svcEnv) activate(t *testing.T, id connection.ID) error {
	t.Helper()
	return e.db.WithTenant(context.Background(), e.a, func(ctx context.Context, tx store.Tx) error {
		_, err := connection.Store{}.Activate(ctx, tx, id)
		return err
	})
}

// An override covers exactly the findings shown: activation works on the same set, and a new finding
// needs a new acknowledgement (DM-25.I3, spec FR-13).
func TestOverrideCoversTheSetShownAndNoMore(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := newSvc(t, s)
		ctx := context.Background()
		c := e.draft(t)
		e.cl.set(overPriv("a", "b"), nil)
		out, err := e.svc.Activate(ctx, e.a, c.ID, human("alice"))
		if !errors.Is(err, connection.ErrActivationRefused) {
			t.Fatalf("first activation: %v", err)
		}
		if err := e.activate(t, c.ID); err == nil {
			t.Fatal("activated with no override")
		}
		ov, err := e.ack(t, c.ID, out.Verification.ID)
		if err != nil || len(ov.AcknowledgedFingerprints) != 2 {
			t.Fatalf("ack: %+v %v", ov, err)
		}
		if err := e.activate(t, c.ID); err != nil {
			t.Fatalf("activation with the override: %v", err)
		}
		h, _ := e.reg.Health(ctx, e.a, c.ID, false, time.Now())
		if !h.Tier0Installation || h.Status != connection.HealthTier0 || h.Override == nil || h.Override.AcknowledgedBy != "alice" || !h.WriteGateOpen {
			t.Fatalf("health: %+v", h)
		}
		// A scheduled run finds a third right: the gate closes, the banner stays.
		e.cl.set(overPriv("a", "b", "c"), nil)
		if _, err := e.svc.Verify(ctx, e.a, c.ID, connection.KindManual, human("alice")); err != nil {
			t.Fatal(err)
		}
		h, _ = e.reg.Health(ctx, e.a, c.ID, false, time.Now())
		if !h.Tier0Installation || h.WriteGateOpen {
			t.Fatalf("new finding must close the write gate and keep the banner: %+v", h)
		}
		// Clearing: the rights are removed, the next passing run clears the override for good.
		e.cl.set(passing(), nil)
		h, err = e.svc.ClearOverride(ctx, e.a, c.ID, human("alice"))
		if err != nil || h.Tier0Installation || h.Status != connection.HealthOK {
			t.Fatalf("after clear: %+v %v", h, err)
		}
		e.cl.set(overPriv("a", "b"), nil)
		if _, err := e.svc.Verify(ctx, e.a, c.ID, connection.KindManual, human("alice")); err != nil {
			t.Fatal(err)
		}
		h, _ = e.reg.Health(ctx, e.a, c.ID, false, time.Now())
		if h.Tier0Installation || h.WriteGateOpen {
			t.Fatalf("a cleared override never comes back (DM-25.I4): %+v", h)
		}
	})
}

// ClearOverride with the rights still there leaves the override and the banner in force: there is no undo.
func TestClearOverrideWhileStillOverPrivilegedKeepsTheBanner(t *testing.T) {
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
		h, err := e.svc.ClearOverride(ctx, e.a, c.ID, human("alice"))
		if err != nil || !h.Tier0Installation {
			t.Fatalf("%+v %v", h, err)
		}
	})
}

// An override is never accepted for anything but over-privilege alone, a stale or old run (FR-13).
func TestOverrideRefusals(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := newSvc(t, s)
		ctx := context.Background()
		code := func(err error) string {
			var oe *connection.OverrideError
			if errors.As(err, &oe) {
				return oe.Code
			}
			return "other:" + errString(err)
		}
		// V8 failing alongside V7: not overridable.
		c := e.draft(t)
		r := overPriv("a")
		r.Outcomes["V8"] = connection.OutcomeFail
		e.cl.set(r, nil)
		out, _ := e.svc.Activate(ctx, e.a, c.ID, human("alice"))
		if _, err := e.ack(t, c.ID, out.Verification.ID); code(err) != connection.ReasonNotOverridable {
			t.Errorf("V8 fail: %s", code(err))
		}
		// Could not verify: not overridable.
		r = overPriv("a")
		r.Verdict, r.Outcomes["V7"] = connection.VerdictCouldNotVerify, connection.OutcomeCouldNotVerify
		e.cl.set(r, nil)
		out, _ = e.svc.Activate(ctx, e.a, c.ID, human("alice"))
		if _, err := e.ack(t, c.ID, out.Verification.ID); code(err) != connection.ReasonCouldNotVerify {
			t.Errorf("could not verify: %s", code(err))
		}
		// A pass has nothing to acknowledge.
		e.cl.set(passing(), nil)
		out, _ = e.svc.Verify(ctx, e.a, c.ID, connection.KindOnboarding, human("alice"))
		if _, err := e.ack(t, c.ID, out.Verification.ID); code(err) != connection.ReasonNotOverridable {
			t.Errorf("pass: %s", code(err))
		}
		// Not the newest run.
		e.cl.set(overPriv("a"), nil)
		old, _ := e.svc.Verify(ctx, e.a, c.ID, connection.KindOnboarding, human("alice"))
		if _, err := e.svc.Verify(ctx, e.a, c.ID, connection.KindOnboarding, human("alice")); err != nil {
			t.Fatal(err)
		}
		if _, err := e.ack(t, c.ID, old.Verification.ID); code(err) != connection.ReasonNotLatestRun {
			t.Errorf("old run: %s", code(err))
		}
	})
}

// backdate ages every verification of the tenant by d, as the owner with the append-only trigger
// off for the statement: the only way a test can make a run old, since completed_at is a DB stamp.
func (e *svcEnv) backdate(t *testing.T, d time.Duration) {
	t.Helper()
	sql := fmt.Sprintf(`ALTER TABLE public.connection_verifications DISABLE TRIGGER connection_verifications_append_only;
		ALTER TABLE public.connection_verifications NO FORCE ROW LEVEL SECURITY;
		UPDATE public.connection_verifications SET started_at = started_at - interval '%d seconds', completed_at = completed_at - interval '%d seconds' WHERE tenant_id = '%s';
		ALTER TABLE public.connection_verifications FORCE ROW LEVEL SECURITY;
		ALTER TABLE public.connection_verifications ENABLE TRIGGER connection_verifications_append_only;`, int(d.Seconds()), int(d.Seconds()), e.a)
	if err := e.d.ExecOwner(context.Background(), sql); err != nil {
		t.Fatal(err)
	}
}

// A run older than 15 minutes opens neither the gate nor an override (FR-17); Activate re-verifies.
func TestStaleRunNeitherActivatesNorBacksAnOverride(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := newSvc(t, s)
		ctx := context.Background()
		c := e.draft(t)
		e.cl.set(passing(), nil)
		if _, err := e.svc.Verify(ctx, e.a, c.ID, connection.KindOnboarding, human("alice")); err != nil {
			t.Fatal(err)
		}
		e.backdate(t, 20*time.Minute)
		var ae *connection.ActivationError
		if err := e.activate(t, c.ID); !errors.As(err, &ae) || ae.Code != connection.ReasonStaleVerification {
			t.Fatalf("stale activation: %v", err)
		}
		// The service runs a new verification inline instead of trusting the old one.
		if _, err := e.svc.Activate(ctx, e.a, c.ID, human("alice")); err != nil || e.cl.calls != 2 {
			t.Fatalf("inline re-verify: %v, connector calls %d", err, e.cl.calls)
		}
		c2 := e.draft(t)
		e.cl.set(overPriv("a"), nil)
		out, _ := e.svc.Verify(ctx, e.a, c2.ID, connection.KindOnboarding, human("alice"))
		e.backdate(t, 20*time.Minute)
		var oe *connection.OverrideError
		if _, err := e.ack(t, c2.ID, out.Verification.ID); !errors.As(err, &oe) || oe.Code != connection.ReasonStaleVerification {
			t.Fatalf("stale override: %v", err)
		}
	})
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// The database refuses an override that names another connection's run.
func TestOverrideEvidenceMustBelongToTheConnection(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := newSvc(t, s)
		ctx := context.Background()
		c1, c2 := e.draft(t), e.draft(t)
		e.cl.set(overPriv("a"), nil)
		out, _ := e.svc.Verify(ctx, e.a, c1.ID, connection.KindOnboarding, human("alice"))
		_, err := e.raw(e.a, `INSERT INTO public.connection_tier0_overrides (tenant_id, connection_id, credential_id, verification_id, acknowledged_by, acknowledged_at, acknowledged_fingerprints)
			VALUES (NULLIF(current_setting('app.tenant_id', true), '')::uuid, $1::uuid, $2::uuid, $3::uuid, 'x', now(), ARRAY['f'])`,
			string(c2.ID), cred, string(out.Verification.ID))
		if err == nil {
			t.Fatal("cross-connection evidence accepted")
		}
	})
}

// derived is everything DM-25.I6 says retention must not change for a kept override.
type derived struct {
	InForce  *connection.Tier0Override
	Health   connection.Health
	GateOpen bool
}

func (e *svcEnv) derive(t *testing.T, id connection.ID, now time.Time) derived {
	t.Helper()
	h, err := e.reg.Health(context.Background(), e.a, id, true, now)
	if err != nil {
		t.Fatal(err)
	}
	var in *connection.Tier0Override
	if err := e.db.WithTenant(context.Background(), e.a, func(ctx context.Context, tx store.Tx) (err error) {
		in, err = connection.Store{}.Tier0OverrideInForce(ctx, tx, id)
		return
	}); err != nil {
		t.Fatal(err)
	}
	return derived{InForce: in, Health: h, GateOpen: h.WriteGateOpen}
}

// purgeRuns removes the given runs and their findings as a retention pass would: the owner, with the
// append-only guard off for the statement. Only the unpinned runs are ever passed in.
func (e *svcEnv) purgeRuns(t *testing.T, ids ...connection.VerificationID) {
	t.Helper()
	for _, id := range ids {
		sql := fmt.Sprintf(`ALTER TABLE public.connection_verification_findings DISABLE TRIGGER connection_verification_findings_append_only;
			ALTER TABLE public.connection_verifications DISABLE TRIGGER connection_verifications_append_only;
			ALTER TABLE public.connection_verification_findings NO FORCE ROW LEVEL SECURITY;
			ALTER TABLE public.connection_verifications NO FORCE ROW LEVEL SECURITY;
			DELETE FROM public.connection_verification_findings WHERE verification_id = '%[1]s';
			DELETE FROM public.connection_verifications WHERE id = '%[1]s';
			ALTER TABLE public.connection_verification_findings FORCE ROW LEVEL SECURITY;
			ALTER TABLE public.connection_verifications FORCE ROW LEVEL SECURITY;
			ALTER TABLE public.connection_verification_findings ENABLE TRIGGER connection_verification_findings_append_only;
			ALTER TABLE public.connection_verifications ENABLE TRIGGER connection_verifications_append_only;`, id)
		if err := e.d.ExecOwner(context.Background(), sql); err != nil {
			t.Fatal(err)
		}
	}
}

// DM-25.I6: every derived state of a kept override reads only pinned rows (its evidence run, the
// clearing run, the newest run), so removing every other run changes neither the override's state
// nor the DM-10.I9 / I11 result. No retention pass exists yet; this proves the derivation's side of
// the contract by removing exactly the rows retention may remove. The crash-inside-a-pass half
// belongs to the retention job when it lands.
func TestProperty_DM25_I6(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := newSvc(t, s)
		ctx := context.Background()
		c := e.draft(t)
		active := false
		verify := func(r connection.VerifyResult) connection.VerificationID {
			t.Helper()
			e.cl.set(r, nil)
			if active {
				res, err := e.svc.RunScheduled(ctx, e.a)
				if err != nil || len(res) != 1 || res[0].Err != nil {
					t.Fatalf("scheduled: %+v %v", res, err)
				}
				return res[0].Outcome.Verification.ID
			}
			out, err := e.svc.Verify(ctx, e.a, c.ID, connection.KindOnboarding, human("alice"))
			if err != nil {
				t.Fatal(err)
			}
			return out.Verification.ID
		}
		unpinnedOld := verify(passing())
		evidence := verify(overPriv("a"))
		if _, err := e.ack(t, c.ID, evidence); err != nil {
			t.Fatal(err)
		}
		if err := e.activate(t, c.ID); err != nil {
			t.Fatal(err)
		}
		active = true
		unpinnedMid := verify(overPriv("a")) // still excessive: not a clearing run, not the evidence

		now := time.Now()
		// in_force: the override stands.
		before := e.derive(t, c.ID, now)
		if before.InForce == nil || !before.Health.Tier0Installation {
			t.Fatalf("override not in force: %+v", before)
		}
		newest := verify(overPriv("a"))
		before = e.derive(t, c.ID, now)
		e.purgeRuns(t, unpinnedOld, unpinnedMid)
		if after := e.derive(t, c.ID, now); !reflect.DeepEqual(before, after) {
			t.Fatalf("in_force state changed by retention:\nbefore %+v\nafter  %+v", before, after)
		}

		// cleared: a run with the over-privilege check at pass ends it for good.
		unpinnedLate := verify(overPriv("a"))
		clearing := verify(passing())
		before = e.derive(t, c.ID, now)
		if before.InForce != nil {
			t.Fatalf("override not cleared: %+v", before.InForce)
		}
		e.purgeRuns(t, newest, unpinnedLate)
		if after := e.derive(t, c.ID, now); !reflect.DeepEqual(before, after) {
			t.Fatalf("cleared state changed by retention:\nbefore %+v\nafter  %+v", before, after)
		}
		_ = clearing
	})
}

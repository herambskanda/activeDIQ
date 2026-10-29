package connection_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

const forestRoot = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"

// fp returns a distinct, valid fingerprint per seed.
func fp(seed string) string { h := sha256.Sum256([]byte(seed)); return hex.EncodeToString(h[:]) }

type fakeClient struct {
	mu    sync.Mutex
	res   connection.VerifyResult
	err   error
	calls int
}

func (f *fakeClient) set(r connection.VerifyResult, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.res, f.err = r, err
}

func (f *fakeClient) VerifyConnection(context.Context, connection.VerifyRequest) (connection.VerifyResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.res, f.err
}

type recorder struct {
	mu  sync.Mutex
	evs []audit.Event
}

func (r *recorder) Append(_ context.Context, _ store.Tx, ev audit.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.evs = append(r.evs, ev)
	return nil
}

func (r *recorder) kinds() []audit.Kind {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []audit.Kind
	for _, e := range r.evs {
		out = append(out, e.Kind)
	}
	return out
}

func human(id string) authority.Chain {
	return authority.Chain{Requester: authority.Principal{ID: authority.PrincipalID(id), Kind: authority.Human}}
}

var allPass = map[connection.Check]connection.Outcome{
	"V1": connection.OutcomePass, "V5": connection.OutcomePass, "V7": connection.OutcomePass, "V8": connection.OutcomePass,
}

func passing() connection.VerifyResult {
	return connection.VerifyResult{DirectoryIdentity: forestRoot, CheckListVersion: 1, Outcomes: allPass, Verdict: connection.VerdictPass}
}

func overPriv(seeds ...string) connection.VerifyResult {
	r := connection.VerifyResult{DirectoryIdentity: forestRoot, CheckListVersion: 1, Verdict: connection.VerdictRefused,
		Outcomes: map[connection.Check]connection.Outcome{"V1": connection.OutcomePass, "V5": connection.OutcomePass,
			"V7": connection.OutcomeFail, "V8": connection.OutcomePass}}
	for _, s := range seeds {
		r.Findings = append(r.Findings, connection.Finding{Check: "V7", Code: "over.tier0_group", Kind: connection.FindingExcessiveRight,
			Severity: connection.SeverityBlock, ObjectGUID: idA, Fingerprint: fp(s)})
	}
	return r
}

type svcEnv struct {
	*env
	svc *connection.Service
	cl  *fakeClient
	rec *recorder
}

func newSvc(t *testing.T, s *storetest.Server) *svcEnv {
	t.Helper()
	e := setup(t, s)
	cl, rec := &fakeClient{}, &recorder{}
	svc, err := connection.NewService(e.reg, cl, rec)
	if err != nil {
		t.Fatal(err)
	}
	return &svcEnv{env: e, svc: svc, cl: cl, rec: rec}
}

func (e *svcEnv) draft(t *testing.T) connection.Connection {
	t.Helper()
	c, err := e.reg.Create(context.Background(), e.a, forest("corp"))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// Acceptance 1: a refused or indeterminate result keeps the connection out of active, and the
// excessive and missing lists are stored and returned.
func TestActivationRefusedStoresAndReturnsTheLists(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := newSvc(t, s)
		ctx := context.Background()
		c := e.draft(t)
		r := overPriv("g1", "g2")
		r.Findings = append(r.Findings, connection.Finding{Check: "V8", Code: "under.read", Kind: connection.FindingMissingRight,
			Severity: connection.SeverityBlock, Fingerprint: fp("m1")})
		r.Outcomes["V8"] = connection.OutcomeFail
		e.cl.set(r, nil)
		out, err := e.svc.Activate(ctx, e.a, c.ID, human("alice"))
		var ae *connection.ActivationError
		if !errors.As(err, &ae) || ae.Code != connection.ReasonNotOverridable {
			t.Fatalf("err = %v, want not_overridable (V8 also failed)", err)
		}
		if out.Connection.State != connection.StateDraft {
			t.Fatalf("state %s, want draft", out.Connection.State)
		}
		if len(out.Verification.Findings) != 3 {
			t.Fatalf("returned %d findings, want 3", len(out.Verification.Findings))
		}
		h, err := e.reg.Health(ctx, e.a, c.ID, true, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if h.ExcessiveCount != 2 || h.MissingCount != 1 || len(h.Excessive) != 2 || len(h.Missing) != 1 || h.Status != connection.HealthAttention {
			t.Fatalf("health: %+v", h)
		}
		// Counts only for a reader who may not see findings.
		hc, _ := e.reg.Health(ctx, e.a, c.ID, false, time.Now())
		if hc.ExcessiveCount != 2 || len(hc.Excessive) != 0 || len(hc.Missing) != 0 {
			t.Fatalf("count-only health leaks findings: %+v", hc)
		}
		// Indeterminate: could_not_verify is never activated either.
		e.cl.set(connection.VerifyResult{DirectoryIdentity: forestRoot, CheckListVersion: 1, Verdict: connection.VerdictCouldNotVerify,
			Outcomes: map[connection.Check]connection.Outcome{"V5": connection.OutcomePass, "V7": connection.OutcomeCouldNotVerify}}, nil)
		out, err = e.svc.Activate(ctx, e.a, c.ID, human("alice"))
		if !errors.As(err, &ae) || ae.Code != connection.ReasonCouldNotVerify || out.Connection.State != connection.StateDraft {
			t.Fatalf("could_not_verify: %v state %s", err, out.Connection.State)
		}
		got, _ := e.reg.Get(ctx, e.a, c.ID)
		if got.State != connection.StateDraft || got.VerifiedAt != nil {
			t.Fatalf("stored: %+v", got)
		}
	})
}

// Acceptance 2: a passing result activates.
func TestActivationPassActivates(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := newSvc(t, s)
		ctx := context.Background()
		c := e.draft(t)
		e.cl.set(passing(), nil)
		out, err := e.svc.Activate(ctx, e.a, c.ID, human("alice"))
		if err != nil {
			t.Fatal(err)
		}
		if out.Connection.State != connection.StateActive || out.Connection.DirectoryIdentity != forestRoot || out.Connection.VerifiedAt == nil {
			t.Fatalf("connection: %+v", out.Connection)
		}
		want := []audit.Kind{connection.AuditVerificationCompleted, connection.AuditActivated}
		if got := e.rec.kinds(); len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
			t.Fatalf("audit kinds %v", got)
		}
		h, _ := e.reg.Health(ctx, e.a, c.ID, false, time.Now())
		if h.Status != connection.HealthOK || h.Tier0Installation || !h.WriteGateOpen {
			t.Fatalf("health: %+v", h)
		}
		// No audit event carries a per-finding identifier (DM-24.I5): only the digest and counts.
		for _, ev := range e.rec.evs {
			for _, ch := range ev.Changes {
				if ch.Attribute == "fingerprint" || ch.Attribute == "object_guid" {
					t.Errorf("event %s carries %s", ev.Kind, ch.Attribute)
				}
			}
		}
	})
}

// A fresh qualifying run activates without calling the connector again (FR-17).
func TestFreshPassActivatesWithoutANewRun(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := newSvc(t, s)
		ctx := context.Background()
		c := e.draft(t)
		e.cl.set(passing(), nil)
		if _, err := e.svc.Verify(ctx, e.a, c.ID, connection.KindOnboarding, human("alice")); err != nil {
			t.Fatal(err)
		}
		if _, err := e.svc.Activate(ctx, e.a, c.ID, human("alice")); err != nil {
			t.Fatal(err)
		}
		if e.cl.calls != 1 {
			t.Fatalf("connector called %d times, want 1", e.cl.calls)
		}
	})
}

// An incomplete or failed run is recorded as failed and returns the connection to draft.
func TestInterruptedRunIsRecordedAndReturnsToDraft(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := newSvc(t, s)
		ctx := context.Background()
		c := e.draft(t)
		e.cl.set(connection.VerifyResult{}, errors.New("stream ended"))
		out, err := e.svc.Activate(ctx, e.a, c.ID, human("alice"))
		if !errors.Is(err, connection.ErrRunInterrupted) {
			t.Fatalf("err = %v", err)
		}
		if out.Connection.State != connection.StateDraft || out.Verification.Verdict != connection.VerdictFailed ||
			out.Verification.Outcome("V7") != connection.OutcomeNotRun {
			t.Fatalf("outcome: %+v", out)
		}
	})
}

// A second connection that finds the same identity fails V5 (spec L10) and stays a draft.
func TestDuplicateIdentityFailsTheRun(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := newSvc(t, s)
		ctx := context.Background()
		first, second := e.draft(t), e.draft(t)
		e.cl.set(passing(), nil)
		if _, err := e.svc.Activate(ctx, e.a, first.ID, human("alice")); err != nil {
			t.Fatal(err)
		}
		out, err := e.svc.Activate(ctx, e.a, second.ID, human("alice"))
		var ae *connection.ActivationError
		if !errors.As(err, &ae) || ae.Code != connection.ReasonVerdictFailed || out.Connection.State != connection.StateDraft {
			t.Fatalf("err %v state %s", err, out.Connection.State)
		}
	})
}

// Acceptance 5: the scheduled health check records a new excessive right on an active connection.
func TestScheduledCheckReportsNewExcess(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := newSvc(t, s)
		ctx := context.Background()
		c := e.draft(t)
		e.cl.set(passing(), nil)
		if _, err := e.svc.Activate(ctx, e.a, c.ID, human("alice")); err != nil {
			t.Fatal(err)
		}
		r := overPriv("drift")
		e.cl.set(r, nil)
		res, err := e.svc.RunScheduled(ctx, e.a)
		if err != nil || len(res) != 1 || res[0].Err != nil {
			t.Fatalf("scheduled: %+v %v", res, err)
		}
		h, _ := e.reg.Health(ctx, e.a, c.ID, true, time.Now())
		if h.State != connection.StateActive {
			t.Fatalf("a scheduled run must not change the state: %s", h.State)
		}
		if h.Status != connection.HealthAttention || h.ExcessiveCount != 1 || len(h.Excessive) != 1 || h.WriteGateOpen {
			t.Fatalf("health: %+v", h)
		}
		if res[0].Outcome.Verification.RequestedBy != "" || res[0].Outcome.Verification.Kind != connection.KindScheduled {
			t.Fatalf("run: %+v", res[0].Outcome.Verification)
		}
		got := e.rec.kinds()
		if got[len(got)-1] != connection.AuditVerdictChanged {
			t.Fatalf("expected a verdict_changed event, got %v", got)
		}
		// The run is replaced by one that finds the right gone and a different one missing.
		r2 := passing()
		r2.Findings = []connection.Finding{{Check: "V8", Code: "under.read", Kind: connection.FindingMissingRight, Severity: connection.SeverityWarn, Fingerprint: fp("m")}}
		e.cl.set(r2, nil)
		if _, err := e.svc.RunScheduled(ctx, e.a); err != nil {
			t.Fatal(err)
		}
		h, _ = e.reg.Health(ctx, e.a, c.ID, true, time.Now())
		if h.ExcessiveCount != 0 || h.MissingCount != 1 || !h.WriteGateOpen {
			t.Fatalf("lists not updated: %+v", h)
		}
	})
}

// The database refuses to change or delete a verification, a finding or an override (DM-24.I1).
func TestVerificationTablesAreAppendOnly(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := newSvc(t, s)
		c := e.draft(t)
		e.cl.set(overPriv("x"), nil)
		if _, err := e.svc.Activate(context.Background(), e.a, c.ID, human("alice")); err == nil {
			t.Fatal("expected a refusal")
		}
		for _, q := range []string{
			`UPDATE public.connection_verifications SET verdict = 'pass'`,
			`DELETE FROM public.connection_verifications`,
			`UPDATE public.connection_verification_findings SET severity = 'info'`,
			`DELETE FROM public.connection_verification_findings`,
			`TRUNCATE public.connection_verifications`,
		} {
			if _, err := e.raw(e.a, q); err == nil {
				t.Errorf("%s was allowed", q)
			}
		}
	})
}

// A pass verdict whose over-privilege (or other required) check is missing or not_run must not
// activate, for AD and for Entra (security review of TM-D1).
func TestPassWithoutOverPrivilegeCheckNeverActivates(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		ctx := context.Background()
		cases := map[string]map[connection.Check]connection.Outcome{
			"V7 absent":     {"V5": connection.OutcomePass, "V8": connection.OutcomePass},
			"only V5":       {"V5": connection.OutcomePass},
			"V7 not_run":    {"V5": connection.OutcomePass, "V7": connection.OutcomeNotRun, "V8": connection.OutcomePass},
			"V8 absent":     {"V5": connection.OutcomePass, "V7": connection.OutcomePass},
			"V5 absent":     {"V7": connection.OutcomePass, "V8": connection.OutcomePass},
			"extra not_run": {"V5": connection.OutcomePass, "V7": connection.OutcomePass, "V8": connection.OutcomePass, "V9": connection.OutcomeNotRun},
		}
		for name, oc := range cases {
			e := newSvc(t, s) // one forest identity per connection (DM-10.I2)
			c := e.draft(t)
			r := passing()
			r.Outcomes = oc
			e.cl.set(r, nil)
			if _, err := e.svc.Activate(ctx, e.a, c.ID, human("alice")); err == nil {
				t.Errorf("%s: activation succeeded", name)
			}
			got, err := e.reg.Get(ctx, e.a, c.ID)
			if err != nil {
				t.Fatal(err)
			}
			if got.State != connection.StateDraft || got.VerifiedAt != nil {
				t.Errorf("%s: connection %+v", name, got)
			}
			h, _ := e.reg.Health(ctx, e.a, c.ID, true, time.Now())
			if h.Verdict != connection.VerdictFailed || h.WriteGateOpen {
				t.Errorf("%s: no failed run recorded: %+v", name, h)
			}
			e.cl.set(passing(), nil)
			if _, err := e.svc.Activate(ctx, e.a, c.ID, human("alice")); err != nil {
				t.Errorf("%s: a following good activation: %v", name, err)
			}
		}
	})
}

// A scheduled run whose pass does not answer the over-privilege check closes the write gate.
func TestScheduledIncompletePassClosesTheGate(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := newSvc(t, s)
		ctx := context.Background()
		c := e.draft(t)
		e.cl.set(passing(), nil)
		if _, err := e.svc.Activate(ctx, e.a, c.ID, human("alice")); err != nil {
			t.Fatal(err)
		}
		bad := map[string]map[connection.Check]connection.Outcome{
			"V7 absent":  {"V5": connection.OutcomePass, "V8": connection.OutcomePass},
			"V7 not_run": {"V5": connection.OutcomePass, "V7": connection.OutcomeNotRun, "V8": connection.OutcomePass},
		}
		for name, oc := range bad {
			e.cl.set(passing(), nil) // back to a clean newest run
			if _, err := e.svc.RunScheduled(ctx, e.a); err != nil {
				t.Fatal(err)
			}
			before := len(e.rec.kinds())
			r := passing()
			r.Outcomes = oc
			e.cl.set(r, nil)
			res, err := e.svc.RunScheduled(ctx, e.a)
			if err != nil || len(res) != 1 || res[0].Err == nil {
				t.Fatalf("%s: scheduled: %+v %v", name, res, err)
			}
			h, _ := e.reg.Health(ctx, e.a, c.ID, true, time.Now())
			if h.WriteGateOpen || h.Status == connection.HealthOK || h.Verdict != connection.VerdictFailed {
				t.Errorf("%s: health: %+v", name, h)
			}
			found := false
			for _, k := range e.rec.kinds()[before:] {
				found = found || k == connection.AuditVerificationCompleted
			}
			if !found {
				t.Errorf("%s: no verification_completed audit event", name)
			}
		}
	})
}

func TestQualifiesRequiresOverPrivilegePassOnAPass(t *testing.T) {
	v := connection.Verification{Verdict: connection.VerdictPass, Outcomes: map[connection.Check]connection.Outcome{"V5": connection.OutcomePass}}
	if ok, _ := connection.Qualifies(connection.KindADForest, v, nil); ok {
		t.Error("a stored pass without V7 qualified")
	}
	v.Outcomes = map[connection.Check]connection.Outcome{"EV2": connection.OutcomePass}
	if ok, _ := connection.Qualifies(connection.KindEntraTenant, v, nil); ok {
		t.Error("a stored Entra pass without EV3 qualified")
	}
	v.Outcomes["EV3"] = connection.OutcomePass
	if ok, _ := connection.Qualifies(connection.KindEntraTenant, v, nil); !ok {
		t.Error("a pass with EV3 pass was refused")
	}
}

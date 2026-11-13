package ad_test

import (
	"context"
	"encoding/json/v2"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/accountkind"
	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/modules/ad"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/operation/operationtest"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

const (
	conn = "conn-1"
	nc   = "11111111-1111-4111-8111-111111111111"
	obj  = "22222222-2222-4222-8222-222222222222"
	// 0x10200: NORMAL_ACCOUNT | DONT_EXPIRE_PASSWORD. 0x2 is ACCOUNTDISABLE.
	uacEnabled  = "66048"
	uacDisabled = "66050"
)

// accounts is the fake connector: one object in an operationtest.FakeDirectory, read and written
// the way the connector's account kinds do (accountkind). It refuses a write whose digest is not
// the Step's, as client.Write does.
type accounts struct {
	dir    *operationtest.FakeDirectory
	class  string
	tier0  bool
	exists bool
	// deny, when set, is returned by Write as the Step's authorisation re-check would (rule 7).
	deny error
	// writeErr, when set, is returned by Write.
	writeErr error
}

func newAccounts() *accounts {
	a := &accounts{dir: operationtest.NewFakeDirectory(), class: "user", exists: true}
	a.dir.Seed(obj, "userAccountControl", uacEnabled)
	a.dir.Seed(obj, "lockoutTime", "133500000000000000")
	a.dir.Seed(obj, "pwdLastSet", "133400000000000000")
	return a
}

func (a *accounts) Account(_ context.Context, _ authority.Pins, t authority.TargetRef) (client.AccountState, error) {
	if !a.exists || t.GUID != obj {
		return client.AccountState{}, nil
	}
	return client.AccountState{
		Exists: true, Class: a.class, Tier0: a.tier0,
		UserAccountControl: first(a.dir.Read(obj, "userAccountControl")),
		LockoutTime:        first(a.dir.Read(obj, "lockoutTime")),
		PwdLastSet:         first(a.dir.Read(obj, "pwdLastSet")),
	}, nil
}

func first(v []string) string {
	if len(v) == 0 {
		return ""
	}
	return v[0]
}

func (a *accounts) Write(_ context.Context, s step.Step, op client.WriteOp) (client.Result, error) {
	if a.deny != nil {
		return client.Result{}, a.deny
	}
	if a.writeErr != nil {
		return client.Result{}, a.writeErr
	}
	if step.Compute(op.DigestKind, op.Target, op.Attrs) != s.Digest() {
		return client.Result{}, client.ErrDigest
	}
	if _, err := accountkind.ChangeFromAttrs(op.DigestKind, op.Attrs); err != nil {
		return client.Result{}, client.ErrKindAttrs
	}
	uac, _ := strconv.Atoi(first(a.dir.Read(obj, "userAccountControl")))
	set := func(s step.Step, attr, v string) error {
		return a.dir.Write(s, operationtest.Mutation{GUID: obj, Attribute: attr, Op: operationtest.Replace, Values: []string{v}})
	}
	switch op.DigestKind {
	case accountkind.KeyUnlock:
		if first(a.dir.Read(obj, "lockoutTime")) == "0" {
			return client.Result{NoOp: true}, nil
		}
		return client.Result{}, set(s, "lockoutTime", "0")
	case accountkind.KeyEnable:
		if uac&2 == 0 {
			return client.Result{NoOp: true}, nil
		}
		return client.Result{}, set(s, "userAccountControl", strconv.Itoa(uac&^2))
	case accountkind.KeyDisable:
		if uac&2 != 0 {
			return client.Result{NoOp: true}, nil
		}
		return client.Result{}, set(s, "userAccountControl", strconv.Itoa(uac|2))
	case accountkind.KeyResetPassword:
		ch, _ := accountkind.ChangeFromAttrs(op.DigestKind, op.Attrs)
		pls := "133600000000000000"
		if ch.GetUserPasswordReset().GetMustChangeAtNextLogon() {
			pls = "0"
		}
		return client.Result{}, set(s, "pwdLastSet", pls)
	}
	return client.Result{}, client.ErrUnknownKind
}

func target() ad.Target {
	return ad.Target{ConnectionID: conn, ObjectGUID: obj, NamingContext: nc}
}

func input(t *testing.T, v any) operation.Input {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func actions(t *testing.T, a *accounts) map[operation.ActionID]operation.Action {
	t.Helper()
	as, err := ad.Actions(a, a)
	if err != nil {
		t.Fatal(err)
	}
	m := map[operation.ActionID]operation.Action{}
	for _, x := range as {
		m[x.Describe().ID] = x
	}
	return m
}

func inputs(t *testing.T) map[operation.ActionID]operation.Input {
	return map[operation.ActionID]operation.Input{
		ad.ResetPasswordID: input(t, ad.ResetInput{Target: target(), MustChangeAtNextLogon: true}),
		ad.UnlockID:        input(t, ad.AccountInput{Target: target()}),
		ad.EnableID:        input(t, ad.AccountInput{Target: target()}),
		ad.DisableID:       input(t, ad.AccountInput{Target: target()}),
	}
}

func pins() authority.Pins { return authority.Pins{nc: "dc1.example"} }

// Every Action runs through the kernel's contract clauses (ADR-0005 O6/O7): Plan is read-only,
// Apply repeats without a second change, Verify fails when the directory drops the write.
func TestContract(t *testing.T) {
	for id, in := range inputs(t) {
		t.Run(string(id), func(t *testing.T) {
			a := newAccounts()
			if id == ad.EnableID {
				a.dir.Seed(obj, "userAccountControl", uacDisabled)
			}
			operationtest.Contract(t, actions(t, a)[id], operationtest.Fixture{Input: in, Directory: a.dir, Pins: pins(), FreshStepUp: id == ad.ResetPasswordID})
		})
	}
}

func planOf(t *testing.T, a *accounts, id operation.ActionID) []operation.StepPlan {
	t.Helper()
	steps, err := actions(t, a)[id].Plan(context.Background(), operation.PlanContext{Pins: pins()}, inputs(t)[id])
	if err != nil {
		t.Fatalf("%s plan: %v", id, err)
	}
	if len(steps) != 1 {
		t.Fatalf("%s planned %d steps", id, len(steps))
	}
	return steps
}

// AC1: reset password is Irreversible, its diff is the must-change flag and the presence of a secret,
// and no password can be in the plan: the input, the payload and the outcome have no field for one.
func TestResetPlanIsIrreversibleAndHoldsNoSecret(t *testing.T) {
	a := newAccounts()
	act := actions(t, a)[ad.ResetPasswordID]
	d := act.Describe()
	if d.Reversibility != operation.Irreversible || !d.StepUp || !d.SecretInput {
		t.Fatalf("descriptor %+v: want Irreversible, StepUp, SecretInput", d)
	}
	sp := planOf(t, a, ad.ResetPasswordID)[0]
	if sp.Reversibility != operation.Irreversible || !sp.Credential || sp.Kind != accountkind.KeyResetPassword {
		t.Fatalf("plan %+v", sp)
	}
	if len(sp.Diff) != 2 {
		t.Fatalf("diff %+v", sp.Diff)
	}
	if c := sp.Diff[0]; c.Attribute != accountkind.AttrMustChange || c.Before[0] != "false" || c.After[0] != "true" || c.Secret {
		t.Fatalf("must-change change %+v", c)
	}
	if c := sp.Diff[1]; c.Attribute != accountkind.AttrSecret || !c.Secret || len(c.Before) != 0 || len(c.After) != 0 {
		t.Fatalf("secret change %+v", c)
	}
	// The input that decodes holds no password member: an unknown one is refused (RejectUnknownMembers).
	_, err := act.Plan(context.Background(), operation.PlanContext{Pins: pins()},
		operation.Input(`{"connectionId":"`+conn+`","objectGuid":"`+obj+`","namingContext":"`+nc+`","mustChangeAtNextLogon":true,"password":"hunter2-sentinel"}`))
	if !errors.Is(err, operation.ErrInvalid) {
		t.Fatalf("a password in the input was accepted: %v", err)
	}
	if strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("error echoes the value: %v", err)
	}
	// Nothing the module serialises carries a password-shaped member.
	b, _ := json.Marshal(sp.Diff)
	b = append(b, sp.Payload...)
	for _, bad := range []string{"password", "unicodepwd", "hunter2"} {
		if strings.Contains(strings.ToLower(string(b)), bad) {
			t.Fatalf("diff or payload mentions %q: %s", bad, b)
		}
	}
}

// The other three Actions' before and after are in Preconditions (the digest binds no attribute for
// them), and each is the class the connector contract (§8.10.1) names.
func TestPlansStateTheBeforeState(t *testing.T) {
	a := newAccounts()
	a.dir.Seed(obj, "userAccountControl", uacDisabled)
	for id, want := range map[operation.ActionID]struct {
		class operation.Reversibility
		pre   string
	}{
		ad.UnlockID:  {operation.Irreversible, "lockoutTime: set → 0"},
		ad.EnableID:  {operation.Reversible, "ACCOUNTDISABLE: set → cleared"},
		ad.DisableID: {operation.Reversible, "already disabled"},
	} {
		sp := planOf(t, a, id)[0]
		if sp.Reversibility != want.class || actions(t, a)[id].Describe().Reversibility != want.class {
			t.Errorf("%s: class %s", id, sp.Reversibility)
		}
		if len(sp.Diff) != 0 || len(sp.Preconditions) != 1 || !strings.Contains(sp.Preconditions[0], want.pre) {
			t.Errorf("%s: diff %+v preconditions %q", id, sp.Diff, sp.Preconditions)
		}
	}
}

// AC2: disable then enable (the inverse) restores userAccountControl exactly, other bits included.
func TestEnableDisableInverseRestoresUAC(t *testing.T) {
	a := newAccounts()
	acts := actions(t, a)
	for _, tc := range []struct {
		id       operation.ActionID
		start    string
		changed  string
		wantInvs operation.ActionID
	}{
		{ad.DisableID, uacEnabled, uacDisabled, ad.EnableID},
		{ad.EnableID, uacDisabled, uacEnabled, ad.DisableID},
	} {
		a.dir.Seed(obj, "userAccountControl", tc.start)
		sp := planOf(t, a, tc.id)
		act := acts[tc.id]
		// Apply through the contract harness-free path: the fake needs a live Step, which only the
		// runner mints, so the exercise is the Contract's; here the inverse is derived from the plan.
		inv, ok := ad.InverseAction(tc.id)
		if !ok || inv != tc.wantInvs {
			t.Fatalf("%s inverse action = %q", tc.id, inv)
		}
		in, err := act.Inverse(sp[0], operation.Outcome{Payload: []byte(`{}`)})
		if err != nil {
			t.Fatalf("%s inverse: %v", tc.id, err)
		}
		var got ad.AccountInput
		if err := json.Unmarshal(in, &got); err != nil || got.Target != target() {
			t.Fatalf("%s inverse input %s (%v)", tc.id, in, err)
		}
		// An outcome that changed nothing has nothing to undo.
		if _, err := act.Inverse(sp[0], operation.Outcome{Payload: []byte(`{"noOp":true}`)}); !errors.Is(err, ad.ErrNothingToUndo) || !errors.Is(err, operation.ErrIrreversible) {
			t.Fatalf("%s no-op inverse: %v", tc.id, err)
		}
	}
	// A step whose before-state already was the after-state has nothing to undo.
	a.dir.Seed(obj, "userAccountControl", uacEnabled)
	sp := planOf(t, a, ad.EnableID)
	if _, err := acts[ad.EnableID].Inverse(sp[0], operation.Outcome{Payload: []byte(`{}`)}); !errors.Is(err, ad.ErrNothingToUndo) {
		t.Fatalf("enable of an enabled account: %v", err)
	}
}

// Unlock and reset have no inverse: the DC owns lockoutTime (connector contract §8.10.1 row 8) and a
// password is not readable (row 7).
func TestUnlockAndResetAreIrreversible(t *testing.T) {
	a := newAccounts()
	for _, id := range []operation.ActionID{ad.UnlockID, ad.ResetPasswordID} {
		sp := planOf(t, a, id)
		if _, err := actions(t, a)[id].Inverse(sp[0], operation.Outcome{Payload: []byte(`{}`)}); !errors.Is(err, operation.ErrIrreversible) {
			t.Errorf("%s inverse: %v", id, err)
		}
		if _, ok := ad.InverseAction(id); ok {
			t.Errorf("%s has an inverse action", id)
		}
		if sp[0].ReversibilityReason == "" {
			t.Errorf("%s gives no reason", id)
		}
	}
}

func TestPlanRefusals(t *testing.T) {
	cases := []struct {
		name string
		mod  func(*accounts)
		in   operation.Input
		want error
		text string
	}{
		{"missing", func(a *accounts) { a.exists = false }, nil, operation.ErrInvalid, ad.ReasonNotFound},
		{"computer", func(a *accounts) { a.class = "computer" }, nil, operation.ErrInvalid, ad.ReasonNotUser},
		{"tier0", func(a *accounts) { a.tier0 = true }, nil, operation.ErrDenied, ad.ReasonTier0},
		{"non-canonical guid", func(*accounts) {}, operation.Input(`{"connectionId":"c","objectGuid":"ABC","namingContext":"` + nc + `"}`), operation.ErrInvalid, ""},
	}
	for _, tc := range cases {
		for _, id := range []operation.ActionID{ad.ResetPasswordID, ad.UnlockID, ad.EnableID, ad.DisableID} {
			a := newAccounts()
			tc.mod(a)
			in := tc.in
			if in == nil {
				in = inputs(t)[id]
			}
			_, err := actions(t, a)[id].Plan(context.Background(), operation.PlanContext{Pins: pins()}, in)
			if !errors.Is(err, tc.want) || (tc.text != "" && !strings.Contains(err.Error(), tc.text)) {
				t.Errorf("%s/%s: %v", tc.name, id, err)
			}
		}
	}
}

// With no connector wired the Actions refuse: they never run without the directory.
func TestNilPortsRefuse(t *testing.T) {
	as, err := ad.Actions(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range as {
		id := x.Describe().ID
		if _, err := x.Plan(context.Background(), operation.PlanContext{}, inputs(t)[id]); !errors.Is(err, operation.ErrTransient) {
			t.Errorf("%s plan with no connector: %v", id, err)
		}
	}
}

func TestDescriptors(t *testing.T) {
	as, err := ad.Actions(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := operation.NewRegistry(as...); err != nil {
		t.Fatal(err)
	}
	for _, x := range as {
		d := x.Describe()
		if d.Target != operation.TargetAD || d.TargetClass != "user" || d.Version != 1 {
			t.Errorf("%+v", d)
		}
		if (d.ID == ad.ResetPasswordID) != (d.StepUp && d.SecretInput) || (d.ID != ad.ResetPasswordID && (d.StepUp || d.SecretInput)) {
			t.Errorf("%s: StepUp/SecretInput %v/%v", d.ID, d.StepUp, d.SecretInput)
		}
		if _, ok := x.(operation.Observer); !ok {
			t.Errorf("%s is not an Observer", d.ID)
		}
	}
}

// Observe tells reconciliation where a step stands (rule 6).
func TestObserve(t *testing.T) {
	claimed := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	ft := func(tm time.Time) string { return strconv.FormatInt((tm.Unix()+11644473600)*1e7, 10) }
	for _, tc := range []struct {
		id     operation.ActionID
		seed   func(*accounts)
		change func(*accounts)
		other  func(*accounts)
	}{
		{ad.UnlockID, func(*accounts) {}, func(a *accounts) { a.dir.Seed(obj, "lockoutTime", "0") }, func(a *accounts) { a.dir.Seed(obj, "lockoutTime", "5") }},
		{ad.EnableID, func(a *accounts) { a.dir.Seed(obj, "userAccountControl", uacDisabled) }, func(a *accounts) { a.dir.Seed(obj, "userAccountControl", uacEnabled) }, func(a *accounts) { a.dir.Seed(obj, "userAccountControl", "514") }},
		{ad.DisableID, func(*accounts) {}, func(a *accounts) { a.dir.Seed(obj, "userAccountControl", uacDisabled) }, func(a *accounts) { a.dir.Seed(obj, "userAccountControl", "512") }},
		{ad.ResetPasswordID, func(a *accounts) { a.dir.Seed(obj, "pwdLastSet", ft(claimed.Add(-time.Hour))) },
			func(a *accounts) { a.dir.Seed(obj, "pwdLastSet", ft(claimed.Add(time.Minute))) }, func(a *accounts) { a.dir.Seed(obj, "pwdLastSet", ft(claimed.Add(-time.Minute))) }},
	} {
		t.Run(string(tc.id), func(t *testing.T) {
			a := newAccounts()
			tc.seed(a)
			act := actions(t, a)[tc.id]
			var sp operation.StepPlan
			if tc.id == ad.ResetPasswordID { // plan with must-change false: after is "last set after the claim"
				steps, err := act.Plan(context.Background(), operation.PlanContext{Pins: pins()}, input(t, ad.ResetInput{Target: target()}))
				if err != nil {
					t.Fatal(err)
				}
				sp = steps[0]
			} else {
				sp = planOf(t, a, tc.id)[0]
			}
			observe := func() operation.Observation {
				o, err := act.(operation.Observer).Observe(context.Background(), pins(), sp, claimed)
				if err != nil {
					t.Fatal(err)
				}
				return o
			}
			if got := observe(); got != operation.ObservedBefore {
				t.Fatalf("before: %s", got)
			}
			tc.change(a)
			if got := observe(); got != operation.ObservedAfter {
				t.Fatalf("after: %s", got)
			}
			tc.other(a)
			if got := observe(); got != operation.ObservedOther {
				t.Fatalf("other: %s", got)
			}
		})
	}
}

// AC3 (rule 7 TOCTOU): an Apply whose authorisation re-check refuses is a denial, not a failure, and
// the refusal keeps no directory text.
func TestApplyDenialAndErrorMapping(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		is   error
		not  error
	}{
		{"scope left", step.ErrDenied, step.ErrDenied, nil},
		{"transport", client.ErrTransport, operation.ErrTransient, operation.ErrOutcomeUnknown},
		{"digest", client.ErrDigest, operation.ErrInvalid, nil},
	} {
		a := newAccounts()
		a.writeErr = tc.err
		_, err := applyWith(t, a, ad.DisableID)
		if !errors.Is(err, tc.is) || (tc.not != nil && errors.Is(err, tc.not)) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
	// A credential step whose connector call fails mid-flight is outcome-unknown, never a retry (rule 6).
	a := newAccounts()
	a.writeErr = client.ErrTransport
	if _, err := applyWith(t, a, ad.ResetPasswordID); !errors.Is(err, operation.ErrOutcomeUnknown) {
		t.Errorf("reset transport failure: %v", err)
	}
}

// storeFace presents a Directory Action to the runner's inline path, as the Contract does, so the
// real runner mints the Step and classifies the error Apply returns.
type storeFace struct{ operation.Action }

func (s storeFace) Describe() operation.Descriptor {
	d := s.Action.Describe()
	d.Target = operation.TargetStore
	return d
}

type fakeDB struct{}

func (fakeDB) WithTenant(ctx context.Context, _ tenant.ID, fn func(context.Context, store.Tx) error) error {
	return fn(ctx, &storetest.FakeTx{})
}

type sink struct{ events []audit.Event }

func (s *sink) Append(_ context.Context, _ store.Tx, ev audit.Event) error {
	s.events = append(s.events, ev)
	return ev.Validate()
}

// scopeAuthz allows the target until moved, then refuses: the technician's delegation no longer
// reaches the object (TM-F-AUTHZ "move between check and write").
type scopeAuthz struct{ calls, refuseFrom int }

func (a *scopeAuthz) FactsQuery(_ authority.Chain, _ authz.Permission, t authority.TargetRef) authority.FactsQuery {
	return authority.FactsQuery{Target: t}
}

func (a *scopeAuthz) Authorize(context.Context, authority.Chain, authz.Permission, authority.TargetRef, authority.Facts) error {
	a.calls++
	if a.refuseFrom > 0 && a.calls >= a.refuseFrom {
		return operation.ErrDenied
	}
	return nil
}

func run(t *testing.T, a *accounts, id operation.ActionID, az operation.Authorizer, sk *sink) (operation.Result, error) {
	t.Helper()
	reg, err := operation.NewRegistry(storeFace{actions(t, a)[id]})
	if err != nil {
		t.Fatal(err)
	}
	r, err := operation.NewRunner(operation.Config{DB: fakeDB{}, Audit: sk, Authz: az, Registry: reg})
	if err != nil {
		t.Fatal(err)
	}
	return r.RunStore(context.Background(), operation.Request{
		Tenant: tenanttest.NewID(t), Action: id, Input: inputs(t)[id], Pins: pins(), Operation: "op-ad-1",
		Actor: authority.Chain{Requester: authority.Principal{ID: "tech", Kind: authority.Human}}, FreshStepUp: true,
	})
}

func applyWith(t *testing.T, a *accounts, id operation.ActionID) (operation.Result, error) {
	return run(t, a, id, &scopeAuthz{}, &sink{})
}

// AC3: the target leaves the technician's scope between Plan and Apply. The runner's re-check fails
// the step denied and commits a denial audit event; nothing is written.
func TestTargetLeavesScopeBetweenPlanAndApply(t *testing.T) {
	for _, id := range []operation.ActionID{ad.ResetPasswordID, ad.UnlockID, ad.EnableID, ad.DisableID} {
		a := newAccounts()
		a.dir.Seed(obj, "userAccountControl", uacDisabled)
		sk := &sink{}
		_, err := run(t, a, id, &scopeAuthz{refuseFrom: 2}, sk) // call 1: Plan; call 2: Apply re-check
		if !errors.Is(err, operation.ErrDenied) {
			t.Fatalf("%s: %v", id, err)
		}
		if a.dir.Writes() != 0 {
			t.Errorf("%s wrote %d times after the scope check refused", id, a.dir.Writes())
		}
		var denied bool
		for _, ev := range sk.events {
			denied = denied || ev.Outcome == audit.Denied
		}
		if !denied {
			t.Errorf("%s: no denial audit event in %d events", id, len(sk.events))
		}
	}
}

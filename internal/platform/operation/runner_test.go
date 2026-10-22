package operation

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// fakeDB models transaction semantics: events appended in a transaction exist only if it commits.
type fakeDB struct {
	committed []audit.Event
	writes    []string // committed store writes
	txs       int
	failOpen  int // the next n transactions fail to open (a lock_timeout stand-in)
	readOnly  int
}

type fakeTx struct {
	db     *fakeDB
	events []audit.Event
	writes []string
}

func (t *fakeTx) Exec(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
	if strings.HasPrefix(sql, "SET TRANSACTION READ ONLY") {
		t.db.readOnly++
	}
	return pgconn.CommandTag{}, nil
}
func (*fakeTx) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("no rows")
}
func (*fakeTx) QueryRow(context.Context, string, ...any) pgx.Row { return nil }

func (d *fakeDB) WithTenant(ctx context.Context, id tenant.ID, fn func(context.Context, store.Tx) error) error {
	if id.IsZero() {
		return store.ErrNoTenant
	}
	if d.failOpen > 0 {
		d.failOpen--
		return errors.New("lock timeout")
	}
	d.txs++
	tx := &fakeTx{db: d}
	if err := fn(ctx, tx); err != nil {
		return err // rollback: tx.events and tx.writes are dropped
	}
	d.committed = append(d.committed, tx.events...)
	d.writes = append(d.writes, tx.writes...)
	return nil
}

type sink struct{ fail bool }

func (s sink) Append(_ context.Context, tx store.Tx, ev audit.Event) error {
	if s.fail {
		return errors.New("chain unavailable")
	}
	if err := ev.Validate(); err != nil {
		return err
	}
	tx.(*fakeTx).events = append(tx.(*fakeTx).events, ev)
	return nil
}

type authzFake struct {
	deny   map[authority.PrincipalID]bool // principals refused
	denyAt atomic.Int32                   // refuse starting at the nth Authorize call (1-based), 0 = never
	calls  atomic.Int32
}

func (*authzFake) FactsQuery(_ authority.Chain, _ authz.Permission, t authority.TargetRef) authority.FactsQuery {
	return authority.FactsQuery{Target: t}
}
func (a *authzFake) Authorize(_ context.Context, c authority.Chain, _ authz.Permission, _ authority.TargetRef, _ authority.Facts) error {
	n := a.calls.Add(1)
	if a.deny[c.Requester.ID] || (a.denyAt.Load() > 0 && n >= a.denyAt.Load()) {
		return errors.New("not in scope")
	}
	return nil
}

type factsFake struct {
	tier0 bool
	err   error
}

func (f factsFake) Facts(context.Context, authority.Pins, authority.FactsQuery) (authority.Facts, error) {
	return authority.Facts{Exists: true, Tier0: f.tier0}, f.err
}

type in struct{ Name string }
type payload struct{ Row string }
type out struct{ Row string }

type behaviour struct {
	applyErr error
	verifyOK bool
	applied  *int
	onApply  func(step.Step)
	plan     func() []TypedStep[payload]
	class    Reversibility
}

func (b behaviour) action(t *testing.T, db *fakeDB) Action {
	if b.applied == nil {
		b.applied = new(int)
	}
	a, err := Define(Typed[in, payload, out]{
		Descriptor: Descriptor{ID: "settings.thing.set", Version: 1, Permission: "settings.thing.set",
			Input: "#/components/schemas/Thing", Target: TargetStore, Reversibility: Irreversible, AuditKind: "settings.thing.changed"},
		Plan: func(_ context.Context, _ PlanContext, i in) ([]TypedStep[payload], error) {
			if b.plan != nil {
				return b.plan(), nil
			}
			cls := b.class
			if cls == "" {
				cls = Reversible
			}
			return []TypedStep[payload]{{
				Plan: StepPlan{Target: authority.TargetRef{GUID: "row-1", Class: "thing"}, Kind: "set", Reversibility: cls,
					Diff: []Change{{Attribute: "name", Before: []string{"old"}, After: []string{i.Name}}, {Attribute: "token", Secret: true, Before: []string{"s1"}, After: []string{"s2"}}}},
				Payload: payload{Row: "row-1"},
			}}, nil
		},
		Apply: func(_ context.Context, s step.Step, p TypedStep[payload]) (out, error) {
			if b.onApply != nil {
				b.onApply(s)
			}
			if err := s.Valid(); err != nil {
				return out{}, err
			}
			if b.applyErr != nil {
				return out{}, b.applyErr
			}
			*b.applied++
			s.Tx().(*fakeTx).writes = append(s.Tx().(*fakeTx).writes, p.Payload.Row)
			return out{Row: p.Payload.Row}, nil
		},
		Verify: func(context.Context, step.Step, TypedStep[payload], out) (Verdict, error) {
			if b.verifyOK {
				return Verdict{OK: true}, nil
			}
			return Verdict{Reason: "mismatch"}, nil
		},
		Inverse: func(TypedStep[payload], out) (in, error) { return in{}, ErrIrreversible },
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func newRunner(t *testing.T, b behaviour, az *authzFake, f LiveFacts, s sink) (*Runner, *fakeDB) {
	t.Helper()
	db := &fakeDB{}
	reg, err := NewRegistry(b.action(t, db))
	if err != nil {
		t.Fatal(err)
	}
	if az == nil {
		az = &authzFake{}
	}
	r, err := NewRunner(Config{DB: db, Audit: s, Authz: az, Registry: reg, Facts: f,
		Now: func() time.Time { return time.Unix(1_700_000_000, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	r.sleep = func(time.Duration) {}
	return r, db
}

func req() Request {
	return Request{Tenant: tenant.New(), Operation: "op-1", Action: "settings.thing.set", Input: Input(`{"Name":"new"}`),
		Actor: authority.Chain{Requester: authority.Principal{ID: "alice", Kind: authority.Human}}}
}

func TestHoldsMinter(t *testing.T) {
	if !HoldsMinter() {
		t.Fatal("operation does not hold the minter")
	}
	if _, err := step.TakeMinter(); !errors.Is(err, step.ErrMinterTaken) {
		t.Fatalf("a second taker got the minter: %v", err)
	}
}

func TestSuccessWritesAndRecordsOneEvent(t *testing.T) {
	r, db := newRunner(t, behaviour{verifyOK: true}, nil, factsFake{}, sink{})
	res, err := r.RunStore(context.Background(), req())
	if err != nil {
		t.Fatal(err)
	}
	if len(db.writes) != 1 || len(db.committed) != 1 || len(res.Steps) != 1 {
		t.Fatalf("writes=%v events=%d steps=%d", db.writes, len(db.committed), len(res.Steps))
	}
	ev := db.committed[0]
	if ev.Outcome != audit.Success || ev.Kind != "settings.thing.changed" || ev.PlanHash != res.PlanHash || ev.PlanHash == "" {
		t.Fatalf("event = %+v", ev)
	}
	if db.readOnly != 1 {
		t.Fatalf("plan transaction READ ONLY statements = %d", db.readOnly)
	}
	for _, c := range ev.Changes {
		if c.Secret && (c.Before != nil || c.After != nil) {
			t.Fatal("secret value reached the audit event")
		}
	}
}

func TestApplyFailureRollsBackAndRecordsFailure(t *testing.T) {
	r, db := newRunner(t, behaviour{applyErr: errors.New("boom"), verifyOK: true}, nil, factsFake{}, sink{})
	_, err := r.RunStore(context.Background(), req())
	if err == nil {
		t.Fatal("no error")
	}
	if len(db.writes) != 0 {
		t.Fatalf("a failed write committed: %v", db.writes)
	}
	if len(db.committed) != 1 || db.committed[0].Outcome != audit.Failure || db.committed[0].Reason != "apply_failed" {
		t.Fatalf("events = %+v", db.committed)
	}
	if strings.Contains(db.committed[0].Reason, "boom") {
		t.Fatal("error text leaked into the event reason")
	}
}

func TestVerifyMismatchRollsBackAndRecordsFailure(t *testing.T) {
	r, db := newRunner(t, behaviour{verifyOK: false}, nil, factsFake{}, sink{})
	_, err := r.RunStore(context.Background(), req())
	if !errors.Is(err, ErrVerify) || len(db.writes) != 0 {
		t.Fatalf("err=%v writes=%v", err, db.writes)
	}
	if len(db.committed) != 1 || db.committed[0].Reason != "verify_failed" || db.committed[0].Outcome != audit.Failure {
		t.Fatalf("events = %+v", db.committed)
	}
}

func TestDeniedAtPlanWritesNothingAndRecordsDenial(t *testing.T) {
	applied := 0
	az := &authzFake{deny: map[authority.PrincipalID]bool{"alice": true}}
	r, db := newRunner(t, behaviour{verifyOK: true, applied: &applied}, az, factsFake{}, sink{})
	_, err := r.RunStore(context.Background(), req())
	if !errors.Is(err, ErrDenied) || applied != 0 || len(db.writes) != 0 {
		t.Fatalf("err=%v applied=%d", err, applied)
	}
	if len(db.committed) != 1 || db.committed[0].Outcome != audit.Denied {
		t.Fatalf("events = %+v", db.committed)
	}
}

func TestRoleLostBetweenPlanAndApplyIsRefusedAtApply(t *testing.T) {
	applied := 0
	az := &authzFake{}
	az.denyAt.Store(2) // 1st call = Plan check, 2nd = the Apply-time re-check
	r, db := newRunner(t, behaviour{verifyOK: true, applied: &applied}, az, factsFake{}, sink{})
	_, err := r.RunStore(context.Background(), req())
	if !errors.Is(err, ErrDenied) || applied != 0 || len(db.writes) != 0 {
		t.Fatalf("err=%v applied=%d writes=%v", err, applied, db.writes)
	}
	if len(db.committed) != 1 || db.committed[0].Outcome != audit.Denied || db.committed[0].Reason != "denied" {
		t.Fatalf("events = %+v", db.committed)
	}
}

func TestTier0AndUnreadableFactsAreRefused(t *testing.T) {
	for name, f := range map[string]factsFake{"tier0": {tier0: true}, "facts error": {err: errors.New("dc down")}} {
		applied := 0
		r, db := newRunner(t, behaviour{verifyOK: true, applied: &applied}, nil, f, sink{})
		_, err := r.RunStore(context.Background(), req())
		if !errors.Is(err, ErrDenied) || applied != 0 {
			t.Errorf("%s: err=%v applied=%d", name, err, applied)
		}
		if len(db.committed) != 1 || db.committed[0].Outcome != audit.Denied {
			t.Errorf("%s: events = %+v", name, db.committed)
		}
	}
}

func TestSmuggledStepIsDeadAfterApply(t *testing.T) {
	var kept step.Step
	r, _ := newRunner(t, behaviour{verifyOK: true, onApply: func(s step.Step) { kept = s }}, nil, factsFake{}, sink{})
	if _, err := r.RunStore(context.Background(), req()); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(kept.Valid(), step.ErrRevoked) || kept.Tx() != nil {
		t.Fatalf("a copy of the step survived: %v", kept.Valid())
	}
}

func TestOutcomeRecordRetriesThenSurfacesErrRecord(t *testing.T) {
	r, db := newRunner(t, behaviour{applyErr: errors.New("boom"), verifyOK: true}, nil, factsFake{}, sink{})
	// transaction 1 is the plan, transaction 2 the business one; fail the next two record attempts
	db.failOpen = 0
	calls := 0
	rdb := &flaky{fakeDB: db, failFrom: 3, failCount: 2, calls: &calls}
	r.cfg.DB = rdb
	_, err := r.RunStore(context.Background(), req())
	if err == nil || errors.Is(err, ErrRecord) {
		t.Fatalf("err = %v (two failed record attempts then success must return only the cause)", err)
	}
	if len(db.committed) != 1 {
		t.Fatalf("events = %d, want exactly one under one event ID", len(db.committed))
	}
	// every attempt fails: ErrRecord is surfaced
	r2, _ := newRunner(t, behaviour{applyErr: errors.New("boom"), verifyOK: true}, nil, factsFake{}, sink{})
	calls = 0
	r2.cfg.DB = &flaky{fakeDB: &fakeDB{}, failFrom: 3, failCount: 100, calls: &calls}
	_, err = r2.RunStore(context.Background(), req())
	if !errors.Is(err, ErrRecord) {
		t.Fatalf("err = %v, want ErrRecord", err)
	}
}

// flaky fails transactions number failFrom.. failFrom+failCount-1 before they open.
type flaky struct {
	*fakeDB
	failFrom, failCount int
	calls               *int
}

func (f *flaky) WithTenant(ctx context.Context, id tenant.ID, fn func(context.Context, store.Tx) error) error {
	*f.calls++
	if *f.calls >= f.failFrom && *f.calls < f.failFrom+f.failCount {
		return errors.New("lock timeout")
	}
	return f.fakeDB.WithTenant(ctx, id, fn)
}

func TestAuditAppendFailureRollsBackTheChange(t *testing.T) {
	r, db := newRunner(t, behaviour{verifyOK: true}, nil, factsFake{}, sink{fail: true})
	_, err := r.RunStore(context.Background(), req())
	if err == nil || len(db.writes) != 0 {
		t.Fatalf("err=%v writes=%v: a change committed without its event", err, db.writes)
	}
}

func TestPlanContractViolations(t *testing.T) {
	cases := map[string]func() []TypedStep[payload]{
		"no kind":  func() []TypedStep[payload] { return []TypedStep[payload]{{Plan: StepPlan{Reversibility: Reversible}}} },
		"no class": func() []TypedStep[payload] { return []TypedStep[payload]{{Plan: StepPlan{Kind: "set"}}} },
	}
	for name, plan := range cases {
		r, db := newRunner(t, behaviour{verifyOK: true, plan: plan}, nil, factsFake{}, sink{})
		_, err := r.RunStore(context.Background(), req())
		if !errors.Is(err, ErrInvalid) || len(db.writes) != 0 {
			t.Errorf("%s: err=%v", name, err)
		}
	}
	// a Descriptor that says Reversible must not get an Irreversible step
	d := Descriptor{ID: "settings.thing.set", Version: 1, Permission: "p", Input: "i", Target: TargetStore, Reversibility: Reversible, AuditKind: "k"}
	a, _ := Define(Typed[in, payload, out]{Descriptor: d,
		Plan: func(context.Context, PlanContext, in) ([]TypedStep[payload], error) {
			return []TypedStep[payload]{{Plan: StepPlan{Kind: "set", Reversibility: Irreversible}}}, nil
		},
		Apply: func(context.Context, step.Step, TypedStep[payload]) (out, error) { return out{}, nil },
		Verify: func(context.Context, step.Step, TypedStep[payload], out) (Verdict, error) {
			return Verdict{OK: true}, nil
		},
		Inverse: func(TypedStep[payload], out) (in, error) { return in{}, nil }})
	reg, _ := NewRegistry(a)
	db := &fakeDB{}
	r, _ := NewRunner(Config{DB: db, Audit: sink{}, Authz: &authzFake{}, Registry: reg})
	if _, err := r.RunStore(context.Background(), req()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v", err)
	}
}

func TestNoStepsIsNoChange(t *testing.T) {
	r, db := newRunner(t, behaviour{verifyOK: true, plan: func() []TypedStep[payload] { return nil }}, nil, factsFake{}, sink{})
	res, err := r.RunStore(context.Background(), req())
	if err != nil || !res.NoChange || len(db.writes) != 0 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

type gateFake struct {
	route Route
	err   error
}

func (gateFake) ID() GateID                                          { return "fake" }
func (g gateFake) Route(context.Context, PlanSummary) (Route, error) { return g.route, g.err }

func TestGateFailsClosed(t *testing.T) {
	cases := map[string]gateFake{
		"error":   {err: errors.New("down")},
		"hold":    {route: Route{Kind: RouteHold, Ref: "r1"}},
		"deny":    {route: Route{Kind: RouteDeny}},
		"garbage": {route: Route{Kind: "maybe"}},
	}
	for name, g := range cases {
		applied := 0
		r, db := newRunner(t, behaviour{verifyOK: true, applied: &applied}, nil, factsFake{}, sink{})
		r.cfg.Gate = g
		_, err := r.RunStore(context.Background(), req())
		if err == nil || applied != 0 || len(db.writes) != 0 {
			t.Errorf("%s: err=%v applied=%d", name, err, applied)
		}
		if len(db.committed) != 1 || db.committed[0].Outcome == audit.Success {
			t.Errorf("%s: events=%+v", name, db.committed)
		}
	}
}

func TestStepUpRequired(t *testing.T) {
	applied := 0
	b := behaviour{verifyOK: true, applied: &applied}
	db := &fakeDB{}
	a := b.action(t, db).(defined[in, payload, out])
	a.t.Descriptor.StepUp = true
	reg, _ := NewRegistry(a)
	r, _ := NewRunner(Config{DB: db, Audit: sink{}, Authz: &authzFake{}, Registry: reg})
	rq := req()
	if _, err := r.RunStore(context.Background(), rq); !errors.Is(err, ErrDenied) || applied != 0 {
		t.Fatalf("err=%v", err)
	}
	rq.FreshStepUp = true
	if _, err := r.RunStore(context.Background(), rq); err != nil {
		t.Fatal(err)
	}
}

func TestRequestAndTargetValidation(t *testing.T) {
	r, db := newRunner(t, behaviour{verifyOK: true}, nil, factsFake{}, sink{})
	bad := req()
	bad.Actor = authority.Chain{}
	if _, err := r.RunStore(context.Background(), bad); !errors.Is(err, ErrInvalid) {
		t.Fatalf("no requester: %v", err)
	}
	bad = req()
	bad.Action = "nope.nope.nope"
	if _, err := r.RunStore(context.Background(), bad); !errors.Is(err, ErrUnknown) {
		t.Fatalf("unknown: %v", err)
	}
	if db.txs != 0 {
		t.Fatal("a rejected request opened a transaction")
	}
	dir := Descriptor{ID: "objects.user.create", Version: 1, Permission: "p", Input: "i", Target: TargetAD, Reversibility: Reversible, AuditKind: "k"}
	a, _ := Define(Typed[in, payload, out]{Descriptor: dir,
		Plan:  func(context.Context, PlanContext, in) ([]TypedStep[payload], error) { return nil, nil },
		Apply: func(context.Context, step.Step, TypedStep[payload]) (out, error) { return out{}, nil },
		Verify: func(context.Context, step.Step, TypedStep[payload], out) (Verdict, error) {
			return Verdict{OK: true}, nil
		},
		Inverse: func(TypedStep[payload], out) (in, error) { return in{}, nil }})
	reg, _ := NewRegistry(a)
	r2, _ := NewRunner(Config{DB: db, Audit: sink{}, Authz: &authzFake{}, Registry: reg})
	rq := req()
	rq.Action = "objects.user.create"
	if _, err := r2.RunStore(context.Background(), rq); !errors.Is(err, ErrTarget) {
		t.Fatalf("directory action on the store runner: %v", err)
	}
}

func TestRegistry(t *testing.T) {
	b := behaviour{verifyOK: true}
	a := b.action(t, nil)
	if _, err := NewRegistry(a, a); !errors.Is(err, ErrInvalid) {
		t.Fatalf("duplicate: %v", err)
	}
	if _, err := NewRegistry(nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil: %v", err)
	}
	reg, _ := NewRegistry(a)
	if c := reg.Catalogue(); len(c) != 1 || c[0].ID != "settings.thing.set" {
		t.Fatalf("catalogue = %+v", c)
	}
	bad := a.Describe()
	for name, mut := range map[string]func(*Descriptor){
		"id":         func(d *Descriptor) { d.ID = "x" },
		"version":    func(d *Descriptor) { d.Version = 0 },
		"permission": func(d *Descriptor) { d.Permission = "" },
		"schema":     func(d *Descriptor) { d.Input = "" },
		"audit kind": func(d *Descriptor) { d.AuditKind = "" },
		"class":      func(d *Descriptor) { d.Reversibility = "" },
		"target":     func(d *Descriptor) { d.Target = "" },
	} {
		d := bad
		mut(&d)
		if err := d.validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := Define(Typed[in, payload, out]{Descriptor: bad}); !errors.Is(err, ErrInvalid) {
		t.Errorf("Define without functions: %v", err)
	}
}

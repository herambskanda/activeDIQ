package operation

import (
	"context"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

// A tiny versioned key/value "owner package" stands in for a module's table. The family is "thing.item":
// set (reversible), purge (irreversible) and restore (the inverse, reachable only through an undo).

type kvRow struct {
	val string
	ver int
}

type kvStore struct {
	mu   sync.Mutex
	rows map[string]kvRow
}

func (k *kvStore) get(n string) kvRow { k.mu.Lock(); defer k.mu.Unlock(); return k.rows[n] }

type kvIn struct {
	Name, Value string
	External    bool
}
type kvPayload struct {
	Name, Before, After string
	BeforeVer           int
	External            bool
}
type kvOut struct{ Version int }
type kvRestoreIn struct {
	Name, Value string
	Version     int // the version the undone operation wrote
}

func kvTarget(n string) authority.TargetRef { return authority.TargetRef{GUID: n, Class: "thing"} }

func (k *kvStore) setAction(t *testing.T, id ActionID, rev Reversibility, stepUp bool) Action {
	a, err := Define(Typed[kvIn, kvPayload, kvOut]{
		Descriptor: Descriptor{ID: id, Version: 1, Permission: "thing.write", Input: "#/x", Target: TargetStore, Reversibility: rev,
			AuditKind: "thing.item.changed", StepUp: stepUp},
		Plan: func(_ context.Context, _ PlanContext, in kvIn) ([]TypedStep[kvPayload], error) {
			cur := k.get(in.Name)
			if cur.val == in.Value {
				return nil, nil
			}
			if in.Value == "forbidden" {
				return nil, &PlanRefusal{Code: "value_not_allowed", Target: kvTarget(in.Name)}
			}
			sp := StepPlan{Target: kvTarget(in.Name), Kind: "thing.set", Reversibility: rev,
				Diff: []Change{{Attribute: "value", Before: []string{cur.val}, After: []string{in.Value}}}}
			if in.External {
				sp.Confirmations = []Confirmation{{Kind: "external_recipients", Items: []string{"x@example.org"}}}
			}
			return []TypedStep[kvPayload]{{Plan: sp, Payload: kvPayload{in.Name, cur.val, in.Value, cur.ver, in.External}}}, nil
		},
		Apply: func(_ context.Context, _ step.Step, p TypedStep[kvPayload]) (kvOut, error) {
			k.mu.Lock()
			defer k.mu.Unlock()
			r := k.rows[p.Payload.Name]
			r.val, r.ver = p.Payload.After, r.ver+1
			k.rows[p.Payload.Name] = r
			return kvOut{Version: r.ver}, nil
		},
		Verify: func(context.Context, step.Step, TypedStep[kvPayload], kvOut) (Verdict, error) {
			return Verdict{OK: true}, nil
		},
		Inverse: func(p TypedStep[kvPayload], o kvOut) (kvIn, error) {
			if rev == Irreversible {
				return kvIn{}, ErrIrreversible
			}
			return kvIn{}, nil // unused: the restore input is built below
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return withRestoreInverse(a)
}

// withRestoreInverse makes the Action's Inverse the input of thing.item.restore.
type restoreInv struct{ Action }

func withRestoreInverse(a Action) Action { return restoreInv{a} }

func (r restoreInv) Inverse(p StepPlan, o Outcome) (Input, error) {
	if _, err := r.Action.Inverse(p, o); err != nil {
		return nil, err
	}
	var pl kvPayload
	var out kvOut
	if err := decodeJSON(p.Payload, &pl); err != nil {
		return nil, err
	}
	if err := decodeJSON(o.Payload, &out); err != nil {
		return nil, err
	}
	return Input(fmt.Sprintf(`{"Name":%q,"Value":%q,"Version":%d}`, pl.Name, pl.Before, out.Version)), nil
}

func (k *kvStore) restoreAction(t *testing.T) Action {
	a, err := Define(Typed[kvRestoreIn, kvPayload, kvOut]{
		Descriptor: Descriptor{ID: "thing.item.restore", Version: 1, Permission: "thing.restore", Input: "#/x", Target: TargetStore,
			Reversibility: Reversible, AuditKind: "thing.item.changed"},
		Plan: func(_ context.Context, pc PlanContext, in kvRestoreIn) ([]TypedStep[kvPayload], error) {
			cur := k.get(in.Name)
			if cur.ver != in.Version { // the family's own version check
				return nil, &PlanRefusal{Code: "superseded", Target: kvTarget(in.Name)}
			}
			if in.Value == "owner-only" {
				return nil, &PlanRefusal{Code: "owner_only", Target: kvTarget(in.Name)}
			}
			sp := StepPlan{Target: kvTarget(in.Name), Kind: "thing.set", Reversibility: Reversible,
				Diff: []Change{{Attribute: "value", Before: []string{cur.val}, After: []string{in.Value}}}}
			return []TypedStep[kvPayload]{{Plan: sp, Payload: kvPayload{in.Name, cur.val, in.Value, cur.ver, false}}}, nil
		},
		Apply: func(_ context.Context, _ step.Step, p TypedStep[kvPayload]) (kvOut, error) {
			k.mu.Lock()
			defer k.mu.Unlock()
			r := k.rows[p.Payload.Name]
			r.val, r.ver = p.Payload.After, r.ver+1
			k.rows[p.Payload.Name] = r
			return kvOut{Version: r.ver}, nil
		},
		Verify: func(context.Context, step.Step, TypedStep[kvPayload], kvOut) (Verdict, error) {
			return Verdict{OK: true}, nil
		},
		Inverse: func(TypedStep[kvPayload], kvOut) (kvRestoreIn, error) { return kvRestoreIn{}, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return withRestoreInverse(a)
}

// permAuthz grants by (principal, permission).
type permAuthz struct{ grants map[string]bool }

func (permAuthz) FactsQuery(_ authority.Chain, _ authz.Permission, t authority.TargetRef) authority.FactsQuery {
	return authority.FactsQuery{Target: t}
}
func (a permAuthz) Authorize(_ context.Context, c authority.Chain, p authz.Permission, _ authority.TargetRef, _ authority.Facts) error {
	if a.grants[string(c.Requester.ID)+"/"+string(p)] {
		return nil
	}
	return errors.New("not granted")
}

type srig struct {
	t    *testing.T
	d    *storetest.Database
	db   *store.DB
	r    *Runner
	kv   *kvStore
	tn   tenant.ID
	az   permAuthz
	gate *swapGate
}

type swapGate struct {
	mu sync.Mutex
	g  Gate
}

func (s *swapGate) ID() GateID { return "swap" }
func (s *swapGate) Route(ctx context.Context, p PlanSummary) (Route, error) {
	s.mu.Lock()
	g := s.g
	s.mu.Unlock()
	return g.Route(ctx, p)
}
func (s *swapGate) set(g Gate) { s.mu.Lock(); s.g = g; s.mu.Unlock() }

func newSRig(t *testing.T, s *storetest.Server) *srig {
	t.Helper()
	d := s.NewDatabase(t)
	d.Migrate(t)
	ctx := context.Background()
	db, err := store.Open(ctx, store.Config{DSN: d.AppDSN()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	ch := audit.NewChainer(db)
	cp := audit.NewCheckpointer(ch, keySrc{})
	tn := tenanttest.Seed(t, d.ExecOwner, "A")
	if err := db.WithTenant(ctx, tn, func(ctx context.Context, tx store.Tx) error { return cp.InitTenant(ctx, tx, tn) }); err != nil {
		t.Fatal(err)
	}
	kv := &kvStore{rows: map[string]kvRow{}}
	reg, err := NewRegistry(kv.setAction(t, "thing.item.set", Reversible, false), kv.setAction(t, "thing.item.purge", Irreversible, false),
		kv.setAction(t, "thing.item.setstrict", Reversible, true), kv.restoreAction(t))
	if err != nil {
		t.Fatal(err)
	}
	az := permAuthz{grants: map[string]bool{}}
	for _, who := range []string{"alice", "bob", "tok"} {
		az.grants[who+"/thing.write"], az.grants[who+"/thing.restore"], az.grants[who+"/thing.base"] = true, true, true
	}
	az.grants["carol/thing.write"], az.grants["carol/thing.base"] = true, true // no thing.restore
	gate := &swapGate{g: PermissionOnly{}}
	rn, err := NewRunner(Config{DB: db, Audit: ch, Authz: az, Registry: reg, Gate: gate, Component: "test"})
	if err != nil {
		t.Fatal(err)
	}
	rn.sleep = func(time.Duration) {}
	return &srig{t: t, d: d, db: db, r: rn, kv: kv, tn: tn, az: az, gate: gate}
}

func (s *srig) count(sql string, args ...any) int {
	s.t.Helper()
	ctx := context.Background()
	c, err := s.d.Admin(ctx)
	if err != nil {
		s.t.Fatal(err)
	}
	defer c.Close(ctx)
	var n int
	if err := c.QueryRow(ctx, sql, args...).Scan(&n); err != nil {
		s.t.Fatal(err)
	}
	return n
}

func (s *srig) str(sql string, args ...any) string {
	s.t.Helper()
	ctx := context.Background()
	c, err := s.d.Admin(ctx)
	if err != nil {
		s.t.Fatal(err)
	}
	defer c.Close(ctx)
	var v string
	if err := c.QueryRow(ctx, sql, args...).Scan(&v); err != nil {
		s.t.Fatal(err)
	}
	return v
}

var seq int

func newOpID() step.OperationID {
	seq++
	return step.OperationID(fmt.Sprintf("00000000-0000-4000-8000-%012d", seq))
}

func human(id string) authority.Chain {
	return authority.Chain{Requester: authority.Principal{ID: authority.PrincipalID(id), Kind: authority.Human}}
}

func (s *srig) set(who string, action ActionID, name, val string, ext bool, confirmed ...Confirmation) (Result, error) {
	in := Input(fmt.Sprintf(`{"Name":%q,"Value":%q,"External":%v}`, name, val, ext))
	return s.r.SubmitStore(context.Background(), Request{Tenant: s.tn, Actor: human(who), Action: action, Input: in, Operation: newOpID(), Confirmed: confirmed})
}

func (s *srig) undo(who string, orig step.OperationID) (Result, error) {
	return s.r.UndoStore(context.Background(), s.undoReq(who, orig))
}

func (s *srig) undoReq(who string, orig step.OperationID) UndoRequest {
	return UndoRequest{Tenant: s.tn, Actor: human(who), Family: "thing.item", Base: "thing.base", Original: orig, Operation: newOpID()}
}

func notUndoable(t *testing.T, err error, code string) {
	t.Helper()
	var nu *NotUndoableError
	if !errors.As(err, &nu) || nu.Code != code {
		t.Fatalf("want not undoable %q, got %v", code, err)
	}
}

// auditCount counts chained events of an outcome and reason (they live in the envelope).
func (s *srig) auditCount(outcome, reason string) int {
	s.t.Helper()
	ctx := context.Background()
	c, err := s.d.Admin(ctx)
	if err != nil {
		s.t.Fatal(err)
	}
	defer c.Close(ctx)
	rows, err := c.Query(ctx, `SELECT envelope FROM public.audit_event`)
	if err != nil {
		s.t.Fatal(err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			s.t.Fatal(err)
		}
		env, err := audit.ParseEnvelope(raw)
		if err != nil {
			s.t.Fatal(err)
		}
		if env.Outcome == outcome && env.Reason == reason {
			n++
		}
	}
	return n
}

var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// AC1: a preview writes nothing and answers every field.
func TestPreviewStoreWritesNothing(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, srv *storetest.Server) {
		s := newSRig(t, srv)
		ctx := context.Background()
		ops, evs := s.count(`SELECT count(*) FROM public.operations`), s.count(`SELECT count(*) FROM public.audit_event`)
		prev := func(who string, action ActionID, in string) Preview {
			p, err := s.r.PreviewStore(ctx, Request{Tenant: s.tn, Actor: human(who), Action: action, Input: Input(in)})
			if err != nil {
				t.Fatal(err)
			}
			return p
		}
		p := prev("alice", "thing.item.set", `{"Name":"a","Value":"1","External":true}`)
		if !sha256Hex.MatchString(p.PlanHash) || p.Outcome != PreviewReady || p.Reversibility != Reversible || len(p.Steps) != 1 ||
			len(p.Blocked) != 0 || !p.Undo.Possible || p.Hold != HoldNone || p.Action != "thing.item.set" {
			t.Fatalf("preview = %+v", p)
		}
		if len(p.Confirmations) != 1 || p.Confirmations[0].Kind != "external_recipients" || p.Confirmations[0].Items[0] != "x@example.org" {
			t.Fatalf("confirmations = %+v", p.Confirmations)
		}
		if q := prev("alice", "thing.item.purge", `{"Name":"a","Value":"1"}`); q.Reversibility != Irreversible || q.Undo.Possible {
			t.Fatalf("purge preview undo = %+v", q)
		}
		if q := prev("alice", "thing.item.set", `{"Name":"a","Value":""}`); q.Outcome != PreviewNoChange {
			t.Fatalf("no-change preview = %+v", q)
		}
		if q := prev("alice", "thing.item.set", `{"Name":"a","Value":"forbidden"}`); q.Outcome != PreviewRefused || len(q.Blocked) != 1 || q.Blocked[0].Code != "value_not_allowed" || !sha256Hex.MatchString(q.PlanHash) {
			t.Fatalf("refused preview = %+v", q)
		}
		if q := prev("mallory", "thing.item.set", `{"Name":"a","Value":"1"}`); q.Outcome != PreviewRefused || q.Blocked[0].Code != "denied" {
			t.Fatalf("denied preview = %+v", q)
		}
		s.gate.set(holdGate{route: Route{Kind: RouteHold}})
		if q := prev("alice", "thing.item.set", `{"Name":"a","Value":"1"}`); q.Outcome != PreviewNeedsApproval || q.Hold != HoldGate {
			t.Fatalf("hold preview = %+v", q)
		}
		s.gate.set(PermissionOnly{})
		// A preview needs no step-up and leaves the required flag for the caller to show.
		if q := prev("alice", "thing.item.setstrict", `{"Name":"a","Value":"1"}`); !q.StepUpRequired || q.Outcome != PreviewReady {
			t.Fatalf("step-up preview = %+v", q)
		}
		if got := s.kv.get("a"); got.ver != 0 {
			t.Fatalf("preview wrote the store: %+v", got)
		}
		if n := s.count(`SELECT count(*) FROM public.operations`); n != ops {
			t.Fatalf("operations %d -> %d", ops, n)
		}
		if n := s.count(`SELECT count(*) FROM public.audit_event`); n != evs {
			t.Fatalf("audit events %d -> %d", evs, n)
		}
	})
}

// AC2: first undo restores the before-image as a new operation; then already_undone, superseded,
// irreversible and not_finished.
func TestUndoStoreAnswers(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, srv *storetest.Server) {
		s := newSRig(t, srv)
		r1, err := s.set("alice", "thing.item.set", "a", "one", false)
		if err != nil || r1.State != OpSucceeded {
			t.Fatalf("set: %+v %v", r1, err)
		}
		r2, err := s.set("alice", "thing.item.set", "a", "two", false)
		if err != nil {
			t.Fatal(err)
		}
		// superseded: a later operation changed the same row.
		_, err = s.undo("bob", r1.Operation)
		notUndoable(t, err, UndoSuperseded)
		if s.kv.get("a").val != "two" {
			t.Fatal("a superseded undo wrote")
		}
		// the first undo restores the before-image as a new operation whose undoes is the original.
		u, err := s.undo("bob", r2.Operation)
		if err != nil || u.State != OpSucceeded || u.Undoes != string(r2.Operation) {
			t.Fatalf("undo: %+v %v", u, err)
		}
		if got := s.kv.get("a").val; got != "one" {
			t.Fatalf("restored value = %q", got)
		}
		if got := s.str(`SELECT undo_of::text FROM public.operations WHERE id = $1::uuid`, string(u.Operation)); got != string(r2.Operation) {
			t.Fatalf("undo_of = %q", got)
		}
		if got := s.str(`SELECT state FROM public.operation_items WHERE operation_id = $1::uuid`, string(r2.Operation)); got != "undone" {
			t.Fatalf("original item = %q", got)
		}
		if got := s.str(`SELECT origin FROM public.operations WHERE id = $1::uuid`, string(u.Operation)); got != "undo" {
			t.Fatalf("origin = %q", got)
		}
		// undone twice.
		_, err = s.undo("bob", r2.Operation)
		notUndoable(t, err, UndoAlreadyUndone)
		// the earlier change can now be undone, since the later one was.
		// (the version check of the restore Action holds its own line: r1 wrote version 1, now at 3.)
		_, err = s.undo("bob", r1.Operation)
		if err == nil {
			t.Fatal("undo of an operation whose row moved on succeeded")
		}
		// an undo is itself an operation and can be undone.
		if _, err := s.undo("bob", u.Operation); err != nil {
			t.Fatalf("undo of the undo: %v", err)
		}
		if got := s.kv.get("a").val; got != "two" {
			t.Fatalf("redo value = %q", got)
		}
		// irreversible.
		p1, err := s.set("alice", "thing.item.purge", "z", "gone", false)
		if err != nil {
			t.Fatal(err)
		}
		_, err = s.undo("alice", p1.Operation)
		notUndoable(t, err, UndoIrreversible)
		// not finished: a held operation has not run.
		s.gate.set(holdGate{route: Route{Kind: RouteHold}})
		h, err := s.set("alice", "thing.item.set", "h", "x", false)
		if err != nil || !h.Held {
			t.Fatalf("held: %+v %v", h, err)
		}
		_, err = s.undo("alice", h.Operation)
		notUndoable(t, err, UndoNotFinished)
		// unknown operation and outside the family are not found.
		if _, err := s.undo("alice", newOpID()); !errors.Is(err, ErrNotFound) {
			t.Fatalf("unknown: %v", err)
		}
		// a principal that cannot reach the target by the base permission learns nothing.
		if _, err := s.undo("mallory", r2.Operation); !errors.Is(err, ErrNotFound) {
			t.Fatalf("no base permission: %v", err)
		}
	})
}

// AC2 / superseded by the generic check: a later forward change is found by the kernel even when the
// restore Action does not look at versions.
func TestUndoSupersededByLaterOperationWithoutActionCheck(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, srv *storetest.Server) {
		s := newSRig(t, srv)
		r1, _ := s.set("alice", "thing.item.set", "a", "one", false)
		if _, err := s.set("alice", "thing.item.set", "a", "two", false); err != nil {
			t.Fatal(err)
		}
		err := s.r.undoChecks(context.Background(), s.tn, string(r1.Operation))
		notUndoable(t, err, UndoSuperseded)
	})
}

// AC3: an inverse the undoer may not make is refused at Plan with the transition's code, and audited.
func TestUndoRefusedAtPlanIsAudited(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, srv *storetest.Server) {
		s := newSRig(t, srv)
		if _, err := s.set("alice", "thing.item.set", "o", "owner-only", false); err != nil {
			t.Fatal(err)
		}
		r, err := s.set("alice", "thing.item.set", "o", "next", false)
		if err != nil {
			t.Fatal(err)
		}
		// undo of r restores "owner-only", which the restore Action's transition check refuses.
		before := s.auditCount("denied", "owner_only")
		_, err = s.undo("bob", r.Operation)
		notUndoable(t, err, UndoPlanRefused)
		var pr *PlanRefusal
		if !errors.As(err, &pr) || pr.Code != "owner_only" {
			t.Fatalf("refusal code lost: %v", err)
		}
		if n := s.auditCount("denied", "owner_only"); n != before+1 {
			t.Fatalf("refusal audited %d times", n-before)
		}
		if s.kv.get("o").val != "next" {
			t.Fatal("a refused undo wrote")
		}
		// the preview answers the same code without writing.
		p, err := s.r.PreviewUndo(context.Background(), s.undoReq("bob", r.Operation))
		if err != nil || p.Outcome != PreviewRefused || p.Blocked[0].Code != "owner_only" {
			t.Fatalf("undo preview = %+v %v", p, err)
		}
		// an undoer without the restore Action's permission is denied at Plan, audited.
		r3, _ := s.set("alice", "thing.item.set", "p", "v", false)
		denied := s.auditCount("denied", "denied")
		_, err = s.undo("carol", r3.Operation)
		if !errors.Is(err, ErrDenied) {
			t.Fatalf("lacking permission: %v", err)
		}
		if n := s.auditCount("denied", "denied"); n != denied+1 {
			t.Fatalf("denial audited %d times", n-denied)
		}
	})
}

// An undo of an operation that itself needed approval is held (rule 8), and a held Store Action is
// persisted as awaiting_approval, running nothing.
func TestHeldStoreIsPersisted(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, srv *storetest.Server) {
		s := newSRig(t, srv)
		s.gate.set(holdGate{route: Route{Kind: RouteHold, Ref: "req-1"}})
		h, err := s.set("alice", "thing.item.set", "h", "x", false)
		if err != nil || !h.Held || h.State != OpAwaitingApproval || h.Hold != HoldGate {
			t.Fatalf("held: %+v %v", h, err)
		}
		if s.kv.get("h").ver != 0 {
			t.Fatal("a held operation ran")
		}
		if got := s.str(`SELECT state || '/' || hold_reason FROM public.operations WHERE id = $1::uuid`, string(h.Operation)); got != "awaiting_approval/gate" {
			t.Fatalf("row = %q", got)
		}
		if n := s.count(`SELECT count(*) FROM public.audit_event WHERE kind = $1`, string(KindOperationHeld)); n != 1 {
			t.Fatalf("held events = %d", n)
		}
		s.gate.set(PermissionOnly{})
		// a token that cannot step up is held step_up; an interactive human is denied.
		tok := authority.Chain{Requester: authority.Principal{ID: "tok", Kind: authority.APIToken}}
		in := Input(`{"Name":"s","Value":"1"}`)
		res, err := s.r.SubmitStore(context.Background(), Request{Tenant: s.tn, Actor: tok, Action: "thing.item.setstrict", Input: in, Operation: newOpID()})
		if err != nil || !res.Held || res.Hold != HoldStepUp {
			t.Fatalf("token: %+v %v", res, err)
		}
		if _, err := s.r.SubmitStore(context.Background(), Request{Tenant: s.tn, Actor: human("alice"), Action: "thing.item.setstrict", Input: in, Operation: newOpID()}); !errors.Is(err, ErrDenied) {
			t.Fatalf("human without MFA: %v", err)
		}
		// RunStore still fails ErrHeld for a gate hold: nothing to approve there.
		s.gate.set(holdGate{route: Route{Kind: RouteHold}})
		if _, err := s.r.RunStore(context.Background(), Request{Tenant: s.tn, Actor: human("alice"), Action: "thing.item.set", Input: in, Operation: "op-x"}); !errors.Is(err, ErrHeld) {
			t.Fatalf("RunStore hold: %v", err)
		}
	})
}

func TestUndoOfApprovedOperationIsHeld(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, srv *storetest.Server) {
		s := newSRig(t, srv)
		r, err := s.set("alice", "thing.item.set", "a", "one", false)
		if err != nil {
			t.Fatal(err)
		}
		// the original is recorded as having needed approval.
		s.exec(`UPDATE public.operations SET hold_reason = 'gate' WHERE id = $1::uuid`, string(r.Operation))
		u, err := s.undo("bob", r.Operation)
		if err != nil || !u.Held || u.Hold != HoldUndoNeededAppr {
			t.Fatalf("undo: %+v %v", u, err)
		}
		if s.kv.get("a").val != "one" {
			t.Fatal("a held undo ran")
		}
	})
}

func (s *srig) exec(sql string, args ...any) {
	s.t.Helper()
	ctx := context.Background()
	c, err := s.d.Admin(ctx)
	if err != nil {
		s.t.Fatal(err)
	}
	defer c.Close(ctx)
	if _, err := c.Exec(ctx, sql, args...); err != nil {
		s.t.Fatal(err)
	}
}

// Confirmations: a submit that differs from what its plan needs is refused.
func TestSubmitStoreConfirmationsMustMatch(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, srv *storetest.Server) {
		s := newSRig(t, srv)
		if _, err := s.set("alice", "thing.item.set", "c", "1", true); !errors.Is(err, ErrDenied) {
			t.Fatalf("missing confirmation: %v", err)
		}
		wrong := Confirmation{Kind: "external_recipients", Items: []string{"other@example.org"}}
		if _, err := s.set("alice", "thing.item.set", "c", "1", true, wrong); !errors.Is(err, ErrDenied) {
			t.Fatalf("wrong confirmation: %v", err)
		}
		if _, err := s.set("alice", "thing.item.set", "c", "1", false, wrong); !errors.Is(err, ErrDenied) {
			t.Fatalf("unneeded confirmation: %v", err)
		}
		ok := Confirmation{Kind: "external_recipients", Items: []string{"x@example.org"}}
		if _, err := s.set("alice", "thing.item.set", "c", "1", true, ok); err != nil {
			t.Fatalf("matching confirmation: %v", err)
		}
	})
}

func TestConcurrentUndoOnlyOneWins(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, srv *storetest.Server) {
		s := newSRig(t, srv)
		r, err := s.set("alice", "thing.item.set", "a", "one", false)
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		errs := make([]error, 4)
		for i := range errs {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, errs[i] = s.undo("bob", r.Operation)
			}()
		}
		wg.Wait()
		wins := 0
		for _, e := range errs {
			if e == nil {
				wins++
			} else if !errors.Is(e, ErrNotUndoable) && !strings.Contains(e.Error(), "state changed") {
				t.Logf("loser: %v", e)
			}
		}
		if wins != 1 {
			t.Fatalf("%d undos succeeded: %v", wins, errs)
		}
		if n := s.count(`SELECT count(*) FROM public.operations WHERE undo_of = $1::uuid AND state = 'succeeded'`, string(r.Operation)); n != 1 {
			t.Fatalf("%d undo operations", n)
		}
	})
}

func decodeJSON(b []byte, v any) error { return jsonUnmarshal(b, v) }

func jsonUnmarshal(b []byte, v any) error { return jsonv2.Unmarshal(b, v) }

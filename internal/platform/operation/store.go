package operation

// The persisted Store path (ADR-0005 rules 3, 8 and 10; ADR-0004 rule 14): preview without a trace,
// submit with a record, undo through the family's restore Action.

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

var uuidText = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// ---- preview ----

// PreviewOutcome is what submitting the previewed request would do now.
type PreviewOutcome string

// Preview outcomes.
const (
	PreviewReady         PreviewOutcome = "ready"
	PreviewNoChange      PreviewOutcome = "no_change"
	PreviewNeedsApproval PreviewOutcome = "needs_approval"
	PreviewRefused       PreviewOutcome = "refused"
)

// Blocked is one refusal of a preview: the object and the machine code (a PlanRefusal's, "denied" for an
// authorisation refusal or "gate_denied").
type Blocked struct {
	Target authority.TargetRef
	Code   string
}

// UndoPlan says whether the previewed change could be undone.
type UndoPlan struct {
	Possible      bool
	Reversibility Reversibility
}

// Preview is the answer of PreviewStore: what a submit of the same request would do now. It is computed
// from a fresh Plan, so a later submit plans again against the live state.
type Preview struct {
	Action         ActionID
	Version        int
	PlanHash       string
	Outcome        PreviewOutcome
	Hold           HoldReason
	StepUpRequired bool
	Reversibility  Reversibility
	Steps          []StepPlan
	Blocked        []Blocked
	Confirmations  []Confirmation
	Undo           UndoPlan
}

// PreviewStore runs a Store Action's Plan, the authorisation of every target and the gate's routing in
// a READ ONLY transaction. It persists nothing and records no audit event, so it needs no step-up and
// no confirmation. A refusal the admin should read is an answer (Outcome refused with Blocked), not an
// error; errors are for a request that cannot be planned at all.
func (r *Runner) PreviewStore(ctx context.Context, req Request) (Preview, error) {
	if err := req.Actor.Validate(); err != nil || req.Tenant.IsZero() {
		return Preview{}, fmt.Errorf("%w: request needs a tenant and a requester", ErrInvalid)
	}
	act, d, err := r.storeAction(req.Action)
	if err != nil {
		return Preview{}, err
	}
	req.Origin = originOrDefault(req.Origin)
	u := &run{r: r, req: req, act: act, d: d, persist: true}
	p := Preview{Action: d.ID, Version: d.Version, StepUpRequired: d.StepUp, Hold: HoldNone, Reversibility: Reversible,
		Steps: []StepPlan{}, Blocked: []Blocked{}, Confirmations: []Confirmation{}}
	steps, err := u.planSteps(ctx)
	if err != nil {
		var pr *PlanRefusal
		if errors.As(err, &pr) && pr.valid() {
			_ = u.checkPlan(nil) // the hash of the empty plan: a refused plan has no steps
			p.PlanHash, p.Outcome = u.planHash, PreviewRefused
			p.Blocked = append(p.Blocked, Blocked{Target: pr.Target, Code: pr.Code})
			return p, nil
		}
		return Preview{}, err
	}
	p.PlanHash, p.Steps, p.Reversibility = u.planHash, steps, worst(steps)
	p.Confirmations = requiredConfirmations(steps)
	if len(steps) == 0 {
		p.Outcome = PreviewNoChange
		return p, nil
	}
	for _, sp := range steps {
		if _, aerr := u.authorise(ctx, sp.Target); aerr != nil {
			if !errors.Is(aerr, ErrDenied) {
				return Preview{}, aerr
			}
			p.Blocked = append(p.Blocked, Blocked{Target: sp.Target, Code: "denied"})
		}
	}
	if len(p.Blocked) > 0 {
		p.Outcome = PreviewRefused
		return p, nil
	}
	hold, route, err := u.routeOf(ctx, steps)
	if err != nil {
		return Preview{}, errors.Join(ErrGate, err)
	}
	switch {
	case route.Kind == RouteDeny:
		p.Outcome = PreviewRefused
		p.Blocked = append(p.Blocked, Blocked{Target: steps[0].Target, Code: "gate_denied"})
		return p, nil
	case route.Kind != RouteAllow && route.Kind != RouteHold:
		return Preview{}, ErrGate
	case hold != HoldNone || route.Kind == RouteHold:
		if hold == HoldNone {
			hold = HoldGate
		}
		p.Outcome, p.Hold = PreviewNeedsApproval, hold
	default:
		p.Outcome = PreviewReady
	}
	p.Undo = UndoPlan{Possible: p.Reversibility != Irreversible, Reversibility: p.Reversibility}
	return p, nil
}

func (r *Runner) storeAction(id ActionID) (Action, Descriptor, error) {
	act, ok := r.cfg.Registry.Lookup(id)
	if !ok {
		return nil, Descriptor{}, fmt.Errorf("%w: %q", ErrUnknown, id)
	}
	d := act.Describe()
	if d.Target != TargetStore {
		return nil, Descriptor{}, fmt.Errorf("%w: %q targets %s", ErrTarget, d.ID, d.Target)
	}
	return act, d, nil
}

func originOrDefault(o string) string {
	if o == "" {
		return OriginAPI
	}
	return o
}

// requiredConfirmations merges the confirmations of every step: one entry per kind, items sorted and
// unique, kinds sorted.
func requiredConfirmations(steps []StepPlan) []Confirmation {
	byKind := map[string]map[string]struct{}{}
	for _, sp := range steps {
		for _, c := range sp.Confirmations {
			if byKind[c.Kind] == nil {
				byKind[c.Kind] = map[string]struct{}{}
			}
			for _, it := range c.Items {
				byKind[c.Kind][it] = struct{}{}
			}
		}
	}
	return canonConfirmations(byKind)
}

func canonConfirmations(byKind map[string]map[string]struct{}) []Confirmation {
	out := make([]Confirmation, 0, len(byKind))
	for k, items := range byKind {
		c := Confirmation{Kind: k, Items: make([]string, 0, len(items))}
		for it := range items {
			c.Items = append(c.Items, it)
		}
		sort.Strings(c.Items)
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Kind < out[j].Kind })
	return out
}

// checkConfirmations refuses a submit whose confirmations differ from what its own plan needs: neither
// fewer nor more, so a person never consents to a different set than the one applied.
func (u *run) checkConfirmations(steps []StepPlan) error {
	need := requiredConfirmations(steps)
	have := map[string]map[string]struct{}{}
	for _, c := range u.req.Confirmed {
		if have[c.Kind] == nil {
			have[c.Kind] = map[string]struct{}{}
		}
		for _, it := range c.Items {
			have[c.Kind][it] = struct{}{}
		}
	}
	got := canonConfirmations(have)
	if len(need) == len(got) && slices.EqualFunc(need, got, func(a, b Confirmation) bool { return a.Kind == b.Kind && slices.Equal(a.Items, b.Items) }) {
		return nil
	}
	if len(need) == 0 {
		return u.denied("confirmation_unexpected", ErrConfirmation)
	}
	return u.denied("confirmation_required", ErrConfirmation)
}

// ---- submit ----

// SubmitStore runs a Store Action like RunStore and records the operation (rule 3): the operation, its
// item and its step with the outcome, in the apply transaction, so it can be undone later. A plan the
// kernel or the gate holds is persisted as awaiting_approval and returns Result.Held; nothing runs. A
// non-interactive caller (token, automation) that lacks a fresh step-up is held step_up where RunStore
// would deny it. req.Operation must be a UUID.
func (r *Runner) SubmitStore(ctx context.Context, req Request) (Result, error) {
	if err := req.Actor.Validate(); err != nil || req.Tenant.IsZero() || !uuidText.MatchString(string(req.Operation)) {
		return Result{}, fmt.Errorf("%w: request needs a tenant, an operation UUID and a requester", ErrInvalid)
	}
	act, d, err := r.storeAction(req.Action)
	if err != nil {
		return Result{}, err
	}
	req.Origin = originOrDefault(req.Origin)
	if !validOrigins[req.Origin] {
		return Result{}, fmt.Errorf("%w: unknown origin", ErrInvalid)
	}
	u := &run{r: r, req: req, act: act, d: d, eventID: r.cfg.NewID(), persist: true}
	return r.finish(ctx, u)
}

func (r *Runner) finish(ctx context.Context, u *run) (Result, error) {
	res, err := u.exec(ctx)
	if err == nil {
		res.Undoes, res.Action = u.req.UndoOf, u.d.ID
		return res, nil
	}
	return Result{}, u.recordFailure(ctx, err)
}

func (u *run) insertOp(ctx context.Context, tx store.Tx, hold HoldReason, ref string) error {
	via, _ := json.Marshal(nonNilPrincipals(u.req.Actor.Via), json.Deterministic(true))
	var input, holdArg, undoOf, reqRef any
	if !u.d.SecretInput {
		input = []byte(u.req.Input)
	}
	if hold != HoldNone {
		holdArg = string(hold)
	}
	if u.req.UndoOf != "" {
		undoOf = u.req.UndoOf
	}
	if ref != "" {
		reqRef = ref
	}
	if _, err := tx.Exec(ctx, `INSERT INTO public.operations (tenant_id, id, action_id, action_version, origin, requester_id,
  requester_kind, via, state, plan_hash, input, hold_reason, step_up_fresh, undo_of, request_ref)
VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8::jsonb, 'draft', $9, $10, $11, $12, $13::uuid, $14)`,
		u.req.Tenant.String(), string(u.req.Operation), string(u.d.ID), u.d.Version, u.req.Origin, string(u.req.Actor.Requester.ID),
		string(u.req.Actor.Requester.Kind), string(via), u.planHash, input, holdArg, u.req.FreshStepUp, undoOf, reqRef); err != nil {
		return fmt.Errorf("operation: creating operation: %w", err)
	}
	return nil
}

func (u *run) walk(ctx context.Context, tx store.Tx, states ...OperationState) error {
	from := OpDraft
	for _, to := range states {
		if err := setOperationState(ctx, tx, u.req.Tenant, string(u.req.Operation), from, to); err != nil {
			return err
		}
		from = to
	}
	return nil
}

func (u *run) insertItem(ctx context.Context, tx store.Tx, i int, sp StepPlan) error {
	target, _ := json.Marshal(sp.Target, json.Deterministic(true))
	t, op := u.req.Tenant.String(), string(u.req.Operation)
	if _, err := tx.Exec(ctx, `INSERT INTO public.operation_items (tenant_id, operation_id, item_no, state, phase, target)
VALUES ($1::uuid, $2::uuid, $3, 'pending', $4, $5::jsonb)`, t, op, i, sp.Phase, string(target)); err != nil {
		return fmt.Errorf("operation: inserting item: %w", err)
	}
	plan, err := json.Marshal(sp, json.Deterministic(true))
	if err != nil {
		return fmt.Errorf("%w: plan does not encode", ErrInvalid)
	}
	dg := stepDigest(sp)
	if _, err := tx.Exec(ctx, `INSERT INTO public.operation_steps (tenant_id, operation_id, item_no, step_no, state, plan, digest,
  connection_id, dc_host, naming_context, credential)
VALUES ($1::uuid, $2::uuid, $3, 0, 'planned', $4::jsonb, $5, $6, '', $7, $8)`, t, op, i, string(plan), dg[:],
		sp.Target.Connection, string(sp.Target.NC), sp.Credential); err != nil {
		return fmt.Errorf("operation: inserting step: %w", err)
	}
	return setItemState(ctx, tx, u.req.Tenant, op, i, ItemPending, ItemPlanned, "")
}

func (u *run) persistNoChange(ctx context.Context) error {
	err := u.r.cfg.DB.WithTenant(ctx, u.req.Tenant, func(ctx context.Context, tx store.Tx) error {
		if err := u.insertOp(ctx, tx, HoldNone, ""); err != nil {
			return err
		}
		if err := u.walk(ctx, tx, OpPlanning, OpNoChange); err != nil {
			return err
		}
		return u.r.emit(ctx, tx, audit.Event{ID: u.eventID, Kind: KindOperationCompleted, Actor: u.req.Actor,
			Key: step.Key{Operation: u.req.Operation}, Outcome: audit.Success, Reason: "no_change", PlanHash: u.planHash,
			Details: detail("result", "no_change")})
	})
	if err != nil {
		return u.failed("persist_failed", err)
	}
	return nil
}

func (u *run) persistHeld(ctx context.Context, steps []StepPlan, hold HoldReason, ref string) error {
	err := u.r.cfg.DB.WithTenant(ctx, u.req.Tenant, func(ctx context.Context, tx store.Tx) error {
		if err := u.insertOp(ctx, tx, hold, ref); err != nil {
			return err
		}
		if err := u.walk(ctx, tx, OpPlanning, OpPlanned); err != nil {
			return err
		}
		for i, sp := range steps {
			if err := u.insertItem(ctx, tx, i, sp); err != nil {
				return err
			}
		}
		if err := setOperationState(ctx, tx, u.req.Tenant, string(u.req.Operation), OpPlanned, OpAwaitingApproval); err != nil {
			return err
		}
		return u.r.emit(ctx, tx, audit.Event{ID: u.eventID, Kind: KindOperationHeld, Actor: u.req.Actor,
			Key: step.Key{Operation: u.req.Operation}, Outcome: audit.Success, Reason: string(hold), PlanHash: u.planHash,
			Details: detail("hold", string(hold))})
	})
	if err != nil {
		return u.failed("persist_failed", err)
	}
	return nil
}

// persistSucceeded records the finished operation in the apply transaction: operation succeeded, each
// item succeeded, each step verified with the outcome the Action returned (the undo reads it).
func (u *run) persistSucceeded(ctx context.Context, tx store.Tx, steps []StepPlan, results []StepResult) error {
	if err := u.insertOp(ctx, tx, HoldNone, ""); err != nil {
		return u.failed("persist_failed", err)
	}
	if err := u.walk(ctx, tx, OpPlanning, OpPlanned, OpApproved, OpQueued, OpRunning); err != nil {
		return u.failed("persist_failed", err)
	}
	t, op := u.req.Tenant, string(u.req.Operation)
	for i, sp := range steps {
		fail := func(err error) error { return u.failed("persist_failed", err) }
		if err := u.insertItem(ctx, tx, i, sp); err != nil {
			return fail(err)
		}
		if err := setItemState(ctx, tx, t, op, i, ItemPlanned, ItemRunning, ""); err != nil {
			return fail(err)
		}
		key := step.Key{Operation: u.req.Operation, Item: i}
		attempt, _, err := claimStep(ctx, tx, t, key, u.r.cfg.Lease)
		if err != nil {
			return fail(err)
		}
		out, _ := json.Marshal(results[i].Outcome, json.Deterministic(true))
		if ok, err := recordStep(ctx, tx, t, key, attempt, StepApplying, StepApplied, "", false, out); err != nil || !ok {
			return fail(errors.Join(ErrConflict, err))
		}
		if ok, err := recordStep(ctx, tx, t, key, attempt, StepApplied, StepVerified, "", false, nil); err != nil || !ok {
			return fail(errors.Join(ErrConflict, err))
		}
		if err := setItemState(ctx, tx, t, op, i, ItemRunning, ItemSucceeded, ""); err != nil {
			return fail(err)
		}
	}
	if err := setOperationState(ctx, tx, t, op, OpRunning, OpSucceeded); err != nil {
		return u.failed("persist_failed", err)
	}
	return nil
}

// ---- undo ----

// Codes of NotUndoableError, the errors[].code of /problems/operation-not-undoable.
const (
	UndoIrreversible   = "irreversible"
	UndoAlreadyUndone  = "already_undone"
	UndoSuperseded     = "superseded"
	UndoNotFinished    = "not_finished"
	UndoPlanRefused    = "plan_refused"
	restoreActionSufix = ".restore"
)

// ErrNotUndoable matches every NotUndoableError.
var ErrNotUndoable = errors.New("operation: not undoable")

// NotUndoableError says why an operation has no applicable inverse.
type NotUndoableError struct{ Code string }

func (e *NotUndoableError) Error() string { return "operation: not undoable: " + e.Code }

// Is makes errors.Is(err, ErrNotUndoable) true.
func (e *NotUndoableError) Is(target error) bool { return target == ErrNotUndoable }

// UndoRequest asks to undo one finished Store operation of an Action family.
type UndoRequest struct {
	Tenant tenant.ID
	// Actor is the principal undoing, never the original requester: the inverse is planned for them.
	Actor authority.Chain
	// Family is the Action family prefix, "reports.schedule". Its restore Action is Family + ".restore".
	Family string
	// Base is the family's base permission. The undoing principal must hold it on the original's
	// target; otherwise the operation is not found, so the answer is no oracle for another's change.
	Base authz.Permission
	// Original is the operation to undo; Operation is the new undo operation's ID (a UUID).
	Original  step.OperationID
	Operation step.OperationID
	// FreshStepUp, Confirmed: as for Request.
	FreshStepUp bool
	Confirmed   []Confirmation
	// Origin is ignored: an undo's origin is "undo".
}

type undoPlan struct {
	req  Request
	orig opRecord
	n    int // items of the original
}

// planUndo reads the original, checks it can be undone and builds the restore Request.
func (r *Runner) planUndo(ctx context.Context, ur UndoRequest) (undoPlan, error) {
	var up undoPlan
	if err := ur.Actor.Validate(); err != nil || ur.Tenant.IsZero() || ur.Family == "" || ur.Base == "" || !uuidText.MatchString(string(ur.Original)) {
		return up, fmt.Errorf("%w: undo needs a tenant, an undoing principal, a family, a base permission and an operation UUID", ErrInvalid)
	}
	restoreID := ActionID(ur.Family + restoreActionSufix)
	if _, _, err := r.storeAction(restoreID); err != nil {
		return up, err
	}
	var targets []authority.TargetRef
	var plans []StepPlan
	var outs []Outcome
	err := r.cfg.DB.WithTenant(ctx, ur.Tenant, func(ctx context.Context, tx store.Tx) error {
		if _, err := tx.Exec(ctx, "SET TRANSACTION READ ONLY"); err != nil {
			return err
		}
		orig, err := loadOp(ctx, tx, ur.Tenant, string(ur.Original), false)
		if err != nil {
			return err
		}
		up.orig = orig
		var items []undoItem
		if items, err = loadUndoItems(ctx, tx, ur.Tenant, orig.ID); err != nil {
			return err
		}
		up.n = len(items)
		for _, it := range items {
			targets = append(targets, it.target)
			plans = append(plans, it.plan)
			outs = append(outs, it.outcome)
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return up, ErrNotFound
		}
		return up, err
	}
	if len(targets) == 0 || !up.orig.Action.inFamily(ur.Family) {
		return up, ErrNotFound
	}
	// Visibility first: no answer about an operation whose target the undoing principal cannot reach.
	vis := &run{r: r, req: Request{Tenant: ur.Tenant, Actor: ur.Actor}, d: Descriptor{Permission: ur.Base, Target: TargetStore}}
	for _, tg := range targets {
		if _, err := vis.authorise(ctx, tg); err != nil {
			return up, ErrNotFound
		}
	}
	if err := r.undoChecks(ctx, ur.Tenant, up.orig.ID); err != nil {
		return up, err
	}
	act, ok := r.cfg.Registry.Lookup(up.orig.Action)
	if !ok {
		return up, fmt.Errorf("%w: %q", ErrUnknown, up.orig.Action)
	}
	if act.Describe().Reversibility == Irreversible {
		return up, &NotUndoableError{Code: UndoIrreversible}
	}
	if len(plans) != 1 {
		return up, &NotUndoableError{Code: UndoPlanRefused}
	}
	if plans[0].Reversibility == Irreversible {
		return up, &NotUndoableError{Code: UndoIrreversible}
	}
	inv, err := act.Inverse(plans[0], outs[0])
	if err != nil {
		if errors.Is(err, ErrIrreversible) {
			return up, &NotUndoableError{Code: UndoIrreversible}
		}
		return up, err
	}
	up.req = Request{Tenant: ur.Tenant, Actor: ur.Actor, Action: restoreID, Input: inv, Operation: ur.Operation,
		FreshStepUp: ur.FreshStepUp, Origin: OriginUndo, UndoNeededApproval: up.orig.Hold != HoldNone || up.orig.ApprovedBy != "",
		Confirmed: ur.Confirmed, UndoOf: up.orig.ID}
	return up, nil
}

func (a ActionID) inFamily(family string) bool {
	return len(a) > len(family)+1 && string(a[:len(family)]) == family && a[len(family)] == '.'
}

type undoItem struct {
	target  authority.TargetRef
	plan    StepPlan
	outcome Outcome
	istate  ItemState
}

func loadUndoItems(ctx context.Context, tx store.Tx, t tenant.ID, op string) ([]undoItem, error) {
	rows, err := tx.Query(ctx, `SELECT i.target, i.state, s.plan, COALESCE(s.outcome, '{}'::jsonb)
FROM public.operation_items i JOIN public.operation_steps s
  ON s.tenant_id = i.tenant_id AND s.operation_id = i.operation_id AND s.item_no = i.item_no
WHERE i.tenant_id = $1::uuid AND i.operation_id = $2::uuid ORDER BY i.item_no, s.step_no`, t.String(), op)
	if err != nil {
		return nil, fmt.Errorf("operation: reading items: %w", err)
	}
	defer rows.Close()
	var out []undoItem
	for rows.Next() {
		var it undoItem
		var target, plan, outcome []byte
		var st string
		if err := rows.Scan(&target, &st, &plan, &outcome); err != nil {
			return nil, err
		}
		it.istate = ItemState(st)
		if err := json.Unmarshal(target, &it.target); err != nil {
			return nil, fmt.Errorf("operation: corrupt item target: %w", err)
		}
		if err := json.Unmarshal(plan, &it.plan); err != nil {
			return nil, fmt.Errorf("operation: corrupt plan: %w", err)
		}
		if err := json.Unmarshal(outcome, &it.outcome); err != nil {
			return nil, fmt.Errorf("operation: corrupt outcome: %w", err)
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// undoChecks answers whether orig can be undone now: it must be succeeded (not_finished), not already
// undone or being undone (already_undone), and no later forward operation may have succeeded on the same
// target (superseded). With lock, the original's row is locked FOR UPDATE, so two concurrent undos
// serialise and the second sees already_undone; markUndone does that inside the apply transaction.
func (r *Runner) undoChecks(ctx context.Context, t tenant.ID, id string) error {
	return r.cfg.DB.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		return undoChecksTx(ctx, tx, t, id, false)
	})
}

func undoChecksTx(ctx context.Context, tx store.Tx, t tenant.ID, id string, lock bool) error {
	cur, err := loadOp(ctx, tx, t, id, lock)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return ErrNotFound
		}
		return err
	}
	if cur.State != OpSucceeded {
		return &NotUndoableError{Code: UndoNotFinished}
	}
	items, err := loadUndoItems(ctx, tx, t, id)
	if err != nil {
		return err
	}
	for _, it := range items {
		if it.istate == ItemUndone {
			return &NotUndoableError{Code: UndoAlreadyUndone}
		}
	}
	var one int
	err = tx.QueryRow(ctx, `SELECT 1 FROM public.operations
WHERE tenant_id = $1::uuid AND undo_of = $2::uuid AND state IN ('awaiting_approval', 'approved', 'queued', 'running', 'succeeded') LIMIT 1`,
		t.String(), id).Scan(&one)
	if err == nil {
		return &NotUndoableError{Code: UndoAlreadyUndone}
	}
	if !store.IsNoRows(err) {
		return fmt.Errorf("operation: reading earlier undo: %w", err)
	}
	for _, it := range items {
		target, _ := json.Marshal(it.target, json.Deterministic(true))
		err = tx.QueryRow(ctx, `SELECT 1 FROM public.operations o
JOIN public.operation_items i ON i.tenant_id = o.tenant_id AND i.operation_id = o.id
JOIN public.operations orig ON orig.tenant_id = o.tenant_id AND orig.id = $2::uuid
WHERE o.tenant_id = $1::uuid AND o.id <> orig.id AND o.undo_of IS NULL AND o.created_at > orig.created_at
  AND i.state = 'succeeded' AND i.target = $3::jsonb LIMIT 1`, t.String(), id, string(target)).Scan(&one)
		if err == nil {
			return &NotUndoableError{Code: UndoSuperseded}
		}
		if !store.IsNoRows(err) {
			return fmt.Errorf("operation: reading later operations: %w", err)
		}
	}
	return nil
}

// markUndone moves the original's items and steps to undone in the apply transaction, after locking and
// re-checking it, so a concurrent second undo fails already_undone and rolls back.
func markUndone(ctx context.Context, tx store.Tx, t tenant.ID, id string) error {
	if err := undoChecksTx(ctx, tx, t, id, true); err != nil {
		return err
	}
	items, err := loadUndoItems(ctx, tx, t, id)
	if err != nil {
		return err
	}
	for i := range items {
		if err := setItemState(ctx, tx, t, id, i, ItemSucceeded, ItemUndone, ""); err != nil {
			return err
		}
	}
	return setStepsUndone(ctx, tx, t, id)
}

// UndoStore undoes a finished Store operation by running its family's restore Action, planned for the
// undoing principal with the checks of the transition it makes (ADR-0005 rule 10). The first undo is a
// new operation whose undoes is the original, so it can itself be undone. It is refused, before anything
// runs, as irreversible, already_undone, superseded or not_finished (NotUndoableError); a restore whose
// Plan refuses the undoer is refused with the Action's code and audited (NotUndoableError plan_refused
// wrapping the PlanRefusal); a missing permission is ErrDenied. An undo of an operation that itself
// needed approval is held (undo_needed_approval).
func (r *Runner) UndoStore(ctx context.Context, ur UndoRequest) (Result, error) {
	if !uuidText.MatchString(string(ur.Operation)) {
		return Result{}, fmt.Errorf("%w: the undo operation needs a UUID", ErrInvalid)
	}
	up, err := r.planUndo(ctx, ur)
	if err != nil {
		return Result{}, err
	}
	act, d, err := r.storeAction(up.req.Action)
	if err != nil {
		return Result{}, err
	}
	u := &run{r: r, req: up.req, act: act, d: d, eventID: r.cfg.NewID(), persist: true}
	orig := up.orig.ID
	u.beforeCommit = func(ctx context.Context, tx store.Tx) error { return markUndone(ctx, tx, ur.Tenant, orig) }
	res, err := r.finish(ctx, u)
	return res, mapUndoErr(err)
}

// PreviewUndo previews the inverse of a finished Store operation under the same refusal rules as
// PreviewStore. An operation that cannot be undone is a NotUndoableError, not a preview.
func (r *Runner) PreviewUndo(ctx context.Context, ur UndoRequest) (Preview, error) {
	up, err := r.planUndo(ctx, ur)
	if err != nil {
		return Preview{}, err
	}
	return r.PreviewStore(ctx, up.req)
}

// mapUndoErr turns the restore Action's Plan refusal into the undo's NotUndoableError, keeping the
// refusal in the chain for its code.
func mapUndoErr(err error) error {
	if err == nil {
		return nil
	}
	var pr *PlanRefusal
	if errors.As(err, &pr) {
		code := UndoPlanRefused
		if pr.Code == UndoSuperseded {
			code = UndoSuperseded
		}
		return fmt.Errorf("%w: %w", &NotUndoableError{Code: code}, err)
	}
	return err
}

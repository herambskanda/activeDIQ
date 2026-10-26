package operation

import (
	"context"
	crand "crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/secret"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// Pinner pins one writable DC per naming context for the whole operation (rule 5). previous is the pin
// of an earlier plan of the same operation; the Pinner keeps it while that DC is healthy.
type Pinner interface {
	Pin(ctx context.Context, connection string, nc authority.NamingContextID, previous string) (DCPin, error)
}

// DCPin is one pinned DC: its host and its DSA GUID (the NTDS Settings objectGUID in canonical form).
type DCPin struct {
	Host    string
	DSAGUID string
}

// validDSAGUID reports whether g is a canonical 8-4-4-4-12 hex GUID that is not the nil GUID. A pin that
// fails this is never persisted: the connector could read an all-zero GUID as "no pin" (rule 5).
func validDSAGUID(g string) bool {
	if len(g) != 36 {
		return false
	}
	nonZero := false
	for i := 0; i < len(g); i++ {
		c := g[i]
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		switch {
		case c >= '1' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
			nonZero = true
		case c == '0':
		default:
			return false
		}
	}
	return nonZero
}

// ErrGate is returned when the registered gate errored or did not answer: the operation stays planned
// and is never allowed (rule 8).
var ErrGate = errors.New("operation: gate did not allow")

// Submission is what SubmitDirectory returns.
type Submission struct {
	Operation step.OperationID
	State     OperationState
	PlanHash  string
	Hold      HoldReason
	Items     int
	Planned   int
	Skipped   int
	Blocked   int
	// Duplicate is true when the idempotency key matched an earlier submission, which is returned.
	Duplicate bool
}

// planPlan is the outcome of Plan for persistence.
type planItem struct {
	sp      StepPlan
	blocked string // reason when refused at Plan
	skipped bool
}

// SubmitDirectory runs the front half of a Directory Action's life: Plan, authorise every target,
// persist the operation, route it through the kernel holds and the gate, and, when allowed, queue
// its chunk jobs in the same transaction as approved -> queued (rule 6). Nothing is written to a
// directory here; the chunk jobs (RunChunk) do that.
func (r *Runner) SubmitDirectory(ctx context.Context, req Request) (Submission, error) {
	if err := req.Actor.Validate(); err != nil || req.Tenant.IsZero() {
		return Submission{}, fmt.Errorf("%w: request needs a tenant and a requester", ErrInvalid)
	}
	act, ok := r.cfg.Registry.Lookup(req.Action)
	if !ok {
		return Submission{}, fmt.Errorf("%w: %q", ErrUnknown, req.Action)
	}
	d := act.Describe()
	if d.Target == TargetStore {
		return Submission{}, fmt.Errorf("%w: %q is a Store action; use RunStore", ErrTarget, d.ID)
	}
	if r.cfg.Facts == nil {
		// Fail closed: without a Facts port the gate would read empty Facts (Tier0=false) and authorise on RBAC alone.
		return Submission{}, fmt.Errorf("%w: %q targets %s but the runner has no Facts port", ErrInvalid, d.ID, d.Target)
	}
	if req.Origin == "" {
		req.Origin = OriginAPI
	}
	if !validOrigins[req.Origin] {
		return Submission{}, fmt.Errorf("%w: unknown origin", ErrInvalid)
	}
	if req.Operation == "" {
		req.Operation = step.OperationID(newUUID())
	}
	if (len(req.Secrets) > 0) != d.SecretInput {
		return Submission{}, fmt.Errorf("%w: secrets supplied do not match the action's SecretInput", ErrInvalid)
	}
	u := &run{r: r, req: req, act: act, d: d, eventID: r.cfg.NewID()}
	if d.StepUp && !req.FreshStepUp && canStepUp(req.Actor) {
		// An interactive human who has not stepped up is refused; a token or automation is held (rule 8).
		return Submission{}, u.recordFailure(ctx, u.denied("step_up_required", ErrDenied))
	}
	opID := string(req.Operation)

	// Draft -> planning, in one transaction. A repeated idempotency key returns the first operation.
	var dup *opRecord
	err := r.cfg.DB.WithTenant(ctx, req.Tenant, func(ctx context.Context, tx store.Tx) error {
		via, _ := json.Marshal(nonNilPrincipals(req.Actor.Via))
		var input any
		if !d.SecretInput {
			input = []byte(req.Input)
		}
		valid := time.Hour
		var key any
		if req.IdempotencyKey != "" {
			key = req.IdempotencyKey
		}
		var maxObj any
		if req.MaxObjects > 0 {
			maxObj = req.MaxObjects
		}
		var id string
		err := tx.QueryRow(ctx, `INSERT INTO public.operations (tenant_id, id, action_id, action_version, origin, requester_id,
  requester_kind, via, state, plan_valid_until, input, max_objects, step_up_fresh, idempotency_key, hold_reason)
VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8::jsonb, 'draft', now() + $9 * interval '1 millisecond', $10, $11, $12, $13,
  CASE WHEN $14 THEN 'undo_needed_approval' END)
ON CONFLICT (tenant_id, requester_id, idempotency_key) WHERE idempotency_key IS NOT NULL DO NOTHING
RETURNING id::text`, req.Tenant.String(), opID, string(d.ID), d.Version, req.Origin, string(req.Actor.Requester.ID),
			string(req.Actor.Requester.Kind), string(via), valid.Milliseconds(), input, maxObj, req.FreshStepUp, key,
			req.UndoNeededApproval).Scan(&id)
		if store.IsNoRows(err) {
			var existing string
			if err := tx.QueryRow(ctx, `SELECT id::text FROM public.operations WHERE tenant_id = $1::uuid AND requester_id = $2 AND idempotency_key = $3`,
				req.Tenant.String(), string(req.Actor.Requester.ID), req.IdempotencyKey).Scan(&existing); err != nil {
				return fmt.Errorf("operation: reading earlier submission: %w", err)
			}
			rec, err := loadOp(ctx, tx, req.Tenant, existing, false)
			if err != nil {
				return err
			}
			dup = &rec
			return nil
		}
		if err != nil {
			return fmt.Errorf("operation: creating operation: %w", err)
		}
		return setOperationState(ctx, tx, req.Tenant, opID, OpDraft, OpPlanning)
	})
	if err != nil {
		return Submission{}, err
	}
	if dup != nil {
		return Submission{Operation: step.OperationID(dup.ID), State: dup.State, PlanHash: dup.PlanHash, Hold: dup.Hold, Duplicate: true}, nil
	}
	sub, err := r.planAndRoute(ctx, req.Tenant, opID, req.Input, req.Secrets, req.SecretTTL)
	if err != nil {
		return sub, err
	}
	return sub, nil
}

func nonNilPrincipals(p []authority.Principal) []authority.Principal {
	if p == nil {
		return []authority.Principal{}
	}
	return p
}

// planAndRoute plans operation opID (state planning), persists the plan and routes it.
func (r *Runner) planAndRoute(ctx context.Context, t tenant.ID, opID string, input Input, secrets map[int]secret.Secret, ttl time.Duration) (Submission, error) {
	var op opRecord
	err := r.cfg.DB.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) (err error) {
		op, err = loadOp(ctx, tx, t, opID, false)
		return err
	})
	if err != nil {
		return Submission{}, err
	}
	act, ok := r.cfg.Registry.Lookup(op.Action)
	if !ok {
		return Submission{}, fmt.Errorf("%w: %q", ErrUnknown, op.Action)
	}
	d := act.Describe()
	u := &run{r: r, req: Request{Tenant: t, Actor: op.Chain, Action: op.Action, Operation: step.OperationID(opID)}, act: act, d: d, eventID: r.cfg.NewID()}

	var steps []StepPlan
	perr := r.cfg.DB.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		if _, err := tx.Exec(ctx, "SET TRANSACTION READ ONLY"); err != nil {
			return fmt.Errorf("plan transaction: %w", err)
		}
		var err error
		steps, err = act.Plan(ctx, PlanContext{Tx: tx, Facts: pinnedReader{port: r.cfg.Facts, ad: d.Target == TargetAD, pins: maps.Clone(op.Pins)}, Pins: op.Pins}, input)
		return err
	})
	if perr == nil {
		perr = u.checkPlan(steps)
	}
	if perr != nil {
		return r.failPlan(ctx, t, op, perr)
	}
	// Pin one DC per naming context (rule 5), keeping an earlier pin while it is healthy.
	pins := authority.Pins{}
	for k, v := range op.Pins {
		pins[k] = v
	}
	dsas := authority.DSAPins{}
	for k, v := range op.DSAs {
		dsas[k] = v
	}
	items := make([]planItem, len(steps))
	for i, sp := range steps {
		items[i] = planItem{sp: sp, skipped: len(sp.Diff) == 0}
		if items[i].skipped {
			continue
		}
		if d.Target == TargetAD {
			if sp.Target.NC == "" {
				items[i].blocked = "no_pin" // an AD target without a naming context is never read or written unpinned
				continue
			}
			if r.cfg.Pinner == nil {
				return r.failPlan(ctx, t, op, fmt.Errorf("%w: no DC pinner wired", ErrInvalid))
			}
			pin, err := r.cfg.Pinner.Pin(ctx, sp.Target.Connection, sp.Target.NC, pins[sp.Target.NC])
			if err != nil {
				return r.failPlan(ctx, t, op, fmt.Errorf("pinning a DC: %w", err))
			}
			if pin.Host == "" || !validDSAGUID(pin.DSAGUID) {
				return r.failPlan(ctx, t, op, fmt.Errorf("pinning a DC: %w: pin lacks a host or a valid DSA GUID", ErrInvalid))
			}
			pins[sp.Target.NC], dsas[sp.Target.NC] = pin.Host, pin.DSAGUID
		}
		if reason := r.authoriseTarget(ctx, t, op.Chain, d.Permission, sp.Target, pins); reason != "" {
			items[i].blocked = reason
		}
	}
	hash := u.planHash
	var sub Submission
	err = r.cfg.DB.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		cur, err := loadOp(ctx, tx, t, opID, true)
		if err != nil {
			return err
		}
		if cur.State != OpPlanning || cur.Revision != op.Revision {
			return ErrConflict // cancelled or re-planned meanwhile: the plan does not land (rule 6)
		}
		sub, err = r.persistPlan(ctx, tx, t, cur, d, items, pins, dsas, hash, secrets, ttl)
		return err
	})
	if err != nil {
		return Submission{}, err
	}
	if sub.State != OpPlanned {
		return sub, nil
	}
	routed, err := r.route(ctx, t, opID)
	routed.Items, routed.Planned, routed.Skipped, routed.Blocked = sub.Items, sub.Planned, sub.Skipped, sub.Blocked
	return routed, err
}

// failPlan records planning -> plan_failed with the failure event.
func (r *Runner) failPlan(ctx context.Context, t tenant.ID, op opRecord, cause error) (Submission, error) {
	err := r.cfg.DB.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		if err := setOperationState(ctx, tx, t, op.ID, OpPlanning, OpPlanFailed); err != nil {
			return err
		}
		if err := deleteOperationSecrets(ctx, tx, t, op.ID); err != nil {
			return err
		}
		return r.emit(ctx, tx, audit.Event{ID: "op-" + op.ID + "-plan-failed", Kind: KindOperationCompleted, Actor: op.Chain,
			Key: step.Key{Operation: step.OperationID(op.ID)}, Outcome: audit.Failure, Reason: "plan_failed", Details: detail("result", "plan_failed")})
	})
	if err != nil {
		return Submission{}, err
	}
	return Submission{Operation: step.OperationID(op.ID), State: OpPlanFailed}, fmt.Errorf("plan_failed: %w", cause)
}

// authoriseTarget authorises the initiator chain over live facts and returns a block reason, or "".
func (r *Runner) authoriseTarget(ctx context.Context, tn tenant.ID, chain authority.Chain, perm authz.Permission, t authority.TargetRef, pins authority.Pins) string {
	q := r.cfg.Authz.FactsQuery(chain, perm, t)
	if r.cfg.Facts == nil {
		return "facts_unavailable"
	}
	f, err := r.cfg.Facts.Facts(ctx, pins, q)
	if err != nil {
		return "facts_unavailable"
	}
	if f.Tier0 {
		return "tier0"
	}
	if err := r.recheck(ctx, tn, chain, perm, t, f); err != nil {
		return "denied"
	}
	return ""
}

// persistPlan replaces the operation's items and steps with the plan and moves planning -> planned,
// no_change or plan_failed. A re-plan with an unchanged hash keeps the approval; a changed hash
// clears it (DM-65.I1).
func (r *Runner) persistPlan(ctx context.Context, tx store.Tx, t tenant.ID, cur opRecord, d Descriptor, items []planItem, pins authority.Pins, dsas authority.DSAPins, hash string, secrets map[int]secret.Secret, ttl time.Duration) (Submission, error) {
	opID := cur.ID
	sub := Submission{Operation: step.OperationID(opID), PlanHash: hash, Items: len(items)}
	// The approval binds the hash and the set of items blocked at plan: a re-plan that unblocks (or
	// blocks) an item changes what would run, so it clears the approval.
	var priorBlocked []int
	rowsB, err := tx.Query(ctx, `SELECT item_no FROM public.operation_items
WHERE tenant_id = $1::uuid AND operation_id = $2::uuid AND state = 'blocked' ORDER BY item_no`, t.String(), opID)
	if err != nil {
		return sub, fmt.Errorf("operation: reading prior blocked items: %w", err)
	}
	for rowsB.Next() {
		var n int
		if err := rowsB.Scan(&n); err != nil {
			rowsB.Close()
			return sub, err
		}
		priorBlocked = append(priorBlocked, n)
	}
	rowsB.Close()
	if err := rowsB.Err(); err != nil {
		return sub, err
	}
	var nowBlocked []int
	for i, it := range items {
		if it.blocked != "" {
			nowBlocked = append(nowBlocked, i)
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM public.operation_steps WHERE tenant_id = $1::uuid AND operation_id = $2::uuid`, t.String(), opID); err != nil {
		return sub, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM public.operation_items WHERE tenant_id = $1::uuid AND operation_id = $2::uuid`, t.String(), opID); err != nil {
		return sub, err
	}
	for i, it := range items {
		target, _ := json.Marshal(it.sp.Target)
		if _, err := tx.Exec(ctx, `INSERT INTO public.operation_items (tenant_id, operation_id, item_no, state, phase, target)
VALUES ($1::uuid, $2::uuid, $3, 'pending', $4, $5::jsonb)`, t.String(), opID, i, it.sp.Phase, string(target)); err != nil {
			return sub, fmt.Errorf("operation: inserting item: %w", err)
		}
		switch {
		case it.blocked != "":
			sub.Blocked++
			if err := setItemState(ctx, tx, t, opID, i, ItemPending, ItemBlocked, it.blocked); err != nil {
				return sub, err
			}
		case it.skipped:
			sub.Skipped++
			if err := setItemState(ctx, tx, t, opID, i, ItemPending, ItemSkipped, ""); err != nil {
				return sub, err
			}
		default:
			sub.Planned++
			plan, err := json.Marshal(it.sp)
			if err != nil {
				return sub, fmt.Errorf("%w: plan does not encode", ErrInvalid)
			}
			dg := stepDigest(it.sp)
			if _, err := tx.Exec(ctx, `INSERT INTO public.operation_steps (tenant_id, operation_id, item_no, step_no, state, plan, digest,
  connection_id, dc_host, naming_context, credential)
VALUES ($1::uuid, $2::uuid, $3, 0, 'planned', $4::jsonb, $5, $6, $7, $8, $9)`, t.String(), opID, i, string(plan), dg[:],
				it.sp.Target.Connection, pins[it.sp.Target.NC], string(it.sp.Target.NC), it.sp.Credential); err != nil {
				return sub, fmt.Errorf("operation: inserting step: %w", err)
			}
			if sec, ok := secrets[i]; ok {
				if err := r.putSecret(ctx, tx, t, step.Key{Operation: step.OperationID(opID), Item: i}, sec, ttl); err != nil {
					return sub, err
				}
			}
			if err := setItemState(ctx, tx, t, opID, i, ItemPending, ItemPlanned, ""); err != nil {
				return sub, err
			}
		}
	}
	next := OpPlanned
	result := ""
	switch {
	case sub.Planned == 0 && sub.Blocked > 0:
		next, result = OpPlanFailed, "plan_failed"
	case sub.Planned == 0:
		next, result = OpNoChange, "no_change"
	}
	pinsJSON, _ := json.Marshal(pins)
	dsasJSON, _ := json.Marshal(dsas)
	keep := cur.ApprovedHash == hash && slices.Equal(priorBlocked, nowBlocked)
	if _, err := tx.Exec(ctx, `UPDATE public.operations SET plan_hash = $3, pins = $4::jsonb, dsa_guids = $7::jsonb,
  plan_valid_until = now() + CASE WHEN $5 THEN interval '1 hour' ELSE interval '24 hours' END,
  approved_by = CASE WHEN $6 THEN approved_by END, approved_plan_hash = CASE WHEN $6 THEN approved_plan_hash END,
  approved_at = CASE WHEN $6 THEN approved_at END
WHERE tenant_id = $1::uuid AND id = $2::uuid`, t.String(), opID, hash, string(pinsJSON), d.Target != TargetStore, keep, string(dsasJSON)); err != nil {
		return sub, fmt.Errorf("operation: recording plan: %w", err)
	}
	if err := setOperationState(ctx, tx, t, opID, OpPlanning, next); err != nil {
		return sub, err
	}
	sub.State = next
	if result != "" {
		out := audit.Success
		if result == "plan_failed" {
			out = audit.Failure
		}
		if err := deleteOperationSecrets(ctx, tx, t, opID); err != nil {
			return sub, err
		}
		if err := r.emit(ctx, tx, audit.Event{ID: "op-" + opID + "-" + result, Kind: KindOperationCompleted, Actor: cur.Chain,
			Key: step.Key{Operation: step.OperationID(opID)}, Outcome: out, Reason: result, PlanHash: hash,
			Details: detail("blocked", sub.Blocked, "result", result, "skipped", sub.Skipped)}); err != nil {
			return sub, err
		}
	}
	return sub, nil
}

type stepRow struct {
	Item, Step int
	State      StepState
	Plan       StepPlan
}

func loadSteps(ctx context.Context, tx store.Tx, t tenant.ID, op string) ([]stepRow, error) {
	rows, err := tx.Query(ctx, `SELECT item_no, step_no, state, plan FROM public.operation_steps
WHERE tenant_id = $1::uuid AND operation_id = $2::uuid ORDER BY item_no, step_no`, t.String(), op)
	if err != nil {
		return nil, fmt.Errorf("operation: reading steps: %w", err)
	}
	defer rows.Close()
	var out []stepRow
	for rows.Next() {
		var sr stepRow
		var st string
		var plan []byte
		if err := rows.Scan(&sr.Item, &sr.Step, &st, &plan); err != nil {
			return nil, err
		}
		sr.State = StepState(st)
		if err := json.Unmarshal(plan, &sr.Plan); err != nil {
			return nil, fmt.Errorf("operation: corrupt plan: %w", err)
		}
		out = append(out, sr)
	}
	return out, rows.Err()
}

// route applies the kernel holds and the gate to a planned operation (rule 8) and, when the result is
// approved, queues it.
func (r *Runner) route(ctx context.Context, t tenant.ID, opID string) (Submission, error) {
	var op opRecord
	var rows []stepRow
	err := r.cfg.DB.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) (err error) {
		if op, err = loadOp(ctx, tx, t, opID, false); err != nil {
			return err
		}
		rows, err = loadSteps(ctx, tx, t, opID)
		return err
	})
	if err != nil {
		return Submission{}, err
	}
	sub := Submission{Operation: step.OperationID(opID), State: op.State, PlanHash: op.PlanHash, Hold: op.Hold}
	if op.State != OpPlanned {
		return sub, nil
	}
	act, _ := r.cfg.Registry.Lookup(op.Action)
	d := act.Describe()
	steps := make([]StepPlan, len(rows))
	for i, sr := range rows {
		steps[i] = sr.Plan
	}
	irrev := false
	if r.cfg.Settings != nil {
		if irrev, err = r.cfg.Settings.ApprovalForIrreversible(ctx); err != nil {
			return sub, fmt.Errorf("%w: reading tenant settings: %w", ErrGate, err)
		}
	}
	hold := kernelHold(holdInput{d: d, req: Request{Actor: op.Chain, Origin: op.Origin, MaxObjects: op.MaxObjects,
		FreshStepUp: op.StepUpFresh, UndoNeededApproval: op.Hold == HoldUndoNeededAppr}, items: len(rows),
		worst: worst(steps), irrevSetting: irrev})
	route, gerr := r.cfg.Gate.Route(ctx, PlanSummary{Action: d, Steps: steps, PlanHash: op.PlanHash,
		Irreversible: worst(steps) == Irreversible, HoldReason: hold, Origin: op.Origin, Requester: op.Chain.Requester})
	if gerr != nil || (route.Kind != RouteAllow && route.Kind != RouteHold && route.Kind != RouteDeny) {
		r.alert(ctx, Alert{Severity: "high", Reason: "gate_error", Operation: opID})
		return sub, errors.Join(ErrGate, gerr)
	}
	approved := op.ApprovedBy != "" && op.ApprovedHash == op.PlanHash
	err = r.cfg.DB.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		cur, err := loadOp(ctx, tx, t, opID, true)
		if err != nil {
			return err
		}
		if cur.State != OpPlanned || cur.Revision != op.Revision || cur.PlanHash != op.PlanHash {
			return ErrConflict
		}
		ev := func(kind audit.Kind, out audit.Outcome, reason string, dt ...any) audit.Event {
			return audit.Event{ID: "op-" + opID + "-" + string(kind) + "-" + cur.PlanHash[:12], Kind: kind, Actor: cur.Chain,
				Key: step.Key{Operation: step.OperationID(opID)}, Outcome: out, Reason: reason, PlanHash: cur.PlanHash, Details: detail(dt...)}
		}
		switch {
		case route.Kind == RouteDeny:
			sub.State = OpRejected
			if err := setOperationState(ctx, tx, t, opID, OpPlanned, OpRejected); err != nil {
				return err
			}
			if err := deleteOperationSecrets(ctx, tx, t, opID); err != nil {
				return err
			}
			return r.emit(ctx, tx, ev(KindOperationRejected, audit.Denied, "gate_denied"))
		case approved && (hold != HoldNone || route.Kind == RouteHold):
			// A re-plan with an unchanged hash keeps its approval (rule 8).
			sub.State = OpApproved
			return setOperationState(ctx, tx, t, opID, OpPlanned, OpApproved)
		case hold != HoldNone || route.Kind == RouteHold:
			reason := hold
			if reason == HoldNone {
				reason = HoldGate
			}
			sub.State, sub.Hold = OpAwaitingApproval, reason
			if _, err := tx.Exec(ctx, `UPDATE public.operations SET hold_reason = $3, request_ref = NULLIF($4, '')
WHERE tenant_id = $1::uuid AND id = $2::uuid`, t.String(), opID, string(reason), route.Ref); err != nil {
				return err
			}
			if err := setOperationState(ctx, tx, t, opID, OpPlanned, OpAwaitingApproval); err != nil {
				return err
			}
			return r.emit(ctx, tx, ev(KindOperationHeld, audit.Success, string(reason), "hold_reason", string(reason)))
		}
		sub.State = OpApproved
		return setOperationState(ctx, tx, t, opID, OpPlanned, OpApproved)
	})
	if err != nil {
		return sub, err
	}
	if sub.State == OpApproved {
		return r.queue(ctx, t, opID, sub)
	}
	return sub, nil
}

func (r *Runner) alert(ctx context.Context, a Alert) {
	if r.cfg.Alerts != nil {
		r.cfg.Alerts.Alert(ctx, a)
	}
}

// queue moves approved -> queued and enqueues the first phase's chunk jobs in the same transaction, so
// a queued operation cannot lack its jobs. A plan past plan_valid_until is re-planned first (rule 9).
func (r *Runner) queue(ctx context.Context, t tenant.ID, opID string, sub Submission) (Submission, error) {
	if r.cfg.Jobs == nil {
		return sub, fmt.Errorf("%w: no job registry wired", ErrInvalid)
	}
	expired := false
	err := r.cfg.DB.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		cur, err := loadOp(ctx, tx, t, opID, true)
		if err != nil {
			return err
		}
		if cur.State != OpApproved {
			sub.State = cur.State
			return nil
		}
		if cur.ValidUntil != nil && !cur.ValidUntil.After(r.cfg.Now()) {
			expired = true
			return nil
		}
		if err := setOperationState(ctx, tx, t, opID, OpApproved, OpQueued); err != nil {
			return err
		}
		sub.State = OpQueued
		return r.enqueueNextPhase(ctx, tx, t, cur)
	})
	if err != nil {
		return sub, err
	}
	if expired {
		return r.Replan(ctx, t, opID)
	}
	return sub, nil
}

// Chunk job args: typed references only.
type chunkArgs struct {
	Operation string `json:"operation"`
	Revision  int    `json:"revision"`
	Phase     int    `json:"phase"`
	Chunk     int    `json:"chunk"`
}

// enqueueNextPhase enqueues one apply job per chunk of the lowest phase that still has planned items.
// The unique key (operation, revision, phase, chunk) only de-duplicates; correctness comes from the
// fenced claims.
func (r *Runner) enqueueNextPhase(ctx context.Context, tx store.Tx, t tenant.ID, op opRecord) error {
	var phase *int
	if err := tx.QueryRow(ctx, `SELECT min(phase) FROM public.operation_items
WHERE tenant_id = $1::uuid AND operation_id = $2::uuid AND state IN ('planned', 'running')`, t.String(), op.ID).Scan(&phase); err != nil {
		return fmt.Errorf("operation: next phase: %w", err)
	}
	if phase == nil {
		return nil
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT item_no / $4 FROM public.operation_items
WHERE tenant_id = $1::uuid AND operation_id = $2::uuid AND phase = $3 AND state IN ('planned', 'running') ORDER BY 1`,
		t.String(), op.ID, *phase, op.ChunkSize)
	if err != nil {
		return err
	}
	var chunks []int
	for rows.Next() {
		var c int
		if err := rows.Scan(&c); err != nil {
			rows.Close()
			return err
		}
		chunks = append(chunks, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, c := range chunks {
		if _, err := r.cfg.Jobs.Enqueue(ctx, tx, jobs.Job{Kind: JobApply, Tenant: t,
			Args:      chunkArgs{Operation: op.ID, Revision: op.Revision, Phase: *phase, Chunk: c},
			UniqueKey: fmt.Sprintf("%s:%d:%d:%d", op.ID, op.Revision, *phase, c)}); err != nil {
			return fmt.Errorf("operation: enqueueing chunk: %w", err)
		}
	}
	return nil
}

// Replan plans an operation again: after its input was edited, its plan expired, or the sweeper found
// it stale. Approvals bound to an unchanged plan hash survive; a changed hash clears them and the
// operation goes back through the gate (rule 8). Steps that were claimed make an operation
// un-re-plannable: only planned, awaiting_approval and approved operations re-plan.
func (r *Runner) Replan(ctx context.Context, t tenant.ID, opID string) (Submission, error) {
	var op opRecord
	err := r.cfg.DB.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		var err error
		if op, err = loadOp(ctx, tx, t, opID, true); err != nil {
			return err
		}
		if op.Input == nil {
			return fmt.Errorf("%w: this operation carries a secret and cannot be re-planned; submit it again", ErrInvalid)
		}
		if err := setOperationState(ctx, tx, t, opID, op.State, OpPlanning); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE public.operations SET plan_revision = plan_revision + 1 WHERE tenant_id = $1::uuid AND id = $2::uuid`, t.String(), opID)
		return err
	})
	if err != nil {
		return Submission{}, err
	}
	return r.planAndRoute(ctx, t, opID, Input(op.Input), nil, 0)
}

// Status reads an operation's current state and item counts, for the API's progress view.
type Status struct {
	Operation step.OperationID
	State     OperationState
	PlanHash  string
	Hold      HoldReason
	Items     map[ItemState]int
	Steps     map[StepState]int
}

// StatusOf returns the persisted state of an operation.
func (r *Runner) StatusOf(ctx context.Context, t tenant.ID, opID string) (Status, error) {
	var st Status
	err := r.cfg.DB.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		op, err := loadOp(ctx, tx, t, opID, false)
		if err != nil {
			return err
		}
		st = Status{Operation: step.OperationID(op.ID), State: op.State, PlanHash: op.PlanHash, Hold: op.Hold,
			Items: map[ItemState]int{}, Steps: map[StepState]int{}}
		rows, err := tx.Query(ctx, `SELECT state, count(*) FROM public.operation_items WHERE tenant_id = $1::uuid AND operation_id = $2::uuid GROUP BY state`, t.String(), opID)
		if err != nil {
			return err
		}
		for rows.Next() {
			var s string
			var n int
			if err := rows.Scan(&s, &n); err != nil {
				rows.Close()
				return err
			}
			st.Items[ItemState(s)] = n
		}
		rows.Close()
		rows, err = tx.Query(ctx, `SELECT state, count(*) FROM public.operation_steps WHERE tenant_id = $1::uuid AND operation_id = $2::uuid GROUP BY state`, t.String(), opID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var s string
			var n int
			if err := rows.Scan(&s, &n); err != nil {
				return err
			}
			st.Steps[StepState(s)] = n
		}
		return rows.Err()
	})
	return st, err
}

func newUUID() string {
	var b [16]byte
	if _, err := crand.Read(b[:]); err != nil {
		panic("operation: no entropy: " + err.Error())
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := fmt.Sprintf("%x", b)
	return strings.Join([]string{h[0:8], h[8:12], h[12:16], h[16:20], h[20:32]}, "-")
}

// Job kinds of the persisted path (rule 6).
const (
	JobApply     = "operation.apply"
	JobVerify    = "operation.verify"
	JobReconcile = "operation.reconcile"
	JobSweep     = "operation.sweep"
)

type verifyArgs struct {
	Operation string `json:"operation"`
}

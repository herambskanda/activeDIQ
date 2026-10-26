package operation

import (
	"context"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"math/rand/v2"
	"sort"
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

// minter is the one step.Minter, taken while this package initialises (rule 2). A second taker in
// the process fails at start-up, and HoldsMinter lets the server boot assert it is this package.
var minter = mustTakeMinter()

func mustTakeMinter() *step.Minter {
	m, err := step.TakeMinter()
	if err != nil {
		panic("operation: the step minter was taken by another package: " + err.Error())
	}
	return m
}

// HoldsMinter reports whether this package holds the step minter. compose/server's boot asserts it.
func HoldsMinter() bool { return minter != nil }

// TxRunner opens a tenant-scoped transaction. *store.DB implements it.
type TxRunner interface {
	WithTenant(ctx context.Context, id tenant.ID, fn func(ctx context.Context, tx store.Tx) error) error
}

// Authorizer decides, over live facts, whether the initiator chain may exercise a permission on a
// target (rule 7). authz implements it with the first endpoint (T-0046). It always evaluates the
// initiator chain, never an approver.
type Authorizer interface {
	FactsQuery(chain authority.Chain, perm authz.Permission, t authority.TargetRef) authority.FactsQuery
	Authorize(ctx context.Context, chain authority.Chain, perm authz.Permission, t authority.TargetRef, f authority.Facts) error
}

// Config wires a Runner. Every field except Facts, Gate, Now, NewID and Component is required.
type Config struct {
	DB        TxRunner
	Audit     audit.Sink
	Authz     Authorizer
	Registry  *Registry
	Facts     LiveFacts // nil: authorisation reads no directory facts (Store Actions)
	Gate      Gate      // nil: the kernel default, PermissionOnly
	Now       func() time.Time
	NewID     func() string
	Component string

	// The fields below are used by the persisted Directory path. SubmitDirectory needs Jobs, Keys and
	// Pinner (when an Action writes to AD); the others are optional.

	Jobs       *jobs.Registry // enqueues the chunk jobs at approved -> queued
	Keys       DEKSource      // seals transient secrets
	Pinner     Pinner         // pins one writable DC per naming context (rule 5)
	Settings   Settings       // tenant settings read by the kernel hold rules
	Provenance Provenance     // the sock-puppet check of rule 8
	Alerts     Alerter
	Lease      time.Duration // a step claim's lease; default 2 minutes
	Slots      int           // concurrent writes per (connection, DC); default 4
	// Attempts is the transient-error attempt limit of one step; default 5. Backoff is the base delay.
	Attempts int
	Backoff  time.Duration
	// StallWindow is how long an operation with unclaimed work may make no progress before the sweeper
	// re-drives it; AbandonAfter is how long an unsubmitted plan lives. Defaults 5 minutes and 7 days.
	StallWindow  time.Duration
	AbandonAfter time.Duration
}

// Runner runs Actions through the pipeline. It is safe for concurrent use.
type Runner struct {
	cfg   Config
	sleep func(time.Duration)
}

// NewRunner validates cfg.
func NewRunner(cfg Config) (*Runner, error) {
	if cfg.DB == nil || cfg.Audit == nil || cfg.Authz == nil || cfg.Registry == nil {
		return nil, fmt.Errorf("%w: runner needs DB, Audit, Authz and Registry", ErrInvalid)
	}
	if cfg.Gate == nil {
		cfg.Gate = PermissionOnly{}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.NewID == nil {
		cfg.NewID = randomID
	}
	if cfg.Component == "" {
		cfg.Component = "operation"
	}
	if cfg.Lease <= 0 {
		cfg.Lease = 2 * time.Minute
	}
	if cfg.Slots <= 0 {
		cfg.Slots = 4
	}
	if cfg.Attempts <= 0 {
		cfg.Attempts = 5
	}
	if cfg.Backoff <= 0 {
		cfg.Backoff = 200 * time.Millisecond
	}
	if cfg.StallWindow <= 0 {
		cfg.StallWindow = 5 * time.Minute
	}
	if cfg.AbandonAfter <= 0 {
		cfg.AbandonAfter = 7 * 24 * time.Hour
	}
	rn := &Runner{cfg: cfg, sleep: time.Sleep}
	if cfg.Jobs != nil {
		if err := rn.registerJobs(cfg.Jobs); err != nil {
			return nil, err
		}
	}
	return rn, nil
}

func randomID() string {
	var b [16]byte
	if _, err := crand.Read(b[:]); err != nil {
		panic("operation: no entropy: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}

// Request is one submission.
type Request struct {
	Tenant      tenant.ID
	Actor       authority.Chain
	Action      ActionID
	Input       Input
	Operation   step.OperationID
	FreshStepUp bool // the submitter completed a fresh MFA (TM-D16)
	// Pins are the DCs pinned per naming context for this operation (rule 5), chosen by the caller of
	// the runner, never by an Action.
	Pins authority.Pins
	// DSAs are the pinned DCs' DSA GUIDs per naming context, chosen with Pins.
	DSAs authority.DSAPins

	// The fields below are used by the persisted Directory path (SubmitDirectory).

	// Origin is how the operation started (DM-41); it defaults to "api".
	Origin string
	// MaxObjects is an automation policy's blast-radius limit (DM-60.I3); zero means none.
	MaxObjects int
	// IdempotencyKey de-duplicates a retried submission per (tenant, requester) for 24 hours (rule 4).
	IdempotencyKey string
	// UndoNeededApproval: this is an undo of an operation that itself needed approval (DM-41.I3).
	UndoNeededApproval bool
	// Secrets are transient secret inputs by item number (rule 9). They are sealed into
	// operation_secrets and never appear in the plan, the input, an event or a log.
	Secrets map[int]secret.Secret
	// SecretTTL bounds the secrets' life; zero means 24 hours, and the cap is 72 hours.
	SecretTTL time.Duration
}

// StepResult is the recorded result of one step.
type StepResult struct {
	Key     step.Key
	Outcome Outcome
}

// Result is the result of a run that succeeded.
type Result struct {
	Operation step.OperationID
	PlanHash  string
	NoChange  bool
	Steps     []StepResult
}

// Record attempts when the outcome of a failed or denied run is recorded (rule 6).
const (
	recordAttempts = 5
	recordBudget   = 30 * time.Second
)

// RunStore runs a Store Action inline: Plan, gate, authorisation, then one transaction holding the
// re-check, Apply, Verify, the state change and the success event. If anything fails, that
// transaction rolls back and the failure or denial is recorded in a fresh one, under the same event
// ID, so it is never lost with the rollback (AG-2). Directory Actions need the claim, reconcile and
// persistence of rule 6 and are refused here with ErrTarget.
func (r *Runner) RunStore(ctx context.Context, req Request) (Result, error) {
	if err := req.Actor.Validate(); err != nil || req.Tenant.IsZero() || req.Operation == "" {
		return Result{}, fmt.Errorf("%w: request needs a tenant, an operation and a requester", ErrInvalid)
	}
	act, ok := r.cfg.Registry.Lookup(req.Action)
	if !ok {
		return Result{}, fmt.Errorf("%w: %q", ErrUnknown, req.Action)
	}
	d := act.Describe()
	if d.Target != TargetStore {
		return Result{}, fmt.Errorf("%w: %q targets %s", ErrTarget, d.ID, d.Target)
	}
	run := &run{r: r, req: req, act: act, d: d, eventID: r.cfg.NewID()}
	res, err := run.exec(ctx)
	if err == nil {
		return res, nil
	}
	return Result{}, run.recordFailure(ctx, err)
}

type run struct {
	r        *Runner
	req      Request
	act      Action
	d        Descriptor
	eventID  string
	planHash string
	failKey  step.Key
	failTgt  authority.TargetRef
	changes  []audit.Change
	reason   string
	outcome  audit.Outcome
}

func (u *run) denied(reason string, err error) error {
	u.reason, u.outcome = reason, audit.Denied
	return fmt.Errorf("%w: %s: %w", ErrDenied, reason, err)
}

func (u *run) failed(reason string, err error) error {
	u.reason, u.outcome = reason, audit.Failure
	return fmt.Errorf("%s: %w", reason, err)
}

func (u *run) exec(ctx context.Context) (Result, error) {
	r := u.r
	if u.d.StepUp && !u.req.FreshStepUp {
		return Result{}, u.denied("step_up_required", ErrDenied)
	}
	// Plan: before the transaction that writes. The plan transaction is READ ONLY.
	var steps []StepPlan
	err := r.cfg.DB.WithTenant(ctx, u.req.Tenant, func(ctx context.Context, tx store.Tx) error {
		if _, err := tx.Exec(ctx, "SET TRANSACTION READ ONLY"); err != nil {
			return fmt.Errorf("plan transaction: %w", err)
		}
		var perr error
		steps, perr = u.act.Plan(ctx, PlanContext{Tx: tx, Facts: u.pinnedFacts(), Pins: maps.Clone(u.req.Pins)}, u.req.Input)
		return perr
	})
	if err != nil {
		return Result{}, u.failed("plan_failed", err)
	}
	if err := u.checkPlan(steps); err != nil {
		return Result{}, u.failed("plan_invalid", err)
	}
	res := Result{Operation: u.req.Operation, PlanHash: u.planHash}
	if len(steps) == 0 {
		res.NoChange = true
		return res, nil
	}
	// Authorise every target at Plan on live facts. A refusal fails the whole run.
	for _, sp := range steps {
		u.failTgt = sp.Target
		if _, err := u.authorise(ctx, sp.Target); err != nil {
			return Result{}, err
		}
	}
	// Gate: fails closed.
	route, err := r.cfg.Gate.Route(ctx, PlanSummary{Action: u.d, Steps: steps, PlanHash: u.planHash, Irreversible: worst(steps) == Irreversible})
	if err != nil {
		return Result{}, u.failed("gate_error", errors.Join(errGate, err))
	}
	switch route.Kind {
	case RouteAllow:
	case RouteHold:
		// A held operation needs its persisted plan and the approval flow (rule 8); nothing runs.
		return Result{}, u.failed("held", ErrHeld)
	case RouteDeny:
		return Result{}, u.denied("gate_denied", ErrDenied)
	default:
		return Result{}, u.failed("gate_error", errGate)
	}
	// Apply: one transaction for every step, so the state change and the success events commit together.
	err = r.cfg.DB.WithTenant(ctx, u.req.Tenant, func(ctx context.Context, tx store.Tx) error {
		res.Steps = res.Steps[:0]
		u.changes = nil
		for i, sp := range steps {
			sr, err := u.applyOne(ctx, tx, i, sp)
			if err != nil {
				return err
			}
			res.Steps = append(res.Steps, sr)
		}
		return nil
	})
	if err != nil {
		return Result{}, err
	}
	return res, nil
}

func (u *run) applyOne(ctx context.Context, tx store.Tx, idx int, sp StepPlan) (StepResult, error) {
	r := u.r
	key := step.Key{Operation: u.req.Operation, Item: idx, Step: 0}
	u.failKey, u.failTgt = key, sp.Target
	q := r.cfg.Authz.FactsQuery(u.req.Actor, u.d.Permission, sp.Target)
	st, revoke, err := minter.Mint(step.Spec{
		Key: key, Attempt: 1, Actor: u.req.Actor, NC: sp.Target.NC, Pins: u.req.Pins, DSAs: u.req.DSAs, Tx: tx, Query: q,
		Digest: stepDigest(sp),
		Recheck: func(ctx context.Context, f authority.Facts) error {
			return r.recheck(ctx, u.req.Actor, u.d.Permission, sp.Target, f)
		},
	})
	if err != nil {
		return StepResult{}, u.failed("mint_failed", err)
	}
	defer revoke() // the Step dies when Apply or Verify returns; a smuggled copy is dead
	// The runner, not Action code, runs the Apply-time re-check, on facts read live now.
	facts, err := u.liveFacts(ctx, q, sp.Target)
	if err != nil {
		return StepResult{}, u.denied("facts_unavailable", err)
	}
	if _, err := st.Recheck(ctx, facts); err != nil {
		return StepResult{}, u.denied("denied", err)
	}
	out, err := u.act.Apply(ctx, st, sp)
	if err != nil {
		return StepResult{}, u.failed("apply_failed", err)
	}
	v, err := u.act.Verify(ctx, st, sp, out)
	if err != nil {
		return StepResult{}, u.failed("verify_error", err)
	}
	if !v.OK {
		return StepResult{}, u.failed("verify_failed", fmt.Errorf("%w: %s", ErrVerify, v.Reason))
	}
	ev := u.event(audit.Success, "applied", key, sp.Target)
	ev.Changes = changesOf(sp.Diff)
	if idx > 0 {
		ev.ID = u.eventID + fmt.Sprintf("-%d", idx)
	}
	if err := r.cfg.Audit.Append(ctx, tx, ev); err != nil {
		return StepResult{}, u.failed("audit_failed", err)
	}
	return StepResult{Key: key, Outcome: out}, nil
}

func (r *Runner) recheck(ctx context.Context, chain authority.Chain, perm authz.Permission, t authority.TargetRef, f authority.Facts) error {
	if f.Tier0 {
		return errors.New("tier0 target") // no role touches tier0 (rule 7)
	}
	return r.cfg.Authz.Authorize(ctx, chain, perm, t, f)
}

// liveFacts reads the facts for one target on the operation's pins (rule 5), so the gate and the
// write agree on the DC. An AD target whose NC has no pin is refused rather than read unpinned.
func (u *run) liveFacts(ctx context.Context, q authority.FactsQuery, t authority.TargetRef) (authority.Facts, error) {
	q.Target = t
	return u.pinnedFacts().Facts(ctx, q)
}

func (u *run) pinnedFacts() PinnedFacts {
	return pinnedReader{port: u.r.cfg.Facts, ad: u.d.Target == TargetAD, store: u.d.Target == TargetStore, pins: maps.Clone(u.req.Pins)}
}

// pinnedReader binds a LiveFacts port to one operation's pins.
type pinnedReader struct {
	port LiveFacts
	ad   bool
	// store: a Store Action, which reads no directory facts, so a nil port is legitimate.
	store bool
	pins  authority.Pins
}

func (p pinnedReader) Facts(ctx context.Context, q authority.FactsQuery) (authority.Facts, error) {
	if p.port == nil {
		if p.store {
			return authority.Facts{}, nil
		}
		return authority.Facts{}, fmt.Errorf("%w: directory target with no Facts port", ErrInvalid)
	}
	if p.ad {
		if nc := q.Target.NC; nc == "" || p.pins[nc] == "" {
			return authority.Facts{}, fmt.Errorf("%w: no DC pin for the target's naming context", ErrInvalid)
		}
	}
	return p.port.Facts(ctx, maps.Clone(p.pins), q)
}

func (u *run) authorise(ctx context.Context, t authority.TargetRef) (authority.Facts, error) {
	q := u.r.cfg.Authz.FactsQuery(u.req.Actor, u.d.Permission, t)
	f, err := u.liveFacts(ctx, q, t)
	if err != nil {
		return f, u.denied("facts_unavailable", err)
	}
	if err := u.r.recheck(ctx, u.req.Actor, u.d.Permission, t, f); err != nil {
		return f, u.denied("denied", err)
	}
	return f, nil
}

// checkPlan enforces the contract on what Plan returned and computes the plan hash.
func (u *run) checkPlan(steps []StepPlan) error {
	for i := range steps {
		sp := &steps[i]
		if sp.Kind == "" || sp.Reversibility.rank() < 0 || sp.Reversibility.rank() > u.d.Reversibility.rank() {
			return fmt.Errorf("%w: step %d of %q has no kind or a reversibility class beyond the descriptor's", ErrInvalid, i, u.d.ID)
		}
		for j := range sp.Diff {
			if sp.Diff[j].Secret { // a secret value is never held in a plan, diff or event
				sp.Diff[j].Before, sp.Diff[j].After = nil, nil
			}
		}
	}
	sort.SliceStable(steps, func(i, j int) bool { return steps[i].Phase < steps[j].Phase })
	type hashed struct {
		Action  ActionID
		Version int
		Steps   []StepPlan
	}
	b, err := json.Marshal(hashed{u.d.ID, u.d.Version, steps}, planHashOpts...)
	if err != nil {
		return fmt.Errorf("%w: plan does not encode", ErrInvalid)
	}
	sum := sha256.Sum256(b)
	u.planHash = hex.EncodeToString(sum[:])
	return nil
}

func worst(steps []StepPlan) Reversibility {
	w := Reversible
	for _, s := range steps {
		if s.Reversibility.rank() > w.rank() {
			w = s.Reversibility
		}
	}
	return w
}

func stepDigest(sp StepPlan) step.Digest {
	attrs := make([]step.Attr, 0, len(sp.Diff))
	for _, c := range sp.Diff {
		attrs = append(attrs, step.Attr{Name: c.Attribute, Values: c.After, Secret: c.Secret})
	}
	return step.Compute(sp.Kind, sp.Target, attrs)
}

func changesOf(cs []Change) []audit.Change {
	out := make([]audit.Change, len(cs))
	for i, c := range cs {
		out[i] = audit.Change{Attribute: c.Attribute, Before: c.Before, After: c.After, Secret: c.Secret}
	}
	return out
}

func (u *run) event(o audit.Outcome, reason string, key step.Key, t authority.TargetRef) audit.Event {
	return audit.Event{
		ID: u.eventID, Kind: u.d.AuditKind, At: u.r.cfg.Now(), Actor: u.req.Actor, Target: t, Key: key,
		Component: u.r.cfg.Component, Outcome: o, Reason: reason, PlanHash: u.planHash,
	}
}

// recordFailure writes the failure or denial event in a fresh transaction, because the business
// transaction rolled back (rule 6). It retries a bounded number of times under the same event ID.
// It returns the original error, joined with ErrRecord when the event could not be recorded.
func (u *run) recordFailure(ctx context.Context, cause error) error {
	if u.outcome == "" { // an error that was not classified is still a failure
		u.outcome, u.reason = audit.Failure, "failed"
	}
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), recordBudget)
	defer cancel()
	ev := u.event(u.outcome, u.reason, u.failKey, u.failTgt)
	var last error
	for attempt := 0; attempt < recordAttempts; attempt++ {
		last = u.r.cfg.DB.WithTenant(rctx, u.req.Tenant, func(ctx context.Context, tx store.Tx) error {
			return u.r.cfg.Audit.Append(ctx, tx, ev)
		})
		if last == nil {
			return cause
		}
		if rctx.Err() != nil {
			break
		}
		u.r.sleep(time.Duration(rand.Int64N(int64(50*time.Millisecond)<<attempt)) + time.Millisecond)
	}
	slog.ErrorContext(rctx, "audit.record_failed", "kind", string(ev.Kind), "operation", string(u.req.Operation),
		"principal", string(u.req.Actor.Requester.ID), "target", u.failTgt.GUID, "outcome", string(u.outcome), "reason", u.reason)
	return errors.Join(cause, fmt.Errorf("%w: %w", ErrRecord, last))
}

// planHashOpts keeps the plan-hash bytes those of the v1 encoder (nil slices and maps as null, HTML
// escaping on) with map keys sorted, so a hash recorded before the json/v2 move still verifies.
var planHashOpts = []json.Options{json.Deterministic(true), json.FormatNilSliceAsNull(true), json.FormatNilMapAsNull(true), jsontext.EscapeForHTML(true)}

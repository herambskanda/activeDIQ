// Package operation is the operation pipeline kernel package (blueprint §5.1, ADR-0005): EP-3 (Action)
// and EP-4 (approval gate). Every write a principal makes is an Action run by the Runner: Plan, gate,
// authorise, Apply with a step token, Verify, and an audit event for the outcome, including a failure
// and a denial. The state machines are in transitions.go.
package operation

import (
	"bytes"
	"context"
	"errors"
	"regexp"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// ActionID names an Action, "<owner>.<noun>.<verb>", for example "objects.user.create". It is stable
// and never reused (X6).
type ActionID string

// SchemaRef points at the OpenAPI component that describes an Action's input. The API, workflow,
// automation and the command palette all share it (blueprint §4.2).
type SchemaRef string

// TargetKind says where an Action writes.
type TargetKind string

// Target kinds. Directory Actions call directory/client with the Step; Store Actions call the owning
// package's write API with the Step, in the runner's one transaction.
const (
	TargetAD    TargetKind = "ad"
	TargetEntra TargetKind = "entra"
	TargetStore TargetKind = "store"
)

// Reversibility is the class of an Action or of one planned step.
type Reversibility string

// Reversibility classes (rule 1). The Descriptor states the worst case, Plan the class per step.
const (
	Reversible   Reversibility = "reversible"
	Lossy        Reversibility = "lossy"
	Irreversible Reversibility = "irreversible"
)

// rank orders classes by severity so a Plan can be compared with its Descriptor.
func (r Reversibility) rank() int {
	switch r {
	case Reversible:
		return 0
	case Lossy:
		return 1
	case Irreversible:
		return 2
	}
	return -1
}

// Descriptor is the static description of an Action.
type Descriptor struct {
	ID         ActionID
	Version    int
	Permission authz.Permission // checked at Plan and again at Apply
	Input      SchemaRef
	Target     TargetKind
	// TargetClass, when set, is the object class every step's Target must have (checked at Plan). An
	// Action holding a rbac.GroupMembershipPermissions permission MUST declare "group": the TM-D18
	// guard computes reach from the authorisation Target, so a step aimed at the member would compute it
	// from the wrong object.
	TargetClass   string
	Reversibility Reversibility // worst case
	AuditKind     audit.Kind    // the step event kind, declared by the same owner
	StepUp        bool          // submit needs a fresh MFA (TM-D16 §7.4)
	// StepUpWhen makes step-up depend on the Input (TM-D30 SX-1: a report schedule needs it only when
	// the after-state has an external recipient). It runs over the canonical validated Input, wherever
	// StepUp is read: submit, the kernel hold, Plan and approval. It must be pure and deterministic, and
	// it receives a copy of the Input (the kernel clones it), so writing to it cannot change what Plan
	// plans or what is persisted. An error, or an absent Input (a SecretInput Action persists none),
	// counts as "required" (fail closed). Mutually exclusive with StepUp; the registry refuses both.
	StepUpWhen  func(Input) (bool, error)
	SecretInput bool // the input carries a secret (rule 9)
	// ControlPlane marks an Action whose permission administers RBAC, delegation, scopes, connections or
	// the tenant: personal to an account, never carried by a group, token, automation policy or hybrid
	// correlation. It must equal authz.NeverCrosses(Permission); a test in compose/server holds the two.
	ControlPlane bool
}

// Input is the validated, canonically encodable input of one invocation.
type Input []byte

// NeedsStepUp reports whether an invocation with this Input requires a fresh MFA: the static StepUp
// flag, or StepUpWhen over the Input. It fails closed: a predicate that errors, panics or sees no
// Input requires step-up. Every place the kernel reads step-up goes through here.
func (d Descriptor) NeedsStepUp(in Input) (need bool) {
	if d.StepUpWhen == nil {
		return d.StepUp
	}
	if len(in) == 0 {
		return true
	}
	defer func() {
		if recover() != nil {
			need = true
		}
	}()
	need, err := d.StepUpWhen(bytes.Clone(in)) // a copy: the predicate cannot change what Plan plans
	return need || err != nil
}

// Change is one planned attribute change, before and after. Secret values are never held.
type Change struct {
	Attribute string
	Before    []string
	After     []string
	Secret    bool
}

// StepPlan is one planned step: its target, diff, preconditions, class and phase (rule 1).
type StepPlan struct {
	Target              authority.TargetRef
	Kind                string // the write's operation kind, bound into the step digest
	Diff                []Change
	Preconditions       []string
	Reversibility       Reversibility
	ReversibilityReason string
	Phase               int
	Payload             []byte
	// Credential marks a step that sets a credential. Reconciliation never re-applies it (rule 6):
	// a repeat would be refused by password history and record a false failure.
	Credential bool
	// Confirmations are what the caller must confirm before this step is submitted, such as external
	// recipients (ADR-0004 rule 14). They are recomputed by every Plan, so they are not part of the plan
	// hash or of the persisted plan.
	Confirmations []Confirmation `json:"-"`
}

// Outcome is what Apply did, as the Action read it back.
type Outcome struct {
	AlreadyApplied bool
	Payload        []byte
	// Tier0 is the connector's step-9 report: objects it found tier0 after the write, with or without
	// a basis (ADR-0005 rule 7). It counts at once and outranks every other Verify reason.
	Tier0 []step.Tier0Finding
}

// Verdict is the result of Verify.
type Verdict struct {
	OK     bool
	Reason string // machine reason code when !OK
	// Tier0 lists the objects an Action's own Verify found tier0, when Reason is tier0_after_write.
	Tier0 []step.Tier0Finding
}

// Confirmation is one thing a caller confirms after reading a preview. Kind is a closed vocabulary shared
// with the API ("external_recipients"); Items are the subjects, such as the external addresses.
type Confirmation struct {
	Kind  string
	Items []string
}

// PlanRefusal is what an Action's Plan returns when the change is refused by a rule of its own, such as
// "owner_only" or "external_not_permitted". The code is machine-readable and shown to the admin: in a
// preview as a blocked entry, and on a submit as the denied attempt's audited reason. Target is the
// object the rule refused, when there is one.
type PlanRefusal struct {
	Code   string
	Target authority.TargetRef
}

func (e *PlanRefusal) Error() string { return "operation: plan refused: " + e.Code }

var refusalCode = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

func (e *PlanRefusal) valid() bool { return e != nil && refusalCode.MatchString(e.Code) }

// Errors of the pipeline. None carries a secret or a directory response.
var (
	ErrIrreversible = errors.New("operation: step is irreversible")
	ErrDenied       = errors.New("operation: denied")
	ErrUnknown      = errors.New("operation: unknown action")
	ErrInvalid      = errors.New("operation: invalid action or plan")
	ErrVerify       = errors.New("operation: verification failed")
	ErrHeld         = errors.New("operation: held for approval")
	// ErrConfirmation is wrapped by the refusal of a submit whose confirmations differ from its plan's.
	ErrConfirmation = errors.New("operation: confirmations differ from the plan")
	ErrTarget       = errors.New("operation: target kind not supported by this runner")
	ErrRecord       = errors.New("operation: outcome could not be recorded")
	// ErrStaleState is what an Action's Apply returns, wrapped, when the target no longer shows the
	// plan's before-state. The step fails stale_state and the target is never overwritten (DM-42.I2).
	ErrStaleState = errors.New("operation: target changed since the plan")
	// ErrTransient marks a failure the same step may retry with a new attempt: connector unreachable,
	// DC busy, throttled.
	ErrTransient = errors.New("operation: transient failure")
	// ErrOutcomeUnknown is what Apply returns for a credential step whose write may or may not have
	// happened. The technician retries as a new operation (rule 6).
	ErrOutcomeUnknown = errors.New("operation: outcome unknown")
	// ErrDeferVerify is what Verify returns when the read-back cannot be completed yet (Entra, or a
	// lost DC): the step stays applied and operation.verify drives it later.
	ErrDeferVerify = errors.New("operation: verification deferred")
)

// Observation is what a live read of a step's target shows relative to its plan.
type Observation string

// Observations, for reconciliation.
const (
	ObservedBefore Observation = "before" // the planned before-state is still in place
	ObservedAfter  Observation = "after"  // the planned after-state is in place
	ObservedOther  Observation = "other"  // anything else
)

// Observer is implemented by a Directory Action so the runner can recover a step whose claim lapsed
// (rule 6). It only reads, on the pinned DC, so it takes no Step. For a Credential step, ObservedAfter
// means the credential's last-set time is later than claimedAt.
type Observer interface {
	Observe(ctx context.Context, pins authority.Pins, p StepPlan, claimedAt time.Time) (Observation, error)
}

// PlanContext is what Plan reads through: the store (read only) and live facts on the pins.
type PlanContext struct {
	Tx    store.Tx    // the runner opens it READ ONLY; Plan has no way to commit or roll it back
	Facts PinnedFacts // reads on a clone of the request's pins; Plan cannot choose a DC (rule 5)
	Pins  authority.Pins
	// Templates refuses a Template the requester's authority does not permit (ADM-132). The Runner binds
	// it to the operation's own chain and tenant, so a Plan cannot name either. Order inside a Plan:
	// Templates, then Template.CheckInput, then Render, then the first read (ADR-0015 D1). A hand-built
	// PlanContext leaves it nil; use operationtest.AllowTemplates / DenyTemplates, or any TemplateGate.
	Templates TemplateGate
}

// TemplateGate is the requester-bound form of the Template check (ADR-0015 D1). A nil error permits.
// Any error is a refusal: the Runner's gate returns *PlanRefusal{Code: "template_not_permitted"}, which
// a preview shows as a blocked entry and a submit audits as a denied attempt (rule 4).
type TemplateGate interface {
	CheckTemplate(ctx context.Context, perm authz.Permission, template string) error
}

// TemplateAuthz is the unbound form of the check: it takes the chain. *rbac.Authorizer satisfies it
// structurally. Only the Runner holds it, so only the Runner chooses the chain.
type TemplateAuthz interface {
	CheckTemplate(ctx context.Context, chain authority.Chain, perm authz.Permission, template string) error
}

const refusalTemplateNotPermitted = "template_not_permitted"

// templateGate binds a TemplateAuthz to one operation's chain and tenant. A nil authz denies.
type templateGate struct {
	authz  TemplateAuthz
	chain  authority.Chain
	tenant tenant.ID
}

func (g templateGate) CheckTemplate(ctx context.Context, perm authz.Permission, template string) error {
	refuse := &PlanRefusal{Code: refusalTemplateNotPermitted}
	if g.authz == nil {
		return refuse // fail closed
	}
	if err := g.authz.CheckTemplate(authority.WithTenant(ctx, g.tenant.String()), g.chain, perm, template); err != nil {
		return refuse // an error that is not a refusal means the check could not be made: also a refusal
	}
	return nil
}

// PinnedFacts reads live facts on the operation's pins. It has no pins parameter, so a Plan cannot
// read unpinned; an AD target whose NC has no pin is refused before the port is called.
type PinnedFacts interface {
	Facts(ctx context.Context, q authority.FactsQuery) (authority.Facts, error)
}

// LiveFacts is the port that reads, live and on the pins, exactly what q asks about one target
// (rule 7). directory/client implements it structurally; compose/server wires it.
type LiveFacts interface {
	Facts(ctx context.Context, pins authority.Pins, q authority.FactsQuery) (authority.Facts, error)
}

// Action is the one shape for every write (rule 1). No directory write is reachable except from an
// Action's Apply with a Step.
type Action interface {
	Describe() Descriptor
	// Plan is the dry run. It cannot write.
	Plan(ctx context.Context, pc PlanContext, in Input) ([]StepPlan, error)
	// Apply performs one planned step. The Step is the only key to a write.
	Apply(ctx context.Context, s step.Step, p StepPlan) (Outcome, error)
	// Verify compares the read-back with the plan's after-state.
	Verify(ctx context.Context, s step.Step, p StepPlan, o Outcome) (Verdict, error)
	// Inverse returns the input that undoes this step, or ErrIrreversible.
	Inverse(p StepPlan, o Outcome) (Input, error)
}

// templateGate is the one place a Plan's TemplateGate is built, so both Runner paths bind the same way.
func (r *Runner) templateGate(chain authority.Chain, t tenant.ID) templateGate {
	return templateGate{authz: r.cfg.TemplateAuthz, chain: chain, tenant: t}
}

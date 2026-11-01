// Package operation is the operation pipeline kernel package (blueprint §5.1, ADR-0005): EP-3 (Action)
// and EP-4 (approval gate). Every write a principal makes is an Action run by the Runner: Plan, gate,
// authorise, Apply with a step token, Verify, and an audit event for the outcome, including a failure
// and a denial. The state machines are in transitions.go.
package operation

import (
	"context"
	"errors"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/store"
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
	SecretInput   bool          // the input carries a secret (rule 9)
	// ControlPlane marks an Action whose permission administers RBAC, delegation, scopes, connections or
	// the tenant: personal to an account, never carried by a group, token, automation policy or hybrid
	// correlation. It must equal authz.NeverCrosses(Permission); a test in compose/server holds the two.
	ControlPlane bool
}

// Input is the validated, canonically encodable input of one invocation.
type Input []byte

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

// Errors of the pipeline. None carries a secret or a directory response.
var (
	ErrIrreversible = errors.New("operation: step is irreversible")
	ErrDenied       = errors.New("operation: denied")
	ErrUnknown      = errors.New("operation: unknown action")
	ErrInvalid      = errors.New("operation: invalid action or plan")
	ErrVerify       = errors.New("operation: verification failed")
	ErrHeld         = errors.New("operation: held for approval")
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

// Package operation is the operation pipeline kernel package (blueprint §5.1, ADR-0005): EP-3 (Action)
// and EP-4 (approval gate). Every write a principal makes is an Action run by the Runner: Plan, gate,
// authorise, Apply with a step token, Verify, and an audit event for the outcome, including a failure
// and a denial. The state machines are in transitions.go.
package operation

import (
	"context"
	"errors"

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
	ID            ActionID
	Version       int
	Permission    authz.Permission // checked at Plan and again at Apply
	Input         SchemaRef
	Target        TargetKind
	Reversibility Reversibility // worst case
	AuditKind     audit.Kind    // the step event kind, declared by the same owner
	StepUp        bool          // submit needs a fresh MFA (TM-D16 §7.4)
	SecretInput   bool          // the input carries a secret (rule 9)
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
}

// Outcome is what Apply did, as the Action read it back.
type Outcome struct {
	AlreadyApplied bool
	Payload        []byte
}

// Verdict is the result of Verify.
type Verdict struct {
	OK     bool
	Reason string // machine reason code when !OK
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
)

// PlanContext is what Plan reads through: the store (read only) and live facts on the pins.
type PlanContext struct {
	Tx    store.Tx // the runner opens it READ ONLY; Plan has no way to commit or roll it back
	Facts LiveFacts
	Pins  authority.Pins
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

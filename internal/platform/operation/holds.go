package operation

import (
	"context"
	"errors"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
)

// HoldReason is why the kernel holds an operation for approval (rule 8). Kernel holds come first and
// cannot be skipped; the registered gate only chooses how the approval is collected.
type HoldReason string

// Hold reasons. HoldGate is a hold requested by the registered gate itself.
const (
	HoldNone           HoldReason = ""
	HoldBlastRadius    HoldReason = "blast_radius"
	HoldIrreversible   HoldReason = "irreversible"
	HoldStepUp         HoldReason = "step_up"
	HoldUndoNeededAppr HoldReason = "undo_needed_approval"
	HoldGate           HoldReason = "gate"
)

// PermApprove is the permission the kernel's single approval requires over every item (rule 8).
const PermApprove authz.Permission = "operation.approve"

// Origins of an operation (DM-41).
const (
	OriginConsole    = "console"
	OriginAPI        = "api"
	OriginCSV        = "csv"
	OriginWorkflow   = "workflow"
	OriginAutomation = "automation"
	OriginReport     = "report_results"
	OriginUndo       = "undo"
	OriginMigration  = "migration"
)

var validOrigins = map[string]bool{OriginConsole: true, OriginAPI: true, OriginCSV: true, OriginWorkflow: true,
	OriginAutomation: true, OriginReport: true, OriginUndo: true, OriginMigration: true}

// Settings are the tenant settings the kernel's hold rules read.
type Settings interface {
	// ApprovalForIrreversible reports the tenant setting "approval for irreversible changes".
	ApprovalForIrreversible(ctx context.Context) (bool, error)
}

// Holder decides the kernel holds of a plan. It returns HoldNone to let the gate decide alone, and
// ErrNoApprovalPath when a hold is needed and nothing could ever approve it.
type holdInput struct {
	d            Descriptor
	req          Request
	items        int
	worst        Reversibility
	irrevSetting bool
}

// ErrNoApprovalPath is returned when an operation must be held but no approval path exists.
var ErrNoApprovalPath = errors.New("operation: held, and no approval path exists")

// kernelHold applies rule 8's kernel hold rules in order. The first that matches names the hold.
func kernelHold(in holdInput) HoldReason {
	chain := in.req.Actor
	switch {
	case in.req.Origin == OriginUndo && in.req.UndoNeededApproval:
		return HoldUndoNeededAppr
	case in.d.StepUp && !in.req.FreshStepUp && !canStepUp(chain):
		return HoldStepUp
	case in.req.MaxObjects > 0 && in.items > in.req.MaxObjects && in.req.Origin == OriginAutomation:
		return HoldBlastRadius
	case in.worst == Irreversible && in.irrevSetting:
		return HoldIrreversible
	}
	return HoldNone
}

// canStepUp reports whether the initiator chain can complete a fresh MFA: an interactive human
// session can; an API token or an automation policy cannot.
func canStepUp(c authority.Chain) bool {
	if c.Requester.Kind != authority.Human {
		return false
	}
	for _, p := range c.Via {
		if p.Kind == authority.APIToken || p.Kind == authority.Automation {
			return false
		}
	}
	return true
}

// Approval is an approver's identity and session facts, supplied by the console's session layer and
// never by the request body.
type Approval struct {
	Principal authority.Principal
	// Interactive is true for an interactive human session. An API token or an automation policy
	// never approves, whatever its permissions.
	Interactive bool
	// FreshStepUp: the approver completed a fresh MFA (TM-D16).
	FreshStepUp bool
}

// Provenance answers the sock-puppet question of rule 8 (a) to (e): did a asked-about principal create
// the other's account, grant it operation.approve, bind its directory_ref, add it to its granting
// group, or set its password or sign-in binding, since the given time? The rule runs both ways; the
// kernel asks in both directions.
type Provenance interface {
	// Tied reports whether `actor` did any of (a) to (e) to `subject` since `since`, through activeDIQ.
	Tied(ctx context.Context, actor, subject authority.PrincipalID, since time.Time) (bool, error)
}

// Alerter raises a security alert to the tenant-owner accounts and the EP-9 sinks.
type Alerter interface {
	Alert(ctx context.Context, a Alert)
}

// Alert is one security alert. It carries identifiers and reason codes, never values.
type Alert struct {
	Severity  string // "high", "critical"
	Reason    string
	Operation string
	Principal authority.PrincipalID
}

// Errors of the approval path. None names a person's attributes.
var (
	ErrSelfApproval   = errors.New("operation: the approver is in the initiator chain")
	ErrNotHuman       = errors.New("operation: only an interactive human session approves")
	ErrStepUpRequired = errors.New("operation: approval needs a fresh step-up")
	ErrSockPuppet     = errors.New("operation: the approver is tied to the initiator")
	ErrStalePlanHash  = errors.New("operation: approval is for a different plan hash")
	ErrNotAwaiting    = errors.New("operation: operation is not awaiting approval")
	ErrNotApprover    = errors.New("operation: approver does not hold operation.approve over every item")
)

// sockPuppetWindow is how far back rule 8 (a) to (e) look.
const sockPuppetWindow = 30 * 24 * time.Hour

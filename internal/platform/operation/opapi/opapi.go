// Package opapi is the one HTTP helper every Action family mounts for its undo pair (ADR-0004 rule 14):
// POST <collection>/operations/{operationId}/undo and .../previews/undo. It is parameterised by the
// family prefix and its base permission, so no module clones the handler. It maps the kernel's
// Preview, Result and errors to the shared OperationPreview, OperationRef and problem-details types;
// the module's generated handler wraps the answers in its own Output types and adds the
// ActiveDIQ-Operation-Id header from the returned reference.
package opapi

import (
	"context"
	"errors"
	"regexp"
	"strings"

	"github.com/skenzeriq/activediq/internal/platform/apihost/apitypes"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// Caller derives, from the authenticated request, the tenant, the authority chain of the principal
// undoing (never taken from the body) and whether they completed a fresh MFA. A refusal is returned as a
// problem.
type Caller func(ctx context.Context) (t tenant.ID, chain authority.Chain, freshStepUp bool, err error)

// Family is one Action family's undo pair. Prefix is "reports.schedule" and the restore Action
// registered for it is Prefix + ".restore"; Base is the family's base permission, the route's floor.
type Family struct {
	Prefix string
	Base   authz.Permission
	Runner *operation.Runner
	Caller Caller
	// NewID returns the UUID of a new operation; the default is a random version 4 UUID.
	NewID func() (string, error)
}

// Undo undoes operation id. A held undo answers a reference in state awaiting_approval (the module
// sends 202); a finished one answers succeeded (200). Its ID is the new undo operation, with Undoes = id.
func (f Family) Undo(ctx context.Context, id apitypes.UUID, body apitypes.OperationUndoRequest) (apitypes.OperationRef, error) {
	ur, err := f.request(ctx, id)
	if err != nil {
		return apitypes.OperationRef{}, err
	}
	ur.Confirmed = ConfirmedOf(body.Confirmations)
	res, err := f.Runner.UndoStore(ctx, ur)
	if err != nil {
		return apitypes.OperationRef{}, Problem(err)
	}
	return RefOf(res)
}

// PreviewUndo previews the undo of operation id. It writes nothing.
func (f Family) PreviewUndo(ctx context.Context, id apitypes.UUID) (apitypes.OperationPreview, error) {
	ur, err := f.request(ctx, id)
	if err != nil {
		return apitypes.OperationPreview{}, err
	}
	p, err := f.Runner.PreviewUndo(ctx, ur)
	if err != nil {
		return apitypes.OperationPreview{}, Problem(err)
	}
	return PreviewOf(p), nil
}

func (f Family) request(ctx context.Context, id apitypes.UUID) (operation.UndoRequest, error) {
	if f.Runner == nil || f.Caller == nil || f.Prefix == "" || f.Base == "" {
		return operation.UndoRequest{}, apitypes.Internal("")
	}
	t, chain, fresh, err := f.Caller(ctx)
	if err != nil {
		return operation.UndoRequest{}, err
	}
	newID := f.NewID
	if newID == nil {
		newID = randomUUID
	}
	nid, err := newID()
	if err != nil {
		return operation.UndoRequest{}, apitypes.Internal("")
	}
	return operation.UndoRequest{Tenant: t, Actor: chain, Family: f.Prefix, Base: f.Base, Original: step.OperationID(id.String()),
		Operation: step.OperationID(nid), FreshStepUp: fresh}, nil
}

// ConfirmedOf maps the request's confirmations to the kernel's.
func ConfirmedOf(cs []apitypes.OperationConfirmation) []operation.Confirmation {
	out := make([]operation.Confirmation, len(cs))
	for i, c := range cs {
		out[i] = operation.Confirmation{Kind: string(c.Kind), Items: c.Items}
	}
	return out
}

// RefOf maps a finished or held Result to the shared OperationRef.
func RefOf(res operation.Result) (apitypes.OperationRef, error) {
	id, err := apitypes.ParseUUID(string(res.Operation))
	if err != nil {
		return apitypes.OperationRef{}, apitypes.Internal("")
	}
	ref := apitypes.OperationRef{ID: id, Action: string(res.Action), State: apitypes.OperationStateValue(res.State),
		HoldReason: holdOf(res.Hold)}
	if res.Undoes != "" {
		u, err := apitypes.ParseUUID(res.Undoes)
		if err != nil {
			return apitypes.OperationRef{}, apitypes.Internal("")
		}
		ref.Undoes = &u
	}
	return ref, nil
}

func holdOf(h operation.HoldReason) apitypes.OperationHoldReasonValue {
	if h == operation.HoldNone {
		return apitypes.OperationHoldReasonValueNone
	}
	return apitypes.OperationHoldReasonValue(h)
}

var resourcePattern = regexp.MustCompile(`^[a-z][a-z0-9]*(\.[a-z][a-z0-9_]*)+$`)

// TargetOf maps a Store target. The resource is the object class when it is a dotted resource name
// ("reports.schedule"), otherwise "store." plus the class.
func TargetOf(t authority.TargetRef) apitypes.OperationTarget {
	res := t.Class
	if !resourcePattern.MatchString(res) {
		res = "store." + strings.Map(func(r rune) rune {
			if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' {
				return r
			}
			return '_'
		}, strings.ToLower(res))
		if !resourcePattern.MatchString(res) {
			res = "store.object"
		}
	}
	var id *string
	if t.GUID != "" {
		g := t.GUID
		id = &g
	}
	return apitypes.OperationTarget{Kind: "store", Store: &apitypes.OperationTargetStore{Kind: "store", Resource: res, ID: id}}
}

func valueOf(vals []string, secret bool) apitypes.OperationValue {
	switch {
	case secret:
		return apitypes.OperationValue{Kind: "redacted", Redacted: &apitypes.OperationValueRedacted{Kind: "redacted"}}
	case len(vals) == 0:
		return apitypes.OperationValue{Kind: "absent", Absent: &apitypes.OperationValueAbsent{Kind: "absent"}}
	case len(vals) == 1:
		return apitypes.OperationValue{Kind: "text", Text: &apitypes.OperationValueText{Kind: "text", Value: vals[0]}}
	}
	return apitypes.OperationValue{Kind: "textList", TextList: &apitypes.OperationValueTextList{Kind: "textList", Values: vals}}
}

// PreviewOf maps the kernel's Preview to the shared OperationPreview. Preview twins of the family's
// writes use it too.
func PreviewOf(p operation.Preview) apitypes.OperationPreview {
	out := apitypes.OperationPreview{
		Action: string(p.Action), ActionVersion: int64(p.Version), PlanHash: p.PlanHash, Outcome: apitypes.OperationPreviewOutcome(p.Outcome),
		HoldReason: holdOf(p.Hold), StepUpRequired: p.StepUpRequired, Reversibility: apitypes.OperationReversibilityValue(p.Reversibility),
		Steps: make([]apitypes.OperationStepPreview, 0, len(p.Steps)), Blocked: make([]apitypes.OperationBlocked, 0, len(p.Blocked)),
		RequiredConfirmations: make([]apitypes.OperationRequiredConfirmation, 0, len(p.Confirmations)),
		Undo:                  apitypes.OperationUndoPlan{Possible: p.Undo.Possible, Reversibility: apitypes.OperationReversibilityValue(p.Undo.Reversibility)},
	}
	if out.Undo.Reversibility == "" {
		out.Undo.Reversibility = apitypes.OperationReversibilityValue(p.Reversibility)
	}
	for _, sp := range p.Steps {
		sv := apitypes.OperationStepPreview{Target: TargetOf(sp.Target), Reversibility: apitypes.OperationReversibilityValue(sp.Reversibility),
			Changes: make([]apitypes.OperationChange, 0, len(sp.Diff))}
		if sp.ReversibilityReason != "" {
			r := sp.ReversibilityReason
			sv.ReversibilityReason = &r
		}
		for _, c := range sp.Diff {
			sv.Changes = append(sv.Changes, apitypes.OperationChange{Field: c.Attribute, Before: valueOf(c.Before, c.Secret), After: valueOf(c.After, c.Secret)})
		}
		out.Steps = append(out.Steps, sv)
	}
	for _, b := range p.Blocked {
		out.Blocked = append(out.Blocked, apitypes.OperationBlocked{Target: TargetOf(b.Target), Code: b.Code})
	}
	for _, c := range p.Confirmations {
		out.RequiredConfirmations = append(out.RequiredConfirmations, apitypes.OperationRequiredConfirmation{
			Kind: apitypes.OperationConfirmationKindValue(c.Kind), Items: c.Items})
	}
	return out
}

// Problem maps a kernel error to the API's problem details, with no secret or driver text. Anything
// not listed is a 500 with no detail.
func Problem(err error) error {
	var nu *operation.NotUndoableError
	var pr *operation.PlanRefusal
	switch {
	case err == nil:
		return nil
	case errors.Is(err, operation.ErrNotFound) || errors.Is(err, operation.ErrUnknown):
		return apitypes.NotFound("")
	case errors.As(err, &nu):
		p := apitypes.OperationNotUndoable(undoText(nu.Code))
		code := nu.Code
		detail := undoText(nu.Code)
		if errors.As(err, &pr) && nu.Code == operation.UndoPlanRefused {
			detail = "The undo is refused: " + pr.Code
		}
		p.Errors = []apitypes.ProblemError{{Code: code, Detail: detail, In: apitypes.ProblemErrorInBody, Pointer: ""}}
		return p
	case errors.Is(err, operation.ErrStepUpRequired):
		return apitypes.StepUpRequired("")
	case errors.Is(err, operation.ErrConfirmation):
		return apitypes.Validation("The confirmations differ from the ones the preview listed")
	case errors.Is(err, operation.ErrDenied):
		return apitypes.Forbidden("")
	case errors.Is(err, operation.ErrInvalid):
		return apitypes.Internal("")
	}
	return apitypes.Internal("")
}

func undoText(code string) string {
	switch code {
	case operation.UndoIrreversible:
		return "The change cannot be reversed."
	case operation.UndoAlreadyUndone:
		return "The operation was already undone."
	case operation.UndoSuperseded:
		return "The object changed after this operation. Undo the later change first."
	case operation.UndoNotFinished:
		return "The operation has not finished."
	}
	return "No inverse can be applied."
}

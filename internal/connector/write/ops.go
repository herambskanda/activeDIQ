package write

import (
	"context"
	"fmt"

	"github.com/skenzeriq/activediq/internal/connector/tier0"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// Authorised is the token the guard hands to an operation body after every step of §8.1 up to the
// write has passed. Its only constructor is unexported, so an operation cannot be called without
// going through the guard; an operation that receives the zero value must refuse (Valid is false).
type Authorised struct{ p *pass }

type pass struct {
	evaluated []guid.GUID
	dc        guid.GUID // DSA GUID of the DC the guard's live re-read ran on (AD); zero otherwise
}

// Valid reports whether the guard issued this token.
func (a Authorised) Valid() bool { return a.p != nil }

// DC is the DSA GUID of the DC the guard re-read on at step 7; zero for a token not bound to a DC.
func (a Authorised) DC() guid.GUID {
	if a.p == nil {
		return guid.GUID{}
	}
	return a.p.dc
}

// Evaluated are the touched objects the guard classified, target first.
func (a Authorised) Evaluated() []guid.GUID {
	if a.p == nil {
		return nil
	}
	return append([]guid.GUID(nil), a.p.evaluated...)
}

// WriteOp is one concrete write kind. A kind ticket adds a row to operations together with the
// WriteChange arm, the touched-set rule and the conformance cases (contract §8.1).
type WriteOp struct {
	// Touched returns every object the typed change writes or whose protection it changes,
	// including the target. It is derived from the typed change, never from a list the server sent.
	Touched func(target guid.GUID, change *connectorv1.WriteChange) ([]guid.GUID, error)
	// PropertyWrite declares what the typed change does to directory properties (contract §8.9),
	// derived from the typed change and never from a list the server sent. It is mandatory: a kind
	// registered without it fails validateOps (the CC-WRITE-22 build-time check) and New. The guard
	// calls it at step 4, before every other step that depends on the kind.
	PropertyWrite func(change *connectorv1.WriteChange) (tier0.PropertyWrite, error)
	// Digest recomputes the plan digest from the typed fields with the operation/step function.
	Digest func(req *connectorv1.ApplyRequest) ([]byte, error)
	Plan   func(ctx context.Context, a Authorised, req *connectorv1.PlanRequest) (*connectorv1.PlanResponse, error)
	Apply  func(ctx context.Context, a Authorised, req *connectorv1.ApplyRequest) (*connectorv1.ApplyResponse, error)
}

// operations is the operation table. It is empty in v1.1: WriteKind has no kind, so every call that
// passes the guard ends in CAPABILITY_UNSUPPORTED and no write path exists. The only place a
// directory or Graph write may be called from is a WriteOp body reachable from this table; the
// fitness test in fitness_test.go enforces that.
var operations = map[connectorv1.WriteKind]WriteOp{}

// validateOps is the build-time check of contract §8.9 / CC-WRITE-22: every registered write kind
// declares its PropertyWrite and its other mandatory functions. It runs in New, so a handler cannot
// be built over a table with a gap, and in the unit tests over the real table on every merge.
func validateOps(ops map[connectorv1.WriteKind]WriteOp) error {
	for k, op := range ops {
		switch {
		case op.PropertyWrite == nil:
			return fmt.Errorf("write: kind %s is registered without a PropertyWrite (contract §8.9)", k)
		case op.Touched == nil || op.Digest == nil || op.Plan == nil || op.Apply == nil:
			return fmt.Errorf("write: kind %s is registered with a missing function", k)
		}
	}
	return nil
}

// Capabilities reports the write group's rows for Describe (contract §4, §8.1): PLAN and APPLY are
// UNSUPPORTED while the operation table is empty, whatever the handler's presence.
func Capabilities() []*connectorv1.OperationSupport {
	state, reason := connectorv1.SupportState_SUPPORT_STATE_SUPPORTED, ""
	if len(operations) == 0 {
		state, reason = connectorv1.SupportState_SUPPORT_STATE_UNSUPPORTED, "no write kind is defined yet"
	}
	return []*connectorv1.OperationSupport{
		{Operation: connectorv1.Operation_OPERATION_PLAN, State: state, Reason: reason},
		{Operation: connectorv1.Operation_OPERATION_APPLY, State: state, Reason: reason},
	}
}

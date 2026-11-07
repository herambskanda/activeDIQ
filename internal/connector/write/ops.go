package write

import (
	"context"
	"fmt"
	"strings"

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
	// props are the attribute keys the kind's PropertyWrite declared at step 4 (the ones the §8.9 guard
	// and the step-7 Tier-0 checks were run for). Only the DACL kind declares nTSecurityDescriptor.
	props []string
	// dir is the directory the object kinds act on; nil when the provider has none.
	dir ObjectDirectory
}

// DeclaresProperty reports whether the write kind this token was issued for declared the attribute in
// its PropertyWrite. The token does not carry the WriteKind itself; ApplyDACL uses this to refuse a
// token issued for another kind, whose declaration would not have covered nTSecurityDescriptor.
func (a Authorised) DeclaresProperty(name string) bool {
	if a.p == nil {
		return false
	}
	for _, k := range a.p.props {
		if strings.EqualFold(k, name) {
			return true
		}
	}
	return false
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
	// TouchedLive adds the objects only a live read can name (the old parent of a move). It runs at
	// step 5, after Touched, against the provider's directory; an error refuses as TouchedSet.
	TouchedLive func(ctx context.Context, d ObjectDirectory, target guid.GUID, change *connectorv1.WriteChange) ([]guid.GUID, error)
	// DeletedTarget marks a kind whose target is a deleted object: step 7 classifies it with the
	// provider's DeletedClassifier instead of the live classifier.
	DeletedTarget bool
	// Digest recomputes the plan digest from the typed fields with the operation/step function.
	Digest func(req *connectorv1.ApplyRequest) ([]byte, error)
	Plan   func(ctx context.Context, a Authorised, req *connectorv1.PlanRequest) (*connectorv1.PlanResponse, error)
	Apply  func(ctx context.Context, a Authorised, req *connectorv1.ApplyRequest) (*connectorv1.ApplyResponse, error)
}

// operations is the operation table. The only place a directory or Graph write may be called from
// is a WriteOp body reachable from this table; the fitness test in fitness_test.go enforces that.
// Kinds 4 to 6 (object move, rename, restore) are wired (T-1624); the others answer
// CAPABILITY_UNSUPPORTED until their build tickets land.
var operations = objectOps()

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

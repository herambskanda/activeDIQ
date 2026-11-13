package write

import (
	"context"
	"fmt"
	"sort"
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
	// dir runs object writes on the session the guard evaluated on; nil when the provider has none.
	dir ObjectDirectory
	// dcID is the bound DC's identity (AD), for the observations a body returns.
	dcID *connectorv1.DcIdentity
	// recheck repeats the §8.9 property guard for a declaration only the body can derive (the live class).
	// It returns nil to allow, else the refusal (with its audit reason) for the target.
	recheck func(ctx context.Context, w tier0.PropertyWrite, target guid.GUID, step string) *Refusal
	// prov is the provider the guard classified against; a body that needs the directory session asks it.
	prov Provider
	// objs is the directory the object move, rename and restore kinds act on; nil when the provider has none.
	objs StructureDirectory
	// regrants are the group memberships a restore re-grants (step 7 of kind 6), for Plan to list.
	regrants []Regrant
}

func (a Authorised) dir() ObjectDirectory {
	if a.p == nil {
		return nil
	}
	return a.p.dir
}

func (a Authorised) dcID() *connectorv1.DcIdentity {
	if a.p == nil {
		return nil
	}
	return a.p.dcID
}

// checkProperty is nil to allow, else the refusal to return. A token with no checker refuses, as a
// guard that is unavailable does.
func (a Authorised) checkProperty(ctx context.Context, w tier0.PropertyWrite, target guid.GUID, step string) *Refusal {
	if a.p == nil || a.p.recheck == nil {
		return propertyRefusal(w, target, step, reasonGuardUnavailable, stLive)
	}
	return a.p.recheck(ctx, w, target, step)
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
	// AlsoDevice makes the step-4 guard check the PropertyWrite declaration a second time with Kind
	// WriteDevice (refused if either refuses). A kind whose target class is only known live (move,
	// rename and restore take users, groups, computers and OUs, and an OU move changes the DN of
	// every computer below it) sets it, because the closure's dynamic rules differ per kind.
	AlsoDevice bool
	// TouchedLive adds the objects only a live read can name (the old parent of a move). It runs at
	// step 5, after Touched, against the provider's directory; an error refuses as TouchedSet.
	TouchedLive func(ctx context.Context, d StructureDirectory, target guid.GUID, change *connectorv1.WriteChange) ([]guid.GUID, error)
	// DeletedTarget marks a kind whose target is a deleted object: step 7 classifies it with the
	// provider's DeletedClassifier instead of the live classifier.
	DeletedTarget bool
	// AlsoDeclares lists further declarations for the same change, each checked by the same guard
	// and each of which must pass (a directory attribute that feeds rule properties of two object
	// classes). Optional.
	AlsoDeclares func(change *connectorv1.WriteChange) ([]tier0.PropertyWrite, error)
	// Digest recomputes the plan digest from the typed fields with the operation/step function.
	Digest func(req *connectorv1.ApplyRequest) ([]byte, error)
	// Vet checks what needs the schema but no directory call: attribute names, limits, the deny-list.
	// It runs at step 4 before the property guard, so a denied attribute is ATTRIBUTE_NOT_ALLOWED.
	Vet func(d ObjectDirectory, change *connectorv1.WriteChange) *Refusal
	// RemovesTarget: the write deletes the target, so step 9 has nothing to re-read for it.
	RemovesTarget bool
	// TargetGone: step 7 cannot classify the target because it is already deleted; true only when
	// the object is shown to be deleted. A retry of the delete is then answered ALREADY_APPLIED.
	TargetGone func(ctx context.Context, d ObjectDirectory, id guid.GUID) bool
	// Arm reports whether the change is the arm of this kind; nil means no check. A mismatch is
	// INVALID_ARGUMENT WriteChangeArmMismatch at step 4, before any live directory read (CC-WK-29).
	Arm func(*connectorv1.WriteChange) bool
	// WantsSecret: the kind's Apply carries ApplyRequest.secret_input, and no other kind's does. Presence
	// that differs is SecretInputMismatch at step 4 (contract §8.10.5).
	WantsSecret bool
	Plan        func(ctx context.Context, a Authorised, req *connectorv1.PlanRequest) (*connectorv1.PlanResponse, error)
	Apply       func(ctx context.Context, a Authorised, req *connectorv1.ApplyRequest) (*connectorv1.ApplyResponse, error)
}

// operations is the operation table. A kind ticket registers its row (account.go: T-1583, the four
// account kinds); a WriteKind with no row ends in CAPABILITY_UNSUPPORTED. Kinds 1 to 3 are T-1623 and
// kinds 4 to 6 (object move, rename, restore) are T-1624. The only place a directory or Graph write may
// be called from is a WriteOp body reachable from this table; the fitness test in fitness_test.go
// enforces that.
var operations = func() map[connectorv1.WriteKind]WriteOp {
	m := map[connectorv1.WriteKind]WriteOp{
		connectorv1.WriteKind_WRITE_KIND_OBJECT_CREATE: objectCreateOp,
		connectorv1.WriteKind_WRITE_KIND_OBJECT_UPDATE: objectUpdateOp,
		connectorv1.WriteKind_WRITE_KIND_OBJECT_DELETE: objectDeleteOp,
	}
	for k, op := range objectOps() {
		m[k] = op
	}
	return m
}()

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

// Capabilities reports the write group's rows for Describe (contract §4, §8.1). PLAN and APPLY are
// SUPPORTED once the operation table has a row; OperationSupport has no per-kind field, so the
// wired kinds are named in Reason (sorted). A kind with no row answers CAPABILITY_UNSUPPORTED on
// the call.
func Capabilities() []*connectorv1.OperationSupport {
	state, reason := connectorv1.SupportState_SUPPORT_STATE_UNSUPPORTED, "no write kind is defined yet"
	if len(operations) > 0 {
		names := make([]string, 0, len(operations))
		for k := range operations {
			names = append(names, k.String())
		}
		sort.Strings(names)
		state, reason = connectorv1.SupportState_SUPPORT_STATE_SUPPORTED, "kinds: "+strings.Join(names, ",")
	}
	return []*connectorv1.OperationSupport{
		{Operation: connectorv1.Operation_OPERATION_PLAN, State: state, Reason: reason},
		{Operation: connectorv1.Operation_OPERATION_APPLY, State: state, Reason: reason},
	}
}

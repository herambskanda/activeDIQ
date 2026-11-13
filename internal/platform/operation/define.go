package operation

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
)

// Typed is the typed shape of an Action: modules write these functions and never handle untyped
// input. In, P (the step payload) and Out must be encodable as JSON, which the canonical form of the
// plan hash is built over.
type Typed[In, P, Out any] struct {
	Descriptor Descriptor
	Plan       func(ctx context.Context, pc PlanContext, in In) ([]TypedStep[P], error)
	Apply      func(ctx context.Context, s step.Step, p TypedStep[P]) (Out, error)
	Verify     func(ctx context.Context, s step.Step, p TypedStep[P], o Out) (Verdict, error)
	Inverse    func(p TypedStep[P], o Out) (In, error)
	// Observe reads the target back on the pinned DC for reconciliation (rule 6). A Directory Action
	// must provide it; a Store Action must not.
	Observe func(ctx context.Context, pins authority.Pins, p TypedStep[P], claimedAt time.Time) (Observation, error)
	// Tier0 returns the connector's step-9 report (ApplyResponse.tier0_after_write) from the typed
	// outcome. A Directory Action fills it from client.Result.Tier0AfterWrite.
	Tier0 func(o Out) []step.Tier0Finding
	// Touched returns the objects besides the target that the step's typed change touches; the
	// server's Tier-0 re-read covers each of them (ADR-0005 rule 7).
	Touched func(p TypedStep[P]) []authority.TargetRef
	// AlsoAuthorize returns further objects the pipeline must authorise, live, for the same permission
	// at Plan and again immediately before Apply (ADR-0005 rule 7), besides the step's target: a
	// move's destination parent. Each is refused or allowed exactly like the target, tier0 included.
	AlsoAuthorize func(p TypedStep[P]) []authority.TargetRef
}

// TypedStep is a StepPlan with a typed payload.
type TypedStep[P any] struct {
	Plan    StepPlan
	Payload P
}

type defined[In, P, Out any] struct{ t Typed[In, P, Out] }

// Define turns typed functions into an Action. It refuses a definition with a missing function.
func Define[In, P, Out any](t Typed[In, P, Out]) (Action, error) {
	if t.Plan == nil || t.Apply == nil || t.Verify == nil || t.Inverse == nil {
		return nil, fmt.Errorf("%w: %q lacks Plan, Apply, Verify or Inverse", ErrInvalid, t.Descriptor.ID)
	}
	if err := t.Descriptor.validate(); err != nil {
		return nil, err
	}
	if t.Descriptor.Target != TargetStore && t.Observe == nil {
		return nil, fmt.Errorf("%w: directory action %q needs Observe for reconciliation", ErrInvalid, t.Descriptor.ID)
	}
	if t.Observe != nil {
		return definedObserver[In, P, Out]{defined[In, P, Out]{t}}, nil
	}
	return defined[In, P, Out]{t}, nil
}

// definedObserver is a defined Action that also implements Observer.
type definedObserver[In, P, Out any] struct{ defined[In, P, Out] }

func (d definedObserver[In, P, Out]) Observe(ctx context.Context, pins authority.Pins, p StepPlan, claimedAt time.Time) (Observation, error) {
	ts, err := d.unpack(p)
	if err != nil {
		return "", err
	}
	return d.t.Observe(ctx, pins, ts, claimedAt)
}

func (d defined[In, P, Out]) Describe() Descriptor { return d.t.Descriptor }

func (d defined[In, P, Out]) Plan(ctx context.Context, pc PlanContext, in Input) ([]StepPlan, error) {
	var typed In
	if err := json.Unmarshal(in, &typed, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("%w: input does not decode", ErrInvalid)
	}
	steps, err := d.t.Plan(ctx, pc, typed)
	if err != nil {
		return nil, err
	}
	out := make([]StepPlan, 0, len(steps))
	for _, s := range steps {
		b, err := json.Marshal(s.Payload, json.Deterministic(true))
		if err != nil {
			return nil, fmt.Errorf("%w: payload does not encode", ErrInvalid)
		}
		p := s.Plan
		p.Payload = b
		out = append(out, p)
	}
	return out, nil
}

func (d defined[In, P, Out]) unpack(p StepPlan) (TypedStep[P], error) {
	var payload P
	if err := json.Unmarshal(p.Payload, &payload); err != nil {
		return TypedStep[P]{}, fmt.Errorf("%w: payload does not decode", ErrInvalid)
	}
	return TypedStep[P]{Plan: p, Payload: payload}, nil
}

func (d defined[In, P, Out]) Apply(ctx context.Context, s step.Step, p StepPlan) (Outcome, error) {
	ts, err := d.unpack(p)
	if err != nil {
		return Outcome{}, err
	}
	out, err := d.t.Apply(ctx, s, ts)
	if err != nil {
		return Outcome{}, err
	}
	b, err := json.Marshal(out, json.Deterministic(true))
	if err != nil {
		return Outcome{}, fmt.Errorf("%w: outcome does not encode", ErrInvalid)
	}
	o := Outcome{Payload: b}
	if d.t.Tier0 != nil {
		o.Tier0 = d.t.Tier0(out)
	}
	return o, nil
}

// Touched implements Toucher.
func (d defined[In, P, Out]) Touched(p StepPlan) []authority.TargetRef {
	if d.t.Touched == nil {
		return nil
	}
	ts, err := d.unpack(p)
	if err != nil {
		return nil
	}
	return d.t.Touched(ts)
}

// AlsoAuthorize implements AlsoAuthorizer.
func (d defined[In, P, Out]) AlsoAuthorize(p StepPlan) []authority.TargetRef {
	if d.t.AlsoAuthorize == nil {
		return nil
	}
	ts, err := d.unpack(p)
	if err != nil {
		return nil
	}
	return d.t.AlsoAuthorize(ts)
}

func (d defined[In, P, Out]) Verify(ctx context.Context, s step.Step, p StepPlan, o Outcome) (Verdict, error) {
	ts, err := d.unpack(p)
	if err != nil {
		return Verdict{}, err
	}
	out, err := decodeOutcome[Out](o)
	if err != nil {
		return Verdict{}, err
	}
	return d.t.Verify(ctx, s, ts, out)
}

func (d defined[In, P, Out]) Inverse(p StepPlan, o Outcome) (Input, error) {
	ts, err := d.unpack(p)
	if err != nil {
		return nil, err
	}
	out, err := decodeOutcome[Out](o)
	if err != nil {
		return nil, err
	}
	in, err := d.t.Inverse(ts, out)
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(in, json.Deterministic(true))
	if err != nil {
		return nil, fmt.Errorf("%w: inverse does not encode", ErrInvalid)
	}
	return b, nil
}

// decodeOutcome decodes an Apply outcome. A step recovered by reconciliation has no payload, because the
// write's reply was lost with the worker; the Action then gets the zero Out and must verify against the
// directory, not against the reply.
func decodeOutcome[Out any](o Outcome) (Out, error) {
	var out Out
	if len(o.Payload) == 0 {
		return out, nil
	}
	if err := json.Unmarshal(o.Payload, &out); err != nil {
		return out, fmt.Errorf("%w: outcome does not decode", ErrInvalid)
	}
	return out, nil
}

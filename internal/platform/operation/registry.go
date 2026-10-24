package operation

import (
	"fmt"
	"sort"
	"strings"
)

// validate checks the Descriptor fields every Action must carry (O5 "lacks a Descriptor field").
func (d Descriptor) validate() error {
	switch {
	case strings.Count(string(d.ID), ".") < 2 || strings.ContainsAny(string(d.ID), " \t\n/"):
		return fmt.Errorf("%w: id %q is not <owner>.<noun>.<verb>", ErrInvalid, d.ID)
	case d.Version < 1:
		return fmt.Errorf("%w: %q has no version", ErrInvalid, d.ID)
	case d.Permission == "":
		return fmt.Errorf("%w: %q has no permission", ErrInvalid, d.ID)
	case d.Input == "":
		return fmt.Errorf("%w: %q has no input schema", ErrInvalid, d.ID)
	case d.AuditKind == "":
		return fmt.Errorf("%w: %q has no audit kind", ErrInvalid, d.ID)
	case d.Reversibility.rank() < 0:
		return fmt.Errorf("%w: %q has no reversibility class", ErrInvalid, d.ID)
	}
	switch d.Target {
	case TargetAD, TargetEntra, TargetStore:
		return nil
	}
	return fmt.Errorf("%w: %q has no target kind", ErrInvalid, d.ID)
}

// Registry is the set of registered Actions, built once at boot from module.Contributions.Actions()
// and the kernel packages' actions subpackages. It is immutable after NewRegistry.
type Registry struct {
	byID map[ActionID]Action
	ids  []ActionID
}

// NewRegistry validates every Descriptor and refuses a duplicate ID.
func NewRegistry(actions ...Action) (*Registry, error) {
	r := &Registry{byID: make(map[ActionID]Action, len(actions))}
	for _, a := range actions {
		if a == nil {
			return nil, fmt.Errorf("%w: nil action", ErrInvalid)
		}
		d := a.Describe()
		if err := d.validate(); err != nil {
			return nil, err
		}
		if _, ok := a.(Observer); !ok && d.Target != TargetStore {
			// Reconciliation needs to read the target back (rule 6); a Directory Action without it
			// would leave a crashed step applying.
			return nil, fmt.Errorf("%w: directory action %q does not implement Observer", ErrInvalid, d.ID)
		}
		if _, dup := r.byID[d.ID]; dup {
			return nil, fmt.Errorf("%w: action %q registered twice", ErrInvalid, d.ID)
		}
		r.byID[d.ID] = a
		r.ids = append(r.ids, d.ID)
	}
	sort.Slice(r.ids, func(i, j int) bool { return r.ids[i] < r.ids[j] })
	return r, nil
}

// Lookup returns the Action with the given ID.
func (r *Registry) Lookup(id ActionID) (Action, bool) {
	if r == nil {
		return nil, false
	}
	a, ok := r.byID[id]
	return a, ok
}

// Catalogue lists the registered Descriptors in ID order, for search and the command palette
// (ADR-0003 F4). It is read-only: a Descriptor is a value.
func (r *Registry) Catalogue() []Descriptor {
	if r == nil {
		return nil
	}
	out := make([]Descriptor, 0, len(r.ids))
	for _, id := range r.ids {
		out = append(out, r.byID[id].Describe())
	}
	return out
}

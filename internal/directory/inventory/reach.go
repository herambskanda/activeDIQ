package inventory

import (
	"context"
	"errors"
	"strings"

	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/rbac"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// groupClass is the object class a membership change must target (TM-D18).
const groupClass = "group"

// Reach is the inventory implementation of rbac.GroupReach (TM-D18, ADR-0003 F6): the groups that gain
// a member when the target group does. It is the target itself plus every group the target is
// transitively a member of, over nesting and primary-group edges (the same walk as Groups.GroupsOf).
type Reach struct{ src GroupSource }

var _ rbac.GroupReach = (*Reach)(nil)

// NewReach binds the resolver to a group source (NewGroups for Postgres).
func NewReach(src GroupSource) *Reach { return &Reach{src: src} }

// ReachedFrom implements rbac.GroupReach. Complete is true only when the walk was read in full; a
// target that is not a well-formed group reference, or a walk beyond MaxGroups, is incomplete, which
// the guard denies. A read error is returned as an error (the guard fails closed on it too).
func (r *Reach) ReachedFrom(ctx context.Context, t tenant.ID, target authority.TargetRef) (authz.Groups, error) {
	if r == nil || r.src == nil {
		return authz.Groups{}, ErrNotConfigured
	}
	if t.IsZero() {
		return authz.Groups{}, ErrNoTenant
	}
	ref := Ref{ConnectionID(strings.ToLower(target.Connection)), GUID(strings.ToLower(target.GUID))}
	// The target must be the group itself: a member (user, computer) would reach the wrong groups.
	if target.Class != groupClass || !ref.Valid() {
		return authz.Groups{}, nil
	}
	// No active group row means the inventory does not know the group (unsynced, out of scope, another
	// tenant's GUID under RLS): its reach is unknown, not "itself only". Fail closed on the source
	// not being able to say so either.
	rows, ok := r.src.(GroupRows)
	if !ok {
		return authz.Groups{}, ErrNotConfigured
	}
	known, err := rows.GroupExists(ctx, t, ref.Connection, ref.Object)
	if err != nil {
		return authz.Groups{}, err
	}
	if !known {
		return authz.Groups{}, nil
	}
	outer, err := r.src.GroupsOf(ctx, t, ref.Connection, ref.Object)
	switch {
	case errors.Is(err, ErrTooMany):
		return authz.Groups{}, nil // a truncated closure would leave a group out
	case err != nil:
		return authz.Groups{}, err
	}
	out := authz.Groups{Complete: true, Groups: make([]authz.Group, 0, len(outer)+1)}
	// Path is left empty: GroupSource returns the closure, not the chain, and a two-element
	// [target, outer] would misstate a deeper chain in deny reasons and audit.
	out.Groups = append(out.Groups, authz.Group{Connection: string(ref.Connection), GUID: string(ref.Object)})
	for _, g := range outer {
		out.Groups = append(out.Groups, authz.Group{Connection: string(ref.Connection), GUID: string(g)})
	}
	return out, nil
}

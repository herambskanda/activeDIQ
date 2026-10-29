package rbac

import (
	"context"
	"errors"
	"fmt"

	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// GroupMembershipPermissions are the changes that widen who a directory group's grants reach
// (DM-36.I1, TM-D18): adding a member, nesting a group into another, and changing a user's
// primaryGroupID. Group subjects make membership an indirect grant, so an Action that performs one of
// these MUST declare one of these permissions and MUST set its authorisation Target to the group whose
// reach grows (for primaryGroupID: the group becoming primary). The guard keys on the permission.
var GroupMembershipPermissions = []authz.Permission{
	"objects.group.add_member",
	"objects.group.nest",
	"objects.user.set_primary_group",
}

// Reasons of the group-membership guard.
const (
	ReasonGroupEscalation authz.Reason = "group_membership_escalation"
	ReasonGroupIncomplete authz.Reason = "group_facts_incomplete"
	ReasonGroupNoResolver authz.Reason = "group_resolver_missing"
)

// GroupReach answers which groups gain a member when the target group does: the target itself and every
// group it is transitively a member of (nesting and primary-group edges), so a role granted to an outer
// group is seen. Implementations read committed directory state; Complete is true only when every edge
// was read in full. Inventory implements it (ADR-0003 F6).
type GroupReach interface {
	ReachedFrom(ctx context.Context, t tenant.ID, target authority.TargetRef) (authz.Groups, error)
}

// WithGroupGuard enables the group-membership guard. Without it every permission in
// GroupMembershipPermissions is refused (fail closed), like the backing guard.
func WithGroupGuard(r GroupReach) Option { return func(a *Authorizer) { a.reach = r } }

func isGroupMembershipPermission(p authz.Permission) bool {
	for _, x := range GroupMembershipPermissions {
		if x == p {
			return true
		}
	}
	return false
}

// checkGroupMembership refuses a membership change unless the actor holds every privilege of every
// pending or active assignment of every group the change reaches, over every scope it holds it
// (the DM-36.I1 test, applied to the indirect grant).
func (a *Authorizer) checkGroupMembership(ctx context.Context, tn tenant.ID, actor []Assignment, who string, t authority.TargetRef) error {
	if a.reach == nil {
		return denied(ReasonGroupNoResolver)
	}
	g, err := a.reach.ReachedFrom(ctx, tn, t)
	if err != nil {
		return fmt.Errorf("rbac: resolving reached groups: %w", err)
	}
	if !g.Complete {
		return denied(ReasonGroupIncomplete)
	}
	if len(g.Groups) == 0 {
		return nil
	}
	gas, err := a.src.SubjectAssignments(ctx, tn, Subjects{Groups: g.Groups}, a.now(), true)
	if err != nil {
		return fmt.Errorf("rbac: loading group assignments: %w", err)
	}
	for _, ga := range gas {
		if ga.Subject != SubjectGroup || len(ga.Permissions) == 0 {
			continue
		}
		if len(ga.Roots) == 0 {
			return denied(ReasonGroupIncomplete) // what it reaches is undefined: fail closed
		}
		switch err := a.holdsOver(ctx, tn, actor, who, ga.Permissions, ga.Roots); {
		case err == nil:
		case errors.Is(err, authz.ErrEscalation):
			return denied(ReasonGroupEscalation)
		default:
			return denied(ReasonGroupIncomplete)
		}
	}
	return nil
}

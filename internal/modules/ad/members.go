package ad

import (
	"context"
	"fmt"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/accountkind"
	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/directory/writechange"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
)

// Digest class labels of the member classes that accountkind does not name (writechange spells them the same).
const (
	classGroup   = "group"
	classContact = "contact"
)

// The group membership Actions (T-1586, connector contract §8.10.3 kinds 11 and 12). The authorisation
// Target of every step is the GROUP, never the member: rbac.GroupReach asks which groups gain a member
// when the target group does (TM-D18), and Descriptor.TargetClass "group" makes the kernel refuse a plan
// whose step is aimed anywhere else. Adding and nesting are two Actions because a Descriptor holds one
// permission: the connector reads the member's class live, so an Action holding add_member cannot nest.
const (
	AddMemberID    operation.ActionID = "ad.group.addMember"
	NestGroupID    operation.ActionID = "ad.group.nestGroup"
	RemoveMemberID operation.ActionID = "ad.group.removeMember"

	PermAddMember    authz.Permission = "objects.group.add_member"
	PermNestGroup    authz.Permission = "objects.group.nest"
	PermRemoveMember authz.Permission = "objects.group.remove_member"

	AuditMemberAdded   audit.Kind = "ad.group.member_added"
	AuditGroupNested   audit.Kind = "ad.group.nested"
	AuditMemberRemoved audit.Kind = "ad.group.member_removed"
)

// Reasons of the membership Actions.
const (
	ReasonNotAGroup      = "target_not_a_group"
	ReasonSelfMember     = "group_cannot_contain_itself"
	ReasonMemberClass    = "member_class_mismatch"
	ReasonMemberNotFound = "member_not_found"
	ReasonUseNest        = "member_is_a_group_use_nest"
)

// MemberInput names the group and the member to add or remove. MemberClass is what the caller believes
// the member is (user, computer, contact, group); Plan and the connector both read it live and refuse a
// mismatch.
type MemberInput struct {
	ConnectionID  string `json:"connectionId"`
	NamingContext string `json:"namingContext"`
	GroupGuid     string `json:"groupGuid"`
	MemberGuid    string `json:"memberGuid"`
	MemberClass   string `json:"memberClass"`
}

// MemberOutcome is what a membership Apply did.
type MemberOutcome struct {
	NoOp  bool                `json:"noOp,omitempty"`
	Tier0 []step.Tier0Finding `json:"tier0,omitempty"`
}

type memberPayload struct {
	Input  MemberInput `json:"input"`
	Direct bool        `json:"direct"` // the member was a direct member when planned
}

type memberSpec struct {
	id     operation.ActionID
	key    string
	perm   authz.Permission
	audit  audit.Kind
	add    bool
	groups bool // the Action is for a member that is a group
	// classes are the member classes this Action accepts.
	classes []string
}

var memberSpecs = []memberSpec{
	{id: AddMemberID, key: writechange.KeyGroupMemberAdd, perm: PermAddMember, audit: AuditMemberAdded, add: true,
		classes: []string{accountkind.ClassUser, accountkind.ClassComputer, classContact}},
	{id: NestGroupID, key: writechange.KeyGroupMemberAdd, perm: PermNestGroup, audit: AuditGroupNested, add: true, groups: true,
		classes: []string{classGroup}},
	{id: RemoveMemberID, key: writechange.KeyGroupMemberRemove, perm: PermRemoveMember, audit: AuditMemberRemoved,
		classes: []string{accountkind.ClassUser, accountkind.ClassComputer, classContact, classGroup}},
}

// MemberInverse pairs a membership Action with the one that undoes it. A Typed Action's Inverse returns an
// input of its own shape, so the undo layer applies the returned input to this Action.
func MemberInverse(id operation.ActionID, memberClass string) (operation.ActionID, bool) {
	switch id {
	case AddMemberID, NestGroupID:
		return RemoveMemberID, true
	case RemoveMemberID:
		if memberClass == classGroup {
			return NestGroupID, true
		}
		return AddMemberID, true
	}
	return "", false
}

// MemberActions builds the three membership Actions over the lifecycle ports.
func MemberActions(p LifecyclePorts) ([]operation.Action, error) {
	var out []operation.Action
	for _, sp := range memberSpecs {
		a, err := buildMember(p, sp)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}

func (in MemberInput) groupRef() authority.TargetRef {
	return accountkind.Target(in.ConnectionID, in.GroupGuid, classGroup, in.NamingContext)
}

func (in MemberInput) memberRef() authority.TargetRef {
	return authority.TargetRef{Connection: in.ConnectionID, GUID: in.MemberGuid, Class: in.MemberClass, NC: authority.NamingContextID(in.NamingContext)}
}

func (in MemberInput) validate(sp memberSpec) error {
	if in.ConnectionID == "" || !accountkind.Canonical(in.GroupGuid) || !accountkind.Canonical(in.MemberGuid) || !accountkind.Canonical(in.NamingContext) {
		return fmt.Errorf("%w: connectionId, groupGuid, memberGuid and namingContext are required (canonical lower-case UUID text)", operation.ErrInvalid)
	}
	for _, c := range sp.classes {
		if c == in.MemberClass {
			return nil
		}
	}
	if in.MemberClass == classGroup && sp.add && !sp.groups {
		return fmt.Errorf("%w: %s", operation.ErrInvalid, ReasonUseNest)
	}
	return fmt.Errorf("%w: %s", operation.ErrInvalid, ReasonMemberClass)
}

// attrs are the digest attributes of kinds 11 and 12 (writechange decodes them).
func (in MemberInput) attrs() []step.Attr {
	return []step.Attr{
		{Name: writechange.AttrMember, Values: []string{in.MemberGuid}},
		{Name: writechange.AttrMemberClass, Values: []string{in.MemberClass}},
	}
}

// memberDescriptors hold the identity and the one permission of each Action as constants, so the GM1
// fitness check can read them statically; buildMember completes the rest of the Descriptor.
var memberDescriptors = map[operation.ActionID]operation.Descriptor{
	AddMemberID:    operation.Descriptor{ID: AddMemberID, Permission: PermAddMember},
	NestGroupID:    operation.Descriptor{ID: NestGroupID, Permission: PermNestGroup},
	RemoveMemberID: operation.Descriptor{ID: RemoveMemberID, Permission: PermRemoveMember},
}

func buildMember(p LifecyclePorts, sp memberSpec) (operation.Action, error) {
	desc := memberDescriptors[sp.id]
	desc.Version, desc.Input, desc.AuditKind = 1, "#/components/schemas/AdGroupMember", sp.audit
	desc.Target, desc.TargetClass, desc.Reversibility = operation.TargetAD, classGroup, operation.Reversible
	return operation.Define(operation.Typed[MemberInput, memberPayload, MemberOutcome]{
		Descriptor: desc,
		Plan: func(ctx context.Context, pc operation.PlanContext, in MemberInput) ([]operation.TypedStep[memberPayload], error) {
			if err := in.validate(sp); err != nil {
				return nil, err
			}
			if p.Reader == nil {
				return nil, errUnavailable
			}
			if in.GroupGuid == in.MemberGuid {
				return nil, fmt.Errorf("%w: %s", operation.ErrInvalid, ReasonSelfMember)
			}
			g, err := p.Reader.Object(ctx, pc.Pins, in.groupRef(), nil, false)
			if err != nil {
				return nil, readError(err)
			}
			switch {
			case !g.Exists:
				return nil, fmt.Errorf("%w: %s", operation.ErrInvalid, ReasonNotFound)
			case g.Class != classGroup:
				return nil, fmt.Errorf("%w: %s", operation.ErrInvalid, ReasonNotAGroup)
			case g.Tier0:
				return nil, fmt.Errorf("%w: %s", operation.ErrDenied, ReasonTier0)
			}
			m, err := p.Reader.Object(ctx, pc.Pins, in.memberRef(), nil, false)
			if err != nil {
				return nil, readError(err)
			}
			switch {
			case !m.Exists:
				return nil, fmt.Errorf("%w: %s", operation.ErrInvalid, ReasonMemberNotFound)
			case m.Class != in.MemberClass:
				return nil, fmt.Errorf("%w: %s", operation.ErrInvalid, ReasonMemberClass)
			case m.Tier0:
				return nil, fmt.Errorf("%w: %s", operation.ErrDenied, ReasonTier0)
			}
			direct, err := p.Reader.DirectMember(ctx, pc.Pins, in.groupRef(), in.memberRef())
			if err != nil {
				return nil, readError(err)
			}
			if direct == sp.add {
				return nil, nil // already in the requested state: nothing to plan
			}
			diff := []operation.Change{{Attribute: writechange.AttrMember, After: []string{in.MemberGuid}}, {Attribute: writechange.AttrMemberClass, After: []string{in.MemberClass}}}
			verb, pre := "removes", "removing a member can widen access where the group is used in a deny entry; the directory does not say where it is used"
			if sp.add {
				verb, pre = "adds", "adding a member widens who the group's grants reach; the group and every group it is nested in are checked live against the actor's rights"
			}
			return []operation.TypedStep[memberPayload]{{
				Plan: operation.StepPlan{
					Target: in.groupRef(), Kind: sp.key, Diff: diff,
					Preconditions:       []string{verb + " one direct member of the group (the member is a " + in.MemberClass + ")", pre},
					Reversibility:       operation.Reversible,
					ReversibilityReason: "the opposite membership change undoes this one",
				},
				Payload: memberPayload{Input: in, Direct: direct},
			}}, nil
		},
		Apply: func(ctx context.Context, s step.Step, tp operation.TypedStep[memberPayload]) (MemberOutcome, error) {
			if p.Writer == nil {
				return MemberOutcome{}, errUnavailable
			}
			in := tp.Payload.Input
			res, err := p.Writer.Write(ctx, s, client.WriteOp{DigestKind: sp.key, Target: in.groupRef(), Attrs: in.attrs()})
			if err != nil {
				return MemberOutcome{}, writeError(err, false)
			}
			out := MemberOutcome{NoOp: res.NoOp}
			if res.Apply != nil {
				out.Tier0 = res.Tier0AfterWrite()
			}
			return out, nil
		},
		Verify: func(ctx context.Context, s step.Step, tp operation.TypedStep[memberPayload], _ MemberOutcome) (operation.Verdict, error) {
			if p.Reader == nil {
				return operation.Verdict{}, errUnavailable
			}
			in := tp.Payload.Input
			t := Target{ConnectionID: in.ConnectionID, ObjectGUID: in.GroupGuid, NamingContext: in.NamingContext}
			ctx = pinnedFor(ctx, s, authority.NamingContextID(in.NamingContext))
			pins := stepPins(s, t)
			g, err := p.Reader.Object(ctx, pins, in.groupRef(), nil, false)
			if err != nil {
				return operation.Verdict{}, readError(err)
			}
			if !g.Exists {
				return operation.Verdict{Reason: "target_gone"}, nil
			}
			if g.Tier0 { // rule 7: the guard runs again on the read-back
				return operation.Verdict{Reason: "tier0_after_write", Tier0: []step.Tier0Finding{{Object: in.GroupGuid}}}, nil
			}
			direct, err := p.Reader.DirectMember(ctx, pins, in.groupRef(), in.memberRef())
			if err != nil {
				return operation.Verdict{}, readError(err)
			}
			if direct != sp.add {
				return operation.Verdict{Reason: "membership_not_as_planned"}, nil
			}
			return operation.Verdict{OK: true}, nil
		},
		Inverse: func(tp operation.TypedStep[memberPayload], o MemberOutcome) (MemberInput, error) {
			if o.NoOp {
				return MemberInput{}, ErrNothingToUndo
			}
			return tp.Payload.Input, nil // applied by the Action MemberInverse names
		},
		Observe: func(ctx context.Context, pins authority.Pins, tp operation.TypedStep[memberPayload], _ time.Time) (operation.Observation, error) {
			if p.Reader == nil {
				return "", errUnavailable
			}
			in := tp.Payload.Input
			direct, err := p.Reader.DirectMember(ctx, pins, in.groupRef(), in.memberRef())
			if err != nil {
				return "", readError(err)
			}
			if direct == sp.add {
				return operation.ObservedAfter, nil
			}
			return operation.ObservedBefore, nil
		},
		// The member is touched too: the connector reports Tier-0 findings for both objects.
		Touched: func(tp operation.TypedStep[memberPayload]) []authority.TargetRef {
			return []authority.TargetRef{tp.Payload.Input.memberRef()}
		},
		Tier0: func(o MemberOutcome) []step.Tier0Finding { return o.Tier0 },
	})
}

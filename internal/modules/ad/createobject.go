package ad

import (
	"context"
	"fmt"
	"strings"

	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/directory/objectdef"
	"github.com/skenzeriq/activediq/internal/directory/writechange"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/operation"
)

// ObjectCreateInput is the input of create for a group, computer, contact or OU: plain attributes, no
// Template (Templates are user create definitions, ADM-008). The common name (the OU name for an OU) is
// Name; a group and a computer also need a sAMAccountName, which defaults to Name (a computer's gets the
// trailing "$").
type ObjectCreateInput struct {
	ConnectionID  string            `json:"connectionId"`
	NamingContext string            `json:"namingContext"`
	ParentGuid    string            `json:"parentGuid"`
	Name          string            `json:"name"`
	Attributes    map[string]string `json:"attributes,omitempty"`
	// GroupScope is "global", "domainLocal" or "universal"; GroupSecurity makes a security group. Group only.
	GroupScope    string `json:"groupScope,omitempty"`
	GroupSecurity bool   `json:"groupSecurity,omitempty"`
	// Enabled creates a computer account enabled. Computer only.
	Enabled bool `json:"enabled,omitempty"`
}

func createObjectSpec(c objClass) lifeSpec[ObjectCreateInput] {
	return lifeSpec[ObjectCreateInput]{
		id: c.id("create"), perm: c.perm("create"), schema: c.schema("Create"), audit: c.audit("created"),
		// A create is Reversible while the object has no links; once it is a member of or holds members
		// its delete is Lossy, which the Descriptor's worst case states.
		reversibility: operation.Lossy, create: true,
		plan: planCreateObject(c),
		satisfied: func(pl lifePayload, st client.ObjectState) bool {
			return strings.EqualFold(st.Class, c.Live) && st.Parent == pl.Parent && strings.EqualFold(st.RDN, pl.RDN)
		},
		before: func(lifePayload, client.ObjectState) bool { return false },
	}
}

func planCreateObject(c objClass) planFn[ObjectCreateInput] {
	return func(ctx context.Context, p LifecyclePorts, pc operation.PlanContext, in ObjectCreateInput) (*lifePlan, error) {
		t := Target{ConnectionID: in.ConnectionID, ObjectGUID: in.ParentGuid, NamingContext: in.NamingContext}
		if err := t.validate(); err != nil {
			return nil, err
		}
		if err := validName(in.Name); err != nil {
			return nil, err
		}
		attrs := objectdef.Input{}
		for k, v := range in.Attributes {
			a, ok := c.canon(k, true)
			if !ok || !validValue(v) {
				return nil, fmt.Errorf("%w: %s: %s", operation.ErrInvalid, ReasonAttributeDenied, k)
			}
			attrs[a] = v
		}
		spec := writechange.CreateSpec{Class: c.Live, RDN: in.Name}
		switch c.Seg {
		case "group":
			if in.GroupScope == "" {
				return nil, fmt.Errorf("%w: groupScope is required", operation.ErrInvalid)
			}
			spec.GroupScope, spec.GroupSecurity = in.GroupScope, in.GroupSecurity
		case "computer":
			spec.Enabled = in.Enabled
		default:
			if in.GroupScope != "" || in.GroupSecurity || in.Enabled {
				return nil, fmt.Errorf("%w: groupScope, groupSecurity and enabled do not apply to this class", operation.ErrInvalid)
			}
		}
		if c.Seg == "group" || c.Seg == "computer" {
			sam := attrs["sAMAccountName"]
			if sam == "" {
				sam = in.Name
				if c.Seg == "computer" {
					sam = strings.ToUpper(in.Name) + "$"
				}
				attrs["sAMAccountName"] = sam
			}
			if c.Seg == "computer" && !strings.HasSuffix(sam, "$") {
				return nil, fmt.Errorf("%w: a computer's sAMAccountName ends with $", operation.ErrInvalid)
			}
		}
		if err := readParent(ctx, p, pc, in.ConnectionID, in.ParentGuid, authority.NamingContextID(in.NamingContext)); err != nil {
			return nil, err
		}
		var set []writechange.Edit
		for _, k := range sortedKeys(attrs) {
			if v := attrs[k]; v != "" {
				set = append(set, writechange.Edit{Op: "set", Attribute: k, Values: []string{v}})
			}
		}
		spec.Set = set
		wa, err := writechange.CreateAttrs(spec)
		if err != nil {
			return nil, fmt.Errorf("%w: the create does not encode", operation.ErrInvalid)
		}
		target := authority.TargetRef{
			Connection: in.ConnectionID, Class: c.Live, Parent: in.ParentGuid, RDN: in.Name,
			NC: authority.NamingContextID(in.NamingContext),
		}
		pre := []string{"creates a " + c.Noun + " in the planned container; the new object does not exist yet"}
		if c.Seg == "computer" && !in.Enabled {
			pre = append(pre, "the account is created disabled")
		}
		return &lifePlan{
			sp: operation.StepPlan{
				Target: target, Kind: writechange.KeyObjectCreate, Diff: diffOfAttrs(wa, nil), Preconditions: pre,
				Reversibility:       operation.Reversible,
				ReversibilityReason: "the new " + c.Noun + " has no links; deleting it undoes the create until something is added to it or it joins a group",
			},
			pl: lifePayload{Target: t, Parent: in.ParentGuid, RDN: in.Name},
		}, nil
	}
}

package graph

import (
	"context"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/odata"
	gs "github.com/skenzeriq/activediq/internal/directory/odata/graphschema"
)

// GroupSchedule is one PIM-for-Groups eligibility or assignment schedule (TM-D25). Every field the
// classifier decides on is carried as Graph sent it; the classifier owns the meaning.
type GroupSchedule struct {
	ID          string
	GroupID     string
	PrincipalID string
	// PrincipalType is the Graph type without namespace ("user", "group", "servicePrincipal"); ""
	// when Graph did not say.
	PrincipalType string
	AccessID      string // "member" or "owner"; anything else is the caller's to refuse
	Status        string
	Eligible      bool       // true: eligibility schedule; false: assignment schedule
	Start         *time.Time // scheduleInfo.startDateTime
	End           *time.Time // scheduleInfo.expiration.endDateTime; nil when the schedule does not expire
}

type rawGroupSchedule struct {
	ID           string          `json:"id"`
	GroupID      string          `json:"groupId"`
	PrincipalID  string          `json:"principalId"`
	AccessID     string          `json:"accessId"`
	Status       string          `json:"status"`
	Principal    DirectoryObject `json:"principal"`
	ScheduleInfo struct {
		Start      *time.Time `json:"startDateTime"`
		Expiration struct {
			End *time.Time `json:"endDateTime"`
		} `json:"expiration"`
	} `json:"scheduleInfo"`
}

// GroupSchedules lists the eligibility and assignment schedules of one group (all pages), filtered
// by groupId. Needs PrivilegedEligibilitySchedule.Read.AzureADGroup and
// PrivilegedAssignmentSchedule.Read.AzureADGroup. A failure of either list fails the call.
func (c *Client) GroupSchedules(ctx context.Context, groupID guid.GUID) ([]GroupSchedule, error) {
	if groupID == (guid.GUID{}) {
		return nil, newErr(CodeInvalidArgument, 0, "group id must not be the zero GUID", nil)
	}
	return c.schedules(ctx, odata.Query{}.Filter(odata.Eq(gs.ScheduleGroupID, odata.GUIDTextOf(groupID))))
}

// PrincipalSchedules is GroupSchedules filtered by principalId: the per-write live check. The zero
// principal is refused, since unfiltered the call would answer for the tenant.
func (c *Client) PrincipalSchedules(ctx context.Context, principalID guid.GUID) ([]GroupSchedule, error) {
	if principalID == (guid.GUID{}) {
		return nil, newErr(CodeInvalidArgument, 0, "principal id must not be the zero GUID", nil)
	}
	return c.schedules(ctx, odata.Query{}.Filter(odata.Eq(gs.SchedulePrincipalID, odata.GUIDTextOf(principalID))))
}

func (c *Client) schedules(ctx context.Context, q odata.Query) ([]GroupSchedule, error) {
	// The principal is expanded so the schedule says what kind of object it names.
	q = q.Expand(gs.NavPrincipal, gs.ID)
	var out []GroupSchedule
	for _, k := range []struct {
		seg      odata.Name
		eligible bool
	}{{gs.SegEligibilitySched, true}, {gs.SegAssignmentSched, false}} {
		raw, err := list[rawGroupSchedule](ctx, c, odata.Get(odata.Seg(gs.SetIdentityGov), odata.Seg(gs.SegPrivilegedAccess),
			odata.Seg(gs.SegGroup), odata.Seg(k.seg)).With(q))
		if err != nil {
			return nil, err
		}
		for _, r := range raw {
			out = append(out, GroupSchedule{ID: r.ID, GroupID: r.GroupID, PrincipalID: r.PrincipalID, PrincipalType: r.Principal.Type(),
				AccessID: r.AccessID, Status: r.Status, Eligible: k.eligible, Start: r.ScheduleInfo.Start, End: r.ScheduleInfo.Expiration.End})
		}
	}
	return out, nil
}

// GroupTransitiveMembers lists the members of a group, nested groups' members included (all pages).
// Nested groups themselves are in the list.
func (c *Client) GroupTransitiveMembers(ctx context.Context, groupID guid.GUID) ([]DirectoryObject, error) {
	return list[DirectoryObject](ctx, c, odata.Get(odata.Seg(gs.SetGroups), odata.Key(odata.GUIDOf(groupID)),
		odata.Seg(gs.SegTransitiveMembers)).With(c.paged(selObject...)))
}

// GroupByID reads one group with its type and dynamic membership rule.
func (c *Client) GroupByID(ctx context.Context, groupID guid.GUID) (Group, error) {
	var g Group
	err := c.read(ctx, odata.Get(odata.Seg(gs.SetGroups), odata.Key(odata.GUIDOf(groupID))).
		With(c.q(gs.ID, gs.DisplayName, gs.GroupIsAssignableToRole, gs.GroupTypes, gs.MembershipRule)), &g)
	return g, err
}

// ServicePlan is one service plan of a subscribed SKU.
type ServicePlan struct {
	ServicePlanID      string `json:"servicePlanId"`
	ServicePlanName    string `json:"servicePlanName"`
	ProvisioningStatus string `json:"provisioningStatus"`
}

// SubscribedSKU is a licence the tenant holds (GET /subscribedSkus).
type SubscribedSKU struct {
	SKUID            string        `json:"skuId"`
	SKUPartNumber    string        `json:"skuPartNumber"`
	CapabilityStatus string        `json:"capabilityStatus"`
	ServicePlans     []ServicePlan `json:"servicePlans"`
}

// SubscribedSKUs lists the tenant's subscribed SKUs (Organization.Read.All is enough).
func (c *Client) SubscribedSKUs(ctx context.Context) ([]SubscribedSKU, error) {
	return list[SubscribedSKU](ctx, c, odata.Get(odata.Seg(gs.SetSubscribedSkus)).With(c.q()))
}

package server

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory"
	"github.com/skenzeriq/activediq/internal/modules/compliance"
	"github.com/skenzeriq/activediq/internal/modules/connections"
	"github.com/skenzeriq/activediq/internal/modules/delegation"
	"github.com/skenzeriq/activediq/internal/modules/inventory"
	"github.com/skenzeriq/activediq/internal/modules/notify"
	"github.com/skenzeriq/activediq/internal/platform"
	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/module/moduletest"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/rbac"
)

// stepUpTable is the §7.4 table (TM-D16 part 1) as far as its operations exist. An operation of the
// table joins here in the change that adds it, with the row it implements. Rows with no operation yet
// (LAPS/BitLocker reveal, RBAC changes, API token and enrollment-token creation, directory credential
// and connection changes, IdP configuration, audit export and retention, break-glass use, authority
// factor approval) are not listed, and each of those tickets adds its row and sets Descriptor.StepUp.
var stepUpTable = map[operation.ActionID]string{
	connections.Tier0OverrideActionID:     "The Tier-0 override acknowledgement (TM-D1)",
	connections.HybridLinkConfirmActionID: "HybridLink confirmation (connections.hybrid_link.confirm)",
	// Declare writes a confirmed link directly, skipping proposed: the same cross-directory authority
	// path as confirm, so it carries the same flag.
	connections.HybridLinkDeclareActionID: "HybridLink declaration confirms without a proposal; same path as confirm",
	// Re-confirming a correlation held for reconfirm_required (TM-D17 rule 4 (g)) is an irreversible
	// cross-directory authority decision; it also requires a current tenant-owner.
	connections.ReconfirmActionID:    "Correlation re-confirmation (TM-D17 rule 4 (g))",
	inventory.SetDesignationActionID: "Designating or un-designating tier0 objects (§6.4)",
	// Legal holds (T-0605): lifting one lets the next retention purge destroy evidence, and placing one
	// withholds data from erasure; both are a compliance officer's act and need a fresh MFA.
	compliance.SetHoldActionID:     "Placing a legal hold on a personal subject",
	compliance.ReleaseHoldActionID: "Releasing a legal hold (lets the retention purge destroy evidence)",
	// notify.settings.update widens the allowed recipient domains and re-points the SMTP relay (TM-D30 SX-7).
	notify.UpdateSettingsActionID: "Widening allowed recipient domains / re-pointing the SMTP relay (TM-D30 SX-7)",
	// RBAC changes (§7.4): every role or assignment change is a step-up operation.
	delegation.RoleCreateID: "RBAC change: creating a custom role",
	delegation.RoleUpdateID: "RBAC change: editing a custom role's permissions",
	delegation.GrantID:      "RBAC change: granting an assignment",
	delegation.RevokeID:     "RBAC change: revoking an assignment",
}

func catalogue(t *testing.T) []operation.Descriptor {
	t.Helper()
	var all []operation.Action
	for _, m := range generatedModules(platform.Deps{}, directory.Services{}) {
		c, err := moduletest.Register(m.Module)
		if err != nil {
			t.Fatalf("register %s: %v", m.ID, err)
		}
		all = append(all, c.Actions()...)
	}
	reg, err := operation.NewRegistry(all...)
	if err != nil {
		t.Fatal(err)
	}
	return reg.Catalogue()
}

// Every table operation that exists carries the flag, and no operation carries it unlisted, so the
// table and the catalogue cannot drift in either direction.
func Test_stepup_flag_catalogue_matches_table(t *testing.T) {
	cat := catalogue(t)
	byID := map[operation.ActionID]operation.Descriptor{}
	for _, d := range cat {
		byID[d.ID] = d
	}
	for id, why := range stepUpTable {
		d, ok := byID[id]
		if !ok {
			t.Errorf("table operation %s (%s) is not in the catalogue: remove it from the table or register it", id, why)
			continue
		}
		if !d.StepUp {
			t.Errorf("%s (%s) is in the §7.4 table but its Descriptor lacks StepUp", id, why)
		}
	}
	for _, d := range cat {
		if _, listed := stepUpTable[d.ID]; d.StepUp && !listed {
			t.Errorf("%s carries StepUp but is not in stepUpTable: add its §7.4 row", d.ID)
		}
	}
}

// groupTargetViolations lists the Actions that hold a group-membership permission without declaring the
// group class as their target.
func groupTargetViolations(cat []operation.Descriptor) []string {
	special := map[authz.Permission]bool{}
	for _, p := range rbac.GroupMembershipPermissions {
		special[p] = true
	}
	var bad []string
	for _, d := range cat {
		if special[d.Permission] && d.TargetClass != "group" {
			bad = append(bad, string(d.ID))
		}
	}
	return bad
}

// TM-D18: the group-membership guard computes reach from the authorisation Target, so every Action that
// changes who a group reaches must declare the group class as its target. An Action aimed at the member
// (the natural LDAP shape) would compute reach from the wrong object.
func Test_group_membership_actions_target_the_group(t *testing.T) {
	if bad := groupTargetViolations(catalogue(t)); len(bad) > 0 {
		t.Errorf("group-membership Actions without TargetClass \"group\": %v", bad)
	}
}

// The check bites: a member-targeted Action, or one with no class, is reported.
func Test_group_target_check_rejects_member_targets(t *testing.T) {
	cat := []operation.Descriptor{
		{ID: "x.group.add", Permission: "objects.group.add_member", TargetClass: "user"},
		{ID: "x.group.nest", Permission: "objects.group.nest"},
		{ID: "x.user.primary", Permission: "objects.user.set_primary_group", TargetClass: "group"},
		{ID: "x.user.reset", Permission: "objects.user.reset_password", TargetClass: "user"},
	}
	if bad := groupTargetViolations(cat); len(bad) != 2 || bad[0] != "x.group.add" || bad[1] != "x.group.nest" {
		t.Fatalf("got %v", bad)
	}
}

// The control_plane flag is the authz.NeverCrosses rule made visible in the catalogue: an Action carries
// it if and only if its permission is in a never-crosses family.
func Test_control_plane_flag_catalogue_matches_never_crosses(t *testing.T) {
	cat := catalogue(t)
	flagged := 0
	for _, d := range cat {
		if d.ControlPlane && !authz.NeverCrosses(d.Permission) {
			t.Errorf("%s (permission %s) is flagged control_plane but its permission is not in a never-crosses family", d.ID, d.Permission)
		}
		if authz.NeverCrosses(d.Permission) && !d.ControlPlane {
			t.Errorf("%s (permission %s) is in a never-crosses family and must be flagged control_plane", d.ID, d.Permission)
		}
		if d.ControlPlane {
			flagged++
		}
	}
	for _, id := range []operation.ActionID{delegation.RoleCreateID, delegation.RoleUpdateID, delegation.GrantID, delegation.RevokeID} {
		found := false
		for _, d := range cat {
			found = found || (d.ID == id && d.ControlPlane)
		}
		if !found {
			t.Errorf("%s is not in the catalogue flagged control_plane", id)
		}
	}
	if flagged == 0 {
		t.Error("no Action is flagged control_plane")
	}
}

// T-0617: every registered Action decodes its input strictly. An input with an extra member is refused
// with ErrInvalid before Plan's own logic runs, so a mistyped or drifted member can never be dropped
// silently (an expiring grant becoming permanent).
func Test_every_action_plan_refuses_unknown_input_member(t *testing.T) {
	var all []operation.Action
	for _, m := range generatedModules(platform.Deps{}, directory.Services{}) {
		c, err := moduletest.Register(m.Module)
		if err != nil {
			t.Fatalf("register %s: %v", m.ID, err)
		}
		all = append(all, c.Actions()...)
	}
	if len(all) == 0 {
		t.Fatal("no actions registered")
	}
	for _, a := range all {
		id := a.Describe().ID
		_, err := a.Plan(context.Background(), operation.PlanContext{}, operation.Input(`{"__unknown_member__":1}`))
		if !errors.Is(err, operation.ErrInvalid) {
			t.Errorf("%s: Plan with an unknown input member returned %v, want ErrInvalid", id, err)
		}
	}
}

// stepUpPolicyGaps lists the StepUp Actions whose permission is bound to an HTTP operation of the
// contract (routed) but has no stepUp row. An Action whose permission no operation declares yet cannot
// have a row (fitness-api A13 fails a row naming nothing); its row enters with its route.
func stepUpPolicyGaps(cat []operation.Descriptor, rows, routed []string) []string {
	var bad []string
	for _, d := range cat {
		p := string(d.Permission)
		if d.StepUp && slices.Contains(routed, p) && !slices.Contains(rows, p) {
			bad = append(bad, string(d.ID))
		}
	}
	return bad
}

// A permission of a StepUp Action that has an HTTP route must be a stepUp row of policy.yaml: apihost
// asks that list, and a route whose permission is missing from it would run on a stale session
// (T-0199 carried requirement; test step_up_permissions_all_in_policy).
func Test_step_up_permissions_all_in_policy(t *testing.T) {
	pol, err := apihost.LoadPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if bad := stepUpPolicyGaps(catalogue(t), pol.StepUp, moduleOperationPermissions); len(bad) > 0 {
		t.Errorf("StepUp Actions with a routed permission and no stepUp row in api/openapi/policy.yaml: %v", bad)
	}
}

// The check bites: a routed StepUp permission without a row is reported; an unrouted one is not.
func Test_step_up_policy_gap_check_bites(t *testing.T) {
	cat := []operation.Descriptor{
		{ID: "a.routed", Permission: "a.do", StepUp: true},
		{ID: "b.unrouted", Permission: "b.do", StepUp: true},
		{ID: "c.rowed", Permission: "c.do", StepUp: true},
		{ID: "d.plain", Permission: "d.do"},
	}
	got := stepUpPolicyGaps(cat, []string{"c.do"}, []string{"a.do", "c.do", "d.do"})
	if len(got) != 1 || got[0] != "a.routed" {
		t.Fatalf("got %v", got)
	}
}

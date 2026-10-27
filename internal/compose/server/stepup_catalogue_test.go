package server

import (
	"testing"

	"github.com/skenzeriq/activediq/internal/directory"
	"github.com/skenzeriq/activediq/internal/modules/connections"
	"github.com/skenzeriq/activediq/internal/modules/delegation"
	"github.com/skenzeriq/activediq/internal/modules/inventory"
	"github.com/skenzeriq/activediq/internal/platform"
	"github.com/skenzeriq/activediq/internal/platform/module/moduletest"
	"github.com/skenzeriq/activediq/internal/platform/operation"
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

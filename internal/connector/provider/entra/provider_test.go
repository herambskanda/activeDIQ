package entra

import (
	"testing"

	"github.com/skenzeriq/activediq/internal/connector/provider"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

var _ provider.Provider = (*EntraProvider)(nil)

// AC4: an Entra provider has the core only, so it is no DC-bound provider and Supports reports every
// group it derives as UNSUPPORTED, each with a reason.
func TestEntraSupportsAndFacets(t *testing.T) {
	var p provider.Provider = &EntraProvider{TenantID: "t"}
	if _, ok := p.(provider.DCBound); ok {
		t.Error("Entra has no DC")
	}
	if _, ok := p.(provider.ObjectReader); ok {
		t.Error("Entra has no object reader yet")
	}
	if _, ok := p.(provider.RightsSource); ok {
		t.Error("Entra has no rights source until T-0615")
	}
	rows := provider.Supports(p)
	if len(rows) != 3 {
		t.Fatalf("%v", rows)
	}
	for _, r := range rows {
		if r.GetState() != connectorv1.SupportState_SUPPORT_STATE_UNSUPPORTED || r.GetReason() == "" {
			t.Errorf("%s: %s %q", r.GetOperation(), r.GetState(), r.GetReason())
		}
	}
}

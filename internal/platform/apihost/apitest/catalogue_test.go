package apitest_test

import (
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/apihost/apitest"
)

// Every concrete x-permission of the shipped contract is in the catalogue, the reports.* ones (T-1032)
// included, and the two reserved words are not permissions.
func TestCatalogueHoldsEveryContractPermission(t *testing.T) {
	doc, err := apihost.LoadDocument()
	if err != nil {
		t.Fatal(err)
	}
	c := apitest.Catalogue(doc)
	for _, p := range []string{"reports.run", "reports.export", "reports.schedule", "reports.schedule.manage_all", "directory.read"} {
		if !c.Has(p) {
			t.Errorf("catalogue lacks %q", p)
		}
	}
	for _, p := range []string{"", "anonymous", "authenticated"} {
		if c.Has(p) {
			t.Errorf("catalogue holds the reserved word %q", p)
		}
	}
	for _, op := range doc.Operations() {
		if op.Permission != "anonymous" && op.Permission != "authenticated" && !c.Has(op.Permission) {
			t.Errorf("%s: %q missing", op.ID, op.Permission)
		}
	}
}

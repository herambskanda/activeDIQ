package odataname_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/skenzeriq/activediq/tools/analyzers/odataname"
)

// FX-11 and OK-10: a non-constant odata.Name is a finding; constants, the odata home, graphschema
// and test files are not.
func TestODataName(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), odataname.Analyzer,
		"internal/modules/m", "internal/directory/odata", "internal/directory/odata/graphschema")
}

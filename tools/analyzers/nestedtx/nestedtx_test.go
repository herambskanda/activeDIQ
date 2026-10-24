package nestedtx_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/skenzeriq/activediq/tools/analyzers/nestedtx"
)

// A direct WithTenant/WithPlatform or context.Background/TODO inside a body is reported; the body's
// own ctx, calls outside a body, and bodies of other functions are not.
func TestNestedTx(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), nestedtx.Analyzer, "internal/modules/m")
}

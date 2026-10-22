package constdisp_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/skenzeriq/activediq/tools/analyzers/constdisp"
)

// HT-18: no folded spelling of Content-Disposition outside httpx; the httpx package is exempt.
func TestConstDisp(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), constdisp.Analyzer, "internal/modules/m", "internal/platform/httpx")
}

package stepescape_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/skenzeriq/activediq/tools/analyzers/stepescape"
)

func TestStepEscape(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), stepescape.Analyzer, "internal/modules/m", "internal/platform/operation/step")
}

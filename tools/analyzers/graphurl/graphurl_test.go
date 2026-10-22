package graphurl_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/skenzeriq/activediq/tools/analyzers/graphurl"
)

// FX-10: hand-written URL path or query in the Graph connector. The token endpoint function, test
// files and other trees are not judged.
func TestGraphURL(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), graphurl.Analyzer, "internal/connector/graph", "internal/modules/m")
}

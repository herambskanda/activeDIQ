package dnstring_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/skenzeriq/activediq/tools/analyzers/dnstring"
)

// The fixtures carry `// want` comments: one violation per banned shape, and the allowed uses (dn,
// the connector, Display, test files) must produce nothing.
func TestDNString(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), dnstring.Analyzer, "internal/modules/m", "internal/connector/ok", "internal/directory/dn")
}

package sqlconst_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/skenzeriq/activediq/tools/analyzers/sqlconst"
)

// Constants and CompiledSQL pass; a variable, a concatenation and a Sprintf are reported; generated
// sqlc code and tier L are not judged.
func TestSQLConst(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), sqlconst.Analyzer, "internal/modules/m", "tools/fitness/x")
}

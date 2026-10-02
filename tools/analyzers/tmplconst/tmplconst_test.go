package tmplconst_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/skenzeriq/activediq/tools/analyzers/tmplconst"
)

// HT-07: parse from constants or embed.FS only.
func TestTmplConst(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), tmplconst.Analyzer, "internal/modules/m")
}

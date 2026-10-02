// Package analyzers lists the type-aware FF-SP2 passes of the safe-primitives fitness set. The same
// list backs `go vet -vettool` (tools/vettool) and the in-process run of tools/fitness/safeprim.
package analyzers

import (
	"golang.org/x/tools/go/analysis"

	"github.com/skenzeriq/activediq/tools/analyzers/dnstring"
	"github.com/skenzeriq/activediq/tools/analyzers/secretjson"
	"github.com/skenzeriq/activediq/tools/analyzers/sqlconst"
	"github.com/skenzeriq/activediq/tools/analyzers/tmplconst"
)

// All returns dnstring, sqlconst, secretjson and tmplconst.
func All() []*analysis.Analyzer {
	return []*analysis.Analyzer{dnstring.Analyzer, sqlconst.Analyzer, secretjson.Analyzer, tmplconst.Analyzer}
}

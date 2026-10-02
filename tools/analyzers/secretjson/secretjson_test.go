package secretjson_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/skenzeriq/activediq/tools/analyzers/secretjson"
)

// Covers the three rules: decode into a Secret-bearing type only through secretjson.Decode, called
// only from apihost, and no string token inside a Secret decoder. The generated nested decoder
// (UnmarshalJSONFrom in a tools/gen/api file) is exempt; the same call in a hand-written file is not.
func TestSecretJSON(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), secretjson.Analyzer,
		"internal/modules/m", "internal/platform/secret", "internal/platform/secret/secretjson", "internal/platform/apihost")
}

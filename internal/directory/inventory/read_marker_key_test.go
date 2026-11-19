package inventory

import (
	"os"
	"strings"
	"testing"
)

// The read-state SQL fragments are literal constants (FF-SP2), so they repeat ReadMarkerKey; this ties
// the literal to the const the mapper writes under (T-2216).
func Test_read_state_sql_literal_matches_marker_key(t *testing.T) {
	src, err := os.ReadFile("datasets.go")
	if err != nil {
		t.Fatal(err)
	}
	want := "{t}.attributes -> '" + ReadMarkerKey + "' ->> '"
	if n := strings.Count(string(src), want); n < 15 {
		t.Fatalf("only %d read-state fragments use marker key %q", n, ReadMarkerKey)
	}
	if strings.Contains(string(src), "-> 'attrRead'") != (ReadMarkerKey == "attrRead") {
		t.Fatalf("ReadMarkerKey %q drifted from the literal in datasets.go", ReadMarkerKey)
	}
}

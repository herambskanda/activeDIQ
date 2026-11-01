package run

import (
	"strconv"
	"strings"
	"testing"
)

// The delete statement is a whole constant (safe-primitives rule), so its LIMIT cannot be built from
// RetentionBatch; this pins the two so the loop's "short batch means done" test cannot drift.
func TestRetentionBatchMatchesDeleteLimit(t *testing.T) {
	if !strings.Contains(deleteRowBatch, "LIMIT "+strconv.Itoa(RetentionBatch)+")") {
		t.Fatalf("deleteRowBatch LIMIT does not match RetentionBatch=%d: %s", RetentionBatch, deleteRowBatch)
	}
}

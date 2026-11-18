package library_test

import (
	"os"
	"testing"
)

// scaleFull is the opt-in switch for the scale tests (T-2008). The default package run stays well under
// the 600 s test timeout on PostgreSQL 16 and 18; `make test-scale` sets ADIQ_SCALE_FULL=1 in its own job
// with its own timeout.
func requireScaleFull(t *testing.T) {
	t.Helper()
	if os.Getenv("ADIQ_SCALE_FULL") != "1" {
		t.Skip("scale test: opt-in with ADIQ_SCALE_FULL=1 (make test-scale)")
	}
}

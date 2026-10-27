package server

import (
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/store"
)

// T-0445 acceptance 2: the owner writer is built with the authn implementations, and a missing
// collaborator fails startup instead of leaving an unguarded writer.
func TestBuildOwnerAssignmentsRequiresEveryPort(t *testing.T) {
	c, err := buildConsole(&store.DB{}, nopSink{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if oa, err := buildOwnerAssignments(&store.DB{}, nopSink{}, c.Sessions); err != nil || oa == nil {
		t.Fatalf("build = %v, %v", oa, err)
	}
	if _, err := buildOwnerAssignments(nil, nopSink{}, c.Sessions); err == nil {
		t.Error("nil database accepted")
	}
	if _, err := buildOwnerAssignments(&store.DB{}, nil, c.Sessions); err == nil {
		t.Error("nil audit sink accepted")
	}
	if _, err := buildOwnerAssignments(&store.DB{}, nopSink{}, nil); err == nil {
		t.Error("nil session store accepted")
	}
}

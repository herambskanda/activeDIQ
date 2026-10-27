package server

import (
	"context"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/store"
)

type nopSink struct{}

func (nopSink) Append(context.Context, store.Tx, audit.Event) error { return nil }

// T-0445 acceptance 2: the owner writer is built with the authn implementations, and a missing
// collaborator fails startup instead of leaving an unguarded writer.
func TestBuildOwnerAssignmentsRequiresEveryPort(t *testing.T) {
	if oa, err := buildOwnerAssignments(&store.DB{}, nopSink{}); err != nil || oa == nil {
		t.Fatalf("build = %v, %v", oa, err)
	}
	if _, err := buildOwnerAssignments(nil, nopSink{}); err == nil {
		t.Error("nil database accepted")
	}
	if _, err := buildOwnerAssignments(&store.DB{}, nil); err == nil {
		t.Error("nil audit sink accepted")
	}
}

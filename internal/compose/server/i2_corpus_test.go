package server

import (
	"context"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory"
	"github.com/skenzeriq/activediq/internal/platform/capability"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/store/owners"
)

// I-2 corpus, registry half (impersonate-as-admin-attribution §6.2, T-1629): every registered Action that
// is not a Store Action must be one the ad module's corpus test (internal/modules/ad/i2_corpus_test.go)
// fixtures. That test covers every Action the ad module builds, so the registry check is: every
// directory-targeting registered Action is an ad.user.* Action. A new directory Action of another
// module or kind fails here until it gets its own fixtured corpus. This file may not name a module
// (blueprint §2.5), hence the ID prefix rather than the ad constants.
func TestI2CorpusEveryRegisteredAction(t *testing.T) {
	c, _, err := bootReport(context.Background(), capability.NewSet(capability.DirectoryAD, capability.DirectoryEntra, capability.TenantProvisioning), directory.Services{}, owners.Lookup)
	if err != nil {
		t.Fatalf("boot: %v", err)
	}
	acts := c.Actions()
	if len(acts) == 0 {
		t.Fatal("no registered Actions: the corpus is empty")
	}
	for _, act := range acts {
		d := act.Describe()
		if d.Target == operation.TargetStore {
			continue
		}
		if !strings.HasPrefix(string(d.ID), "ad.user.") {
			t.Errorf("%s targets %s and has no I-2 fixture: add a fixtured corpus for it", d.ID, d.Target)
		}
	}
}

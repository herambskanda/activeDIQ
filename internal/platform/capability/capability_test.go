package capability_test

import (
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/capability"
)

func TestSetEnabled(t *testing.T) {
	s := capability.NewSet(capability.DirectoryAD)
	if !s.Enabled(capability.DirectoryAD) {
		t.Errorf("%q should be enabled", capability.DirectoryAD)
	}
	if s.Enabled(capability.DirectoryEntra) {
		t.Errorf("%q should not be enabled", capability.DirectoryEntra)
	}
	if capability.Set(nil).Enabled(capability.DirectoryAD) {
		t.Error("a nil set enables nothing")
	}
}

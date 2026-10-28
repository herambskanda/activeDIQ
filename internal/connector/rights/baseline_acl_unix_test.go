//go:build unix

package rights

import (
	"os"
	"testing"
)

func widenForTest(t *testing.T, p string) {
	t.Helper()
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
}

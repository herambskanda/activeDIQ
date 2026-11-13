package sync_test

import (
	"errors"
	"strings"
	"testing"

	dirsync "github.com/skenzeriq/activediq/internal/directory/sync"
)

func wantMalformed(t *testing.T, err error, attr string, code dirsync.Code) {
	t.Helper()
	var e *dirsync.Error
	if !errors.Is(err, dirsync.ErrMalformed) || !errors.As(err, &e) {
		t.Fatalf("error = %v, want a *sync.Error", err)
	}
	if e.Attr != attr || e.Code != code {
		t.Errorf("error = (%s, %s), want (%s, %s)", e.Attr, e.Code, attr, code)
	}
	if !strings.Contains(err.Error(), attr) {
		t.Errorf("%q does not name the attribute", err.Error())
	}
}

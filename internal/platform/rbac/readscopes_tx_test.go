package rbac

import (
	"context"
	"errors"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// Before Bind, and for a nil producer, every call is refused: never an unscoped read.
func TestTxReadScopesFailsClosedUntilBound(t *testing.T) {
	for name, p := range map[string]*TxReadScopes{"nil": nil, "unbound": NewTxReadScopes(nil)} {
		if _, err := p.ReadScope(context.Background(), tenant.ID{}, authority.Chain{}, "directory.read"); !errors.Is(err, ErrReadScopesUnbound) {
			t.Errorf("%s: err = %v, want ErrReadScopesUnbound", name, err)
		}
	}
	if err := NewTxReadScopes(nil).Bind(nil); err == nil {
		t.Error("Bind accepted a nil producer")
	}
}

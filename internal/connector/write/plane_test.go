package write

import (
	"errors"
	"testing"

	"github.com/skenzeriq/activediq/internal/connector/provider"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// hidden wraps a provider and exposes only the core interface, as a logging or metrics decorator would.
type hidden struct{ provider.Provider }

func TestNewRefusesKindFacetMismatch(t *testing.T) {
	r := newRig(t, nil)

	// AD kind with DCBound hidden: refused, not treated as the Entra plane.
	if _, err := New(hidden{r.prov}, r.gate); !errors.Is(err, provider.ErrKindFacets) {
		t.Fatalf("AD provider without DCBound accepted: %v", err)
	}
	// A non-AD kind that implements DCBound.
	r.prov.kind = connectorv1.ProviderKind_PROVIDER_KIND_ENTRA
	if _, err := New(r.prov, r.gate); !errors.Is(err, provider.ErrKindFacets) {
		t.Fatalf("Entra provider with DCBound accepted: %v", err)
	}
	// Unspecified kind.
	r.prov.kind = connectorv1.ProviderKind_PROVIDER_KIND_UNSPECIFIED
	if _, err := New(r.prov, r.gate); !errors.Is(err, provider.ErrKindFacets) {
		t.Fatalf("unspecified kind accepted: %v", err)
	}
}

// An op registered for the Entra provider kind is not dispatchable from an AD provider.
func TestOpTableKeyedByProviderKind(t *testing.T) {
	rr := newRig(t, nil)
	rec := withTestOp(rr)
	op := rr.h.ops[adKey(1)]
	rr.h.ops = map[opKey]WriteOp{{connectorv1.ProviderKind_PROVIDER_KIND_ENTRA, 1}: op}
	if _, ok := rr.h.ops[opKey{rr.prov.Kind(), 1}]; ok {
		t.Fatal("Entra row reachable from an AD provider")
	}
	if rec.plan != 0 || rec.apply != 0 {
		t.Fatal("op ran")
	}
}

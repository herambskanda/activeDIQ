package write

import (
	"context"
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

// An op registered only for the Entra provider kind is not dispatchable from an AD provider, with a
// run that passes every check. The control proves the same request does reach an AD-keyed row.
func TestOpTableKeyedByProviderKind(t *testing.T) {
	run := passRun(nil)
	rr := newRig(t, &run)
	rec := withTestOp(rr)
	id := mk(10)
	plan := func() error {
		q := planReq(id, ctxFor(id))
		q.Kind = 1
		_, err := rr.h.Plan(context.Background(), q)
		return err
	}
	if err := plan(); err != nil || rec.plan != 1 {
		t.Fatalf("control: AD-keyed row did not run: err=%v plans=%d", err, rec.plan)
	}

	op := rr.h.ops[adKey(1)]
	rr.h.ops = map[opKey]WriteOp{{connectorv1.ProviderKind_PROVIDER_KIND_ENTRA, 1}: op}
	if err := plan(); connErr(t, err).GetCode() != connectorv1.ErrorCode_ERROR_CODE_CAPABILITY_UNSUPPORTED {
		t.Fatalf("Plan reached an Entra row from an AD provider: %v", err)
	}
	a := applyReq(id, ctxFor(id))
	a.Kind = 1
	if _, err := rr.h.Apply(context.Background(), a); connErr(t, err).GetCode() != connectorv1.ErrorCode_ERROR_CODE_CAPABILITY_UNSUPPORTED {
		t.Fatalf("Apply reached an Entra row from an AD provider: %v", err)
	}
	if rec.plan != 1 || rec.apply != 0 {
		t.Fatalf("op ran: plan=%d apply=%d", rec.plan, rec.apply)
	}
}

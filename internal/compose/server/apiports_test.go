package server

import (
	"context"
	"errors"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/limiter"
)

// testLimiter is the limiter over a memory principal store, as a one-node install builds it.
func testLimiter(t *testing.T) *limiter.Limiter {
	t.Helper()
	l, err := limiter.New(limiter.Config{Principals: limiter.NewMemoryStore(nil)})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// failClosedPorts mounts the given limiter as Limits and keeps the other ports refusing.
func TestFailClosedPortsMountsLimiter(t *testing.T) {
	lim := testLimiter(t)
	p := failClosedPorts(lim)
	if p.Limits != apihost.Limiter(lim) {
		t.Fatalf("Limits is %T, want the limiter", p.Limits)
	}
	if _, err := p.Authn.Authenticate(nil); !errors.Is(err, apihost.ErrUnauthenticated) {
		t.Errorf("Authn must stay fail-closed, got %v", err)
	}
}

// A request past chain step 10 is metered against the shared store: burst+1 reveals are refused, and the
// same principal ID in another tenant is unaffected.
func TestLimiterMetersPrincipalAgainstStore(t *testing.T) {
	ctx := context.Background()
	p := failClosedPorts(testLimiter(t)).Limits
	a := apihost.Principal{ID: "u1", Tenant: "t1"}
	for i := 0; i < 5; i++ {
		d, err := p.AllowPrincipal(ctx, "reveal", a)
		if err != nil || d.RetryAfter != 0 {
			t.Fatalf("call %d refused: %+v %v", i, d, err)
		}
	}
	if d, err := p.AllowPrincipal(ctx, "reveal", a); err != nil || d.RetryAfter == 0 {
		t.Fatalf("burst+1 admitted: %+v %v", d, err)
	}
	if d, err := p.AllowPrincipal(ctx, "reveal", apihost.Principal{ID: "u1", Tenant: "t2"}); err != nil || d.RetryAfter != 0 {
		t.Fatalf("other tenant refused: %+v %v", d, err)
	}
}

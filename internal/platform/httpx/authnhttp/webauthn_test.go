package authnhttp

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/authn"
)

type neverCalled struct{ t *testing.T }

func (n neverCalled) Begin(context.Context, authn.PendingHandle) (authn.WebAuthnOptions, error) {
	n.t.Fatal("the factor was called for a malformed pending cookie")
	return authn.WebAuthnOptions{}, nil
}

func (n neverCalled) Verify(context.Context, authn.PendingHandle, authn.WebAuthnAssertion, netip.Addr) (authn.CreateResult, error) {
	n.t.Fatal("the factor was called for a malformed pending cookie")
	return authn.CreateResult{}, nil
}

// A missing or malformed pending cookie is ErrPendingInvalid before the factor is reached.
func TestWebAuthnCookiesMalformedPending(t *testing.T) {
	c := WebAuthnCookies{Factor: neverCalled{t}}
	for _, v := range []string{"", "garbage", "a.b"} {
		if _, err := c.BeginWebAuthnCookie(context.Background(), v); !errors.Is(err, authn.ErrPendingInvalid) {
			t.Fatalf("begin %q: %v", v, err)
		}
		if _, _, err := c.VerifyWebAuthnCookie(context.Background(), v, authn.WebAuthnAssertion{}, netip.Addr{}); !errors.Is(err, authn.ErrPendingInvalid) {
			t.Fatalf("verify %q: %v", v, err)
		}
	}
}

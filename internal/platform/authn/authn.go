// Package authn serves the sign-in plane operations of the console: the break-glass password step
// (AN-8), the second factor (AN-10), sign-out and the CSRF value. Until the build tickets land every
// handler answers 501 /problems/not-implemented, so the contract, the policy rows and the route set are
// real while no behaviour is faked (threat model section 7.6).
package authn

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/apihost/apitypes"
	"github.com/skenzeriq/activediq/internal/platform/authn/api"
)

// TOTPCookieVerifier is the HTTP-facing shape of the AN-10 TOTP step: it takes the pending cookie's value
// and returns the Set-Cookie lines to send. httpx/authnhttp implements it (authn imports no net/http,
// ADR-0004 A6), so the cookie attributes live in one place.
type TOTPCookieVerifier interface {
	VerifyTOTPCookie(ctx context.Context, pendingCookie, code string, from netip.Addr) (CreateResult, []string, error)
}

// Handlers implements api.Handlers. AN-10 TOTP is real once a SecondFactor is supplied; the other
// operations stay 501 stubs until their build tickets land.
type Handlers struct {
	SecondFactor TOTPCookieVerifier
	Log          *slog.Logger
}

var _ api.Handlers = Handlers{}

// API returns the tag's routes for compose/server to mount.
func API(h Handlers) apihost.TagHandlers { return api.Bind(h) }

func (Handlers) SignInBreakGlassPassword(context.Context, api.SignInBreakGlassPasswordInput) (api.SignInBreakGlassPasswordOutput, error) {
	return nil, apitypes.NotImplemented("")
}

func (Handlers) CreateWebAuthnSignInChallenge(context.Context, api.CreateWebAuthnSignInChallengeInput) (api.CreateWebAuthnSignInChallengeOutput, error) {
	return nil, apitypes.NotImplemented("")
}

func (Handlers) VerifyWebAuthnSignIn(context.Context, api.VerifyWebAuthnSignInInput) (api.VerifyWebAuthnSignInOutput, error) {
	return nil, apitypes.NotImplemented("")
}

// VerifyTOTPSignIn is AN-10 for TOTP. The pending handle is the cookie and nothing else; every way the
// sign-in can fail (no cookie, a repeated or malformed one, an expired or exhausted pending sign-in, a
// wrong code) is the same 401 as any other sign-in failure, so the answer is no oracle. On success the
// response sets the new session cookie and clears the pending one.
func (h Handlers) VerifyTOTPSignIn(ctx context.Context, in api.VerifyTOTPSignInInput) (api.VerifyTOTPSignInOutput, error) {
	if h.SecondFactor == nil {
		return nil, apitypes.NotImplemented("")
	}
	var code string
	in.Body.Code.Expose(func(b []byte) { code = string(b) })
	// PeerIP is the client address (the TCP peer, or the right-most untrusted X-Forwarded-For hop when the peer is a configured trusted proxy, ACTIVEDIQ_TRUSTED_PROXIES); the zero Addr only when it does not parse.
	from, _ := netip.ParseAddr(in.PeerIP)
	_, lines, err := h.SecondFactor.VerifyTOTPCookie(ctx, in.HostAdiqPending.Reveal(), code, from)
	if err != nil {
		if errors.Is(err, ErrPendingInvalid) || errors.Is(err, ErrSecondFactorRefused) {
			if h.Log != nil {
				h.Log.Info("second factor refused", "peer_ip", in.PeerIP, "trace_id", apihost.TraceID(ctx))
			}
			return nil, apitypes.SignInFailed("")
		}
		return nil, err // an infrastructure fault: the chain answers 500 without detail
	}
	return api.VerifyTOTPSignIn204{SetCookie: lines}, nil
}

func (Handlers) SignOut(context.Context, api.SignOutInput) (api.SignOutOutput, error) {
	return nil, apitypes.NotImplemented("")
}

func (Handlers) GetCSRFToken(context.Context, api.GetCSRFTokenInput) (api.GetCSRFTokenOutput, error) {
	return nil, apitypes.NotImplemented("")
}

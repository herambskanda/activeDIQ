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
	"github.com/skenzeriq/activediq/internal/platform/secret"
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
	// Password is AN-8. While nil the operation answers 501, so no behaviour is faked.
	Password     PasswordCookieBeginner
	SecondFactor TOTPCookieVerifier
	WebAuthn     WebAuthnCookieVerifier
	Log          *slog.Logger
}

var _ api.Handlers = Handlers{}

// Bind returns the tag's routes for compose/server to mount (the ADR-0004 A6 shape: h.Bind()).
func (h Handlers) Bind() apihost.TagHandlers { return api.Bind(h) }

// PasswordCookieBeginner is the HTTP-facing shape of AN-8: it takes the submitted credentials and returns
// the Set-Cookie line of the pending sign-in. httpx/authnhttp implements it over LocalCredentials.
type PasswordCookieBeginner interface {
	BeginPasswordCookie(ctx context.Context, username string, password secret.Secret, from netip.Addr) (string, error)
}

// SignInBreakGlassPassword is AN-8. Success sets only the pending cookie (AN-10 follows); every refusal is
// the one 401 of the sign-in plane, with no hint of why.
func (h Handlers) SignInBreakGlassPassword(ctx context.Context, in api.SignInBreakGlassPasswordInput) (api.SignInBreakGlassPasswordOutput, error) {
	if h.Password == nil {
		return nil, apitypes.NotImplemented("")
	}
	from, _ := netip.ParseAddr(in.PeerIP)
	line, err := h.Password.BeginPasswordCookie(ctx, in.Body.Username, in.Body.Password, from)
	if err != nil {
		if errors.Is(err, ErrSignInRefused) {
			if h.Log != nil {
				h.Log.Info("password step refused", "peer_ip", in.PeerIP, "trace_id", apihost.TraceID(ctx))
			}
			return nil, apitypes.SignInFailed("")
		}
		if errors.Is(err, ErrSignInBusy) {
			return nil, apitypes.RateLimited("")
		}
		// A store or key fault fails closed with the same 401 (threat model §7.6 rule 2d).
		if h.Log != nil {
			h.Log.Error("password step failed", "error", err.Error(), "peer_ip", in.PeerIP, "trace_id", apihost.TraceID(ctx))
		}
		return nil, apitypes.SignInFailed("")
	}
	return api.SignInBreakGlassPassword204{SetCookie: line}, nil
}

// WebAuthnCookieVerifier is the HTTP-facing shape of the AN-10 WebAuthn step, like TOTPCookieVerifier:
// both take the pending cookie's value. httpx/authnhttp implements it.
type WebAuthnCookieVerifier interface {
	BeginWebAuthnCookie(ctx context.Context, pendingCookie string) (WebAuthnOptions, error)
	VerifyWebAuthnCookie(ctx context.Context, pendingCookie string, in WebAuthnAssertion, from netip.Addr) (CreateResult, []string, error)
}

// refusedAsSignInFailed maps every way AN-10 can say no to the one uniform 401; anything else is an
// infrastructure fault and goes to the chain, which answers 500 without detail.
func (h Handlers) refusedAsSignInFailed(ctx context.Context, err error, peer string) error {
	if errors.Is(err, ErrPendingInvalid) || errors.Is(err, ErrSecondFactorRefused) {
		if h.Log != nil {
			h.Log.Info("second factor refused", "peer_ip", peer, "trace_id", apihost.TraceID(ctx))
		}
		return apitypes.SignInFailed("")
	}
	return err
}

// CreateWebAuthnSignInChallenge is AN-10 step one for WebAuthn: the request options for the pending
// sign-in the cookie names.
func (h Handlers) CreateWebAuthnSignInChallenge(ctx context.Context, in api.CreateWebAuthnSignInChallengeInput) (api.CreateWebAuthnSignInChallengeOutput, error) {
	if h.WebAuthn == nil {
		return nil, apitypes.NotImplemented("")
	}
	opts, err := h.WebAuthn.BeginWebAuthnCookie(ctx, in.HostAdiqPending.Reveal())
	if err != nil {
		return nil, h.refusedAsSignInFailed(ctx, err, in.PeerIP)
	}
	body := api.WebAuthnChallenge{Challenge: opts.Challenge, RpID: opts.RPID, TimeoutMs: opts.TimeoutMS,
		UserVerification: api.WebAuthnUserVerification(opts.UserVerification), AllowCredentials: []api.WebAuthnCredentialDescriptor{}}
	for _, id := range opts.AllowCredentials {
		body.AllowCredentials = append(body.AllowCredentials, api.WebAuthnCredentialDescriptor{ID: id, Type: api.WebAuthnCredentialTypePublicKey})
	}
	return api.CreateWebAuthnSignInChallenge200{Body: body}, nil
}

// VerifyWebAuthnSignIn is AN-10 step two for WebAuthn. Like VerifyTOTPSignIn, every failure is the same 401.
func (h Handlers) VerifyWebAuthnSignIn(ctx context.Context, in api.VerifyWebAuthnSignInInput) (api.VerifyWebAuthnSignInOutput, error) {
	if h.WebAuthn == nil {
		return nil, apitypes.NotImplemented("")
	}
	a := WebAuthnAssertion{CredentialID: in.Body.CredentialID, AuthenticatorData: in.Body.AuthenticatorData,
		ClientDataJSON: in.Body.ClientDataJSON, Signature: in.Body.Signature}
	if in.Body.UserHandle != nil {
		a.UserHandle = *in.Body.UserHandle
	}
	from, _ := netip.ParseAddr(in.PeerIP)
	_, lines, err := h.WebAuthn.VerifyWebAuthnCookie(ctx, in.HostAdiqPending.Reveal(), a, from)
	if err != nil {
		return nil, h.refusedAsSignInFailed(ctx, err, in.PeerIP)
	}
	return api.VerifyWebAuthnSignIn204{SetCookie: lines}, nil
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

// CSRFHeader is the request header the console sends the CSRF value in; it names the header in the
// GET /auth/csrf answer and is the one authnhttp.CSRFHeader checks.
const CSRFHeader = "X-CSRF-Token"

// GetCSRFToken answers the calling session's CSRF value. The Authenticator derived it from the session
// token, which never reaches a handler. Only a cookie session has one: any other principal, or none, is
// the same 401 as a missing session, with no value.
func (Handlers) GetCSRFToken(ctx context.Context, _ api.GetCSRFTokenInput) (api.GetCSRFTokenOutput, error) {
	p, ok := apihost.PrincipalFrom(ctx)
	if !ok || p.Kind != apihost.KindSession || p.CSRF == "" {
		return nil, apitypes.Unauthenticated("")
	}
	return api.GetCSRFToken200{Body: api.CsrfValue{Header: CSRFHeader, Value: p.CSRF}}, nil
}

// ReverifyStepUp is the step-up re-verification (TM-D16). Its handler is T-0437; until then it answers 501
// so no behaviour is faked. Request.FreshStepUp comes only from StepUp.Fresh, never from the request.
func (Handlers) ReverifyStepUp(context.Context, api.ReverifyStepUpInput) (api.ReverifyStepUpOutput, error) {
	return nil, apitypes.NotImplemented("")
}

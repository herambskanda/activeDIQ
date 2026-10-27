// Package authnhttp is the HTTP binding of authn (ADR-0004 A6): the __Host- cookie attributes, the CSRF
// value derived from the session token, and the cookie-session Authenticator that apihost's chain calls
// (steps 8 and 9). authn itself holds no net/http import, because a kernel package that serves API is a
// handler package and only apihost and generated code may touch the request.
package authnhttp

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/authn"
)

const (
	// CookieName is the console session cookie. The __Host- prefix makes browsers accept it only
	// Secure, with Path=/ and no Domain (threat model §7.3).
	CookieName = "__Host-adiq_session"
	// CSRFHeader carries the CSRF value on every cookie-session mutation.
	CSRFHeader = "X-CSRF-Token"
)

// SessionCookie is the cookie that hands tok to the browser: __Host- prefix, HttpOnly, Secure,
// SameSite=Strict, Path=/, no Domain. maxAge is the session's absolute lifetime remaining; the
// server-side deadlines decide, the cookie only stops the browser keeping it longer.
func SessionCookie(tok authn.Token, maxAge time.Duration) *http.Cookie {
	return &http.Cookie{Name: CookieName, Value: tok.Reveal(), Path: "/", MaxAge: int(maxAge / time.Second),
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode}
}

// ClearCookie tells the browser to drop the session cookie, with the same attributes so the
// __Host- rules accept it.
func ClearCookie() *http.Cookie {
	return &http.Cookie{Name: CookieName, Value: "", Path: "/", MaxAge: -1,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode}
}

// CSRFValue is the CSRF value of a session: an HMAC-SHA-256 of a fixed label keyed by the session
// token, so it is bound to the session, needs no storage, changes when the session is rotated, and
// does not reveal the token. It is not a credential on its own.
func CSRFValue(tok authn.Token) string {
	m := hmac.New(sha256.New, []byte(tok.Reveal()))
	m.Write([]byte("activediq csrf v1"))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// SessionResolver is what the authenticator needs of the store.
type SessionResolver interface {
	Lookup(ctx context.Context, tok authn.Token) (authn.Session, error)
}

var _ SessionResolver = (*authn.Store)(nil)

// Authenticator implements apihost.Authenticator for console cookie sessions. Bearer API tokens are
// not its business: a request without the session cookie is unauthenticated here.
type Authenticator struct {
	sessions SessionResolver
	log      *slog.Logger
}

var _ apihost.Authenticator = (*Authenticator)(nil)

// NewAuthenticator builds the cookie-session authenticator. A nil log discards.
func NewAuthenticator(s SessionResolver, log *slog.Logger) (*Authenticator, error) {
	if s == nil {
		return nil, errors.New("authn: authenticator needs a session resolver")
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Authenticator{sessions: s, log: log}, nil
}

// tokenFrom reads the one session cookie. Zero or several cookies of that name are refused: with
// several, which one the browser meant is not knowable.
func tokenFrom(r *http.Request) (authn.Token, bool) {
	var found *http.Cookie
	for _, c := range r.Cookies() {
		if c.Name != CookieName {
			continue
		}
		if found != nil {
			return authn.Token{}, false
		}
		found = c
	}
	if found == nil {
		return authn.Token{}, false
	}
	tok, err := authn.ParseToken(found.Value)
	return tok, err == nil
}

// Authenticate resolves the cookie to a principal. Every way a cookie can fail to name a live session
// (absent, malformed, unknown, expired, revoked, a tenant whose policy cannot be read) is the same
// ErrUnauthenticated, so the answer cannot be used to probe sessions or tenant IDs. The tenant in the
// cookie only selects where Lookup looks; nothing is authorised before Lookup succeeds.
func (a *Authenticator) Authenticate(r *http.Request) (apihost.Principal, error) {
	tok, ok := tokenFrom(r)
	if !ok {
		return apihost.Principal{}, apihost.ErrUnauthenticated
	}
	sess, err := a.sessions.Lookup(r.Context(), tok)
	switch {
	case err == nil:
	case errors.Is(err, authn.ErrSessionNotFound), errors.Is(err, authn.ErrExpired), errors.Is(err, authn.ErrRevoked),
		errors.Is(err, authn.ErrInvalidToken), errors.Is(err, authn.ErrPolicyRead):
		if errors.Is(err, authn.ErrPolicyRead) {
			a.log.Warn("session policy unreadable for a presented token", "trace_id", apihost.TraceID(r.Context()))
		}
		return apihost.Principal{}, apihost.ErrUnauthenticated
	default:
		return apihost.Principal{}, err // an infrastructure failure: the chain refuses, fail closed
	}
	return apihost.Principal{ID: sess.Account, Tenant: sess.Tenant.String(), Kind: apihost.KindSession}, nil
}

// CheckCSRF compares the X-CSRF-Token header with the value derived from the request's own session
// cookie, in constant time. Missing, repeated or wrong headers are all ErrCSRF.
func (a *Authenticator) CheckCSRF(r *http.Request, _ apihost.Principal) error {
	tok, ok := tokenFrom(r)
	vals := r.Header.Values(CSRFHeader)
	if !ok || len(vals) != 1 {
		return apihost.ErrCSRF
	}
	if !hmac.Equal([]byte(vals[0]), []byte(CSRFValue(tok))) {
		return apihost.ErrCSRF
	}
	return nil
}

// PendingCookie is the cookie that hands h to the browser: __Host-, HttpOnly, Secure,
// SameSite=Strict, Path=/, no Domain, living no longer than the record.
func PendingCookie(h authn.PendingHandle) *http.Cookie {
	return &http.Cookie{Name: authn.PendingCookieName, Value: h.Reveal(), Path: "/", MaxAge: int(authn.PendingSignInTTL / time.Second),
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode}
}

// ClearPendingCookie drops the pending cookie, with the attributes the __Host- rules need.
func ClearPendingCookie() *http.Cookie {
	return &http.Cookie{Name: authn.PendingCookieName, Value: "", Path: "/", MaxAge: -1,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode}
}

// PendingHandleFromRequest reads the handle from the request's cookie and from nowhere else: a handle
// in the URL or the body is ignored, so it is "no pending sign-in". Zero or several cookies of that
// name are refused.
func PendingHandleFromRequest(r *http.Request) (authn.PendingHandle, error) {
	var found *http.Cookie
	for _, c := range r.Cookies() {
		if c.Name != authn.PendingCookieName {
			continue
		}
		if found != nil {
			return authn.PendingHandle{}, authn.ErrPendingInvalid
		}
		found = c
	}
	if found == nil {
		return authn.PendingHandle{}, authn.ErrPendingInvalid
	}
	return authn.ParsePendingHandle(found.Value)
}

// TOTPVerifier is what VerifyTOTPRequest needs of authn.SecondFactor.
type TOTPVerifier interface {
	VerifyTOTP(ctx context.Context, h authn.PendingHandle, code string, from netip.Addr) (authn.CreateResult, error)
}

var _ TOTPVerifier = (*authn.SecondFactor)(nil)

// VerifyTOTPRequest is the AN-10 TOTP entry for an HTTP request: the handle comes from the pending
// cookie only. On success it returns the session and the two cookies to set: the new session cookie
// and the cleared pending cookie. from is the client address the caller resolved (trusted-proxy rules
// are the HTTP host's, not this package's).
func VerifyTOTPRequest(ctx context.Context, f TOTPVerifier, r *http.Request, code string, from netip.Addr) (authn.CreateResult, []*http.Cookie, error) {
	h, err := PendingHandleFromRequest(r)
	if err != nil {
		return authn.CreateResult{}, nil, err
	}
	return verifyTOTPHandle(ctx, f, h, code, from)
}

// verifyTOTPHandle runs the verification and, on success, builds the two cookies to set.
func verifyTOTPHandle(ctx context.Context, f TOTPVerifier, h authn.PendingHandle, code string, from netip.Addr) (authn.CreateResult, []*http.Cookie, error) {
	res, err := f.VerifyTOTP(ctx, h, code, from)
	if err != nil {
		return authn.CreateResult{}, nil, err
	}
	return res, []*http.Cookie{SessionCookie(res.Token, time.Until(res.Session.AbsoluteExpiry)), ClearPendingCookie()}, nil
}

// TOTPCookies adapts a TOTPVerifier to authn.TOTPCookieVerifier, the shape authn.Handlers takes: it
// is where the cookie attributes meet the generated Input of verifyTotpSignIn.
type TOTPCookies struct{ Factor TOTPVerifier }

var _ authn.TOTPCookieVerifier = TOTPCookies{}

// VerifyTOTPCookie is VerifyTOTPRequest for a caller that already holds the one pending cookie's
// value. An empty or malformed value is ErrPendingInvalid. It returns the Set-Cookie lines: the new
// session cookie, then the clearing pending cookie. from is the client address the caller resolved;
// the zero Addr only when genuinely unknown.
func (c TOTPCookies) VerifyTOTPCookie(ctx context.Context, pendingCookie, code string, from netip.Addr) (authn.CreateResult, []string, error) {
	h, err := authn.ParsePendingHandle(pendingCookie)
	if err != nil {
		return authn.CreateResult{}, nil, authn.ErrPendingInvalid
	}
	res, cookies, err := verifyTOTPHandle(ctx, c.Factor, h, code, from)
	if err != nil {
		return authn.CreateResult{}, nil, err
	}
	lines := make([]string, 0, len(cookies))
	for _, ck := range cookies {
		lines = append(lines, ck.String())
	}
	return res, lines, nil
}

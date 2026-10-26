package authn

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
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
func SessionCookie(tok Token, maxAge time.Duration) *http.Cookie {
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
func CSRFValue(tok Token) string {
	m := hmac.New(sha256.New, []byte(tok.text))
	m.Write([]byte("activediq csrf v1"))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// SessionResolver is what the authenticator needs of the store.
type SessionResolver interface {
	Lookup(ctx context.Context, tok Token) (Session, error)
}

var _ SessionResolver = (*Store)(nil)

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
func tokenFrom(r *http.Request) (Token, bool) {
	var found *http.Cookie
	for _, c := range r.Cookies() {
		if c.Name != CookieName {
			continue
		}
		if found != nil {
			return Token{}, false
		}
		found = c
	}
	if found == nil {
		return Token{}, false
	}
	tok, err := ParseToken(found.Value)
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
	case errors.Is(err, ErrSessionNotFound), errors.Is(err, ErrExpired), errors.Is(err, ErrRevoked),
		errors.Is(err, ErrInvalidToken), errors.Is(err, ErrPolicyRead):
		if errors.Is(err, ErrPolicyRead) {
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

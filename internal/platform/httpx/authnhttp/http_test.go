package authnhttp

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/authn"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

type fakeResolver struct {
	err  error
	sess authn.Session
	got  authn.Token
}

func (f *fakeResolver) Lookup(_ context.Context, tok authn.Token) (authn.Session, error) {
	f.got = tok
	return f.sess, f.err
}

// randSecret is 32 random bytes in the token's encoding, so two tokens differ.
func randSecret(t *testing.T) string {
	t.Helper()
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}

func mustToken(t *testing.T) (authn.Token, tenant.ID) {
	t.Helper()
	ten := tenant.New()
	tok, err := authn.ParseToken(ten.String() + "." + randSecret(t))
	if err != nil {
		t.Fatal(err)
	}
	return tok, ten
}

func TestCookieAttributes(t *testing.T) {
	tok, _ := mustToken(t)
	c := SessionCookie(tok, 0)
	if !strings.HasPrefix(c.Name, "__Host-") || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode || c.Path != "/" || c.Domain != "" {
		t.Fatalf("cookie = %+v", c)
	}
	line := c.String()
	for _, want := range []string{"__Host-", "HttpOnly", "Secure", "SameSite=Strict", "Path=/"} {
		if !strings.Contains(line, want) {
			t.Errorf("%q missing from %q", want, line)
		}
	}
	if strings.Contains(line, "Domain") {
		t.Errorf("Domain in %q", line)
	}
	clr := ClearCookie()
	if clr.MaxAge >= 0 || clr.Name != CookieName || !clr.Secure || clr.Path != "/" || clr.Domain != "" {
		t.Fatalf("clear cookie = %+v", clr)
	}
}

func req(tok string, csrf ...string) *http.Request {
	r := httptest.NewRequest("POST", "/api/v1/x", nil)
	if tok != "" {
		r.AddCookie(&http.Cookie{Name: CookieName, Value: tok})
	}
	for _, v := range csrf {
		r.Header.Add(CSRFHeader, v)
	}
	return r
}

func TestCSRFValueAndCheck(t *testing.T) {
	tok, _ := mustToken(t)
	other, _ := mustToken(t)
	a, _ := NewAuthenticator(&fakeResolver{}, nil)
	good := CSRFValue(tok)
	if good == CSRFValue(other) || strings.Contains(good, tok.Reveal()[37:]) {
		t.Fatal("CSRF value not session-bound or leaks the token")
	}
	if err := a.CheckCSRF(req(tok.Reveal(), good), apihost.Principal{}); err != nil {
		t.Fatalf("good value refused: %v", err)
	}
	for name, r := range map[string]*http.Request{
		"missing":    req(tok.Reveal()),
		"wrong":      req(tok.Reveal(), "AAAA"),
		"other":      req(tok.Reveal(), CSRFValue(other)),
		"empty":      req(tok.Reveal(), ""),
		"repeated":   req(tok.Reveal(), good, good),
		"no cookie":  req("", good),
		"bad cookie": req("nope", good),
	} {
		if err := a.CheckCSRF(r, apihost.Principal{}); !errors.Is(err, apihost.ErrCSRF) {
			t.Errorf("%s: err = %v, want ErrCSRF", name, err)
		}
	}
}

func TestAuthenticateMapsEveryFailureToUnauthenticated(t *testing.T) {
	tok, ten := mustToken(t)
	for _, e := range []error{authn.ErrSessionNotFound, authn.ErrExpired, authn.ErrRevoked, authn.ErrInvalidToken,
		errors.Join(authn.ErrPolicyRead, errors.New("unknown tenant"))} {
		a, _ := NewAuthenticator(&fakeResolver{err: e}, nil)
		if _, err := a.Authenticate(req(tok.Reveal())); !errors.Is(err, apihost.ErrUnauthenticated) {
			t.Errorf("%v -> %v, want ErrUnauthenticated", e, err)
		}
	}
	for name, r := range map[string]*http.Request{
		"no cookie": req(""),
		"malformed": req("garbage"),
		"two cookies": func() *http.Request {
			r := req(tok.Reveal())
			r.AddCookie(&http.Cookie{Name: CookieName, Value: tok.Reveal()})
			return r
		}(),
	} {
		f := &fakeResolver{}
		a, _ := NewAuthenticator(f, nil)
		if _, err := a.Authenticate(r); !errors.Is(err, apihost.ErrUnauthenticated) {
			t.Errorf("%s: %v", name, err)
		}
		if f.got.Reveal() != "" {
			t.Errorf("%s: Lookup was called", name)
		}
	}
	// Infrastructure failure is not a 401.
	boom := errors.New("db down")
	a, _ := NewAuthenticator(&fakeResolver{err: boom}, nil)
	if _, err := a.Authenticate(req(tok.Reveal())); !errors.Is(err, boom) || errors.Is(err, apihost.ErrUnauthenticated) {
		t.Errorf("infra err = %v", err)
	}
	// Success.
	acct := tenant.New().String()
	a, _ = NewAuthenticator(&fakeResolver{sess: authn.Session{ID: "sess-1", Account: acct, Tenant: ten}}, nil)
	p, err := a.Authenticate(req(tok.Reveal()))
	if err != nil || p.ID != acct || p.Tenant != ten.String() || p.Kind != apihost.KindSession || p.SessionID != "sess-1" {
		t.Fatalf("principal = %+v, %v", p, err)
	}
}

func TestNewAuthenticatorNeedsResolver(t *testing.T) {
	if _, err := NewAuthenticator(nil, nil); err == nil {
		t.Fatal("nil resolver accepted")
	}
}

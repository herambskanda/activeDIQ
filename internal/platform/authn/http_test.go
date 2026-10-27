package authn

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

type fakeResolver struct {
	err  error
	sess Session
	got  Token
}

func (f *fakeResolver) Lookup(_ context.Context, tok Token) (Session, error) {
	f.got = tok
	return f.sess, f.err
}

func mustToken(t *testing.T) (Token, tenant.ID) {
	t.Helper()
	ten := tenant.New()
	tok, err := newToken(ten)
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
	for _, e := range []error{ErrSessionNotFound, ErrExpired, ErrRevoked, ErrInvalidToken,
		errors.Join(ErrPolicyRead, errors.New("unknown tenant"))} {
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
		if f.got.text != "" {
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
	a, _ = NewAuthenticator(&fakeResolver{sess: Session{Account: acct, Tenant: ten}}, nil)
	p, err := a.Authenticate(req(tok.Reveal()))
	if err != nil || p.ID != acct || p.Tenant != ten.String() || p.Kind != apihost.KindSession {
		t.Fatalf("principal = %+v, %v", p, err)
	}
}

func TestNewAuthenticatorNeedsResolver(t *testing.T) {
	if _, err := NewAuthenticator(nil, nil); err == nil {
		t.Fatal("nil resolver accepted")
	}
}

func TestRotateKillsOldTokenAndChangesCSRF(t *testing.T) {
	each(t, func(t *testing.T, e *sessEnv) {
		s := e.node(t, pol)
		ctx := context.Background()
		acct := e.account(t)
		old := create(t, s, e.ten, acct)
		nu, err := s.Rotate(ctx, old.Token, ReasonRoleChanged)
		if err != nil {
			t.Fatalf("Rotate: %v", err)
		}
		if _, err := s.Lookup(ctx, old.Token); !errors.Is(err, ErrRevoked) {
			t.Fatalf("old token Lookup = %v, want ErrRevoked", err)
		}
		got, err := s.Lookup(ctx, nu.Token)
		if err != nil || got.Account != acct {
			t.Fatalf("new token Lookup = %+v, %v", got, err)
		}
		if CSRFValue(old.Token) == CSRFValue(nu.Token) {
			t.Fatal("CSRF value survived rotation")
		}
		if _, err := s.Rotate(ctx, old.Token, ReasonRoleChanged); !errors.Is(err, ErrRevoked) {
			t.Fatalf("second Rotate of the old token = %v, want ErrRevoked", err)
		}
	})
}

func TestRotateKeepsAbsoluteDeadline(t *testing.T) {
	each(t, func(t *testing.T, e *sessEnv) {
		e.skewClock(t)
		s := e.node(t, pol)
		ctx := context.Background()
		cur := create(t, s, e.ten, e.account(t))
		abs := cur.Session.AbsoluteExpiry
		var err error
		for i := 0; i < 20; i++ {
			e.clk.advance(5 * time.Minute)
			prev := cur
			if cur, err = s.Rotate(ctx, prev.Token, ReasonOnDemand); err != nil {
				if !e.clk.now().Before(abs) && (errors.Is(err, ErrExpired) || errors.Is(err, ErrRevoked)) {
					return // ended no later than the original deadline
				}
				t.Fatalf("Rotate #%d at %v (abs %v): %v", i, e.clk.now(), abs, err)
			}
			if !cur.Session.AbsoluteExpiry.Equal(abs) || !cur.Session.CreatedAt.Equal(prev.Session.CreatedAt) {
				t.Fatalf("rotation moved the window: abs %v->%v created %v->%v", abs, cur.Session.AbsoluteExpiry, prev.Session.CreatedAt, cur.Session.CreatedAt)
			}
			if !e.clk.now().Before(abs) {
				t.Fatalf("rotation succeeded at %v past the original deadline %v", e.clk.now(), abs)
			}
		}
		t.Fatal("session survived 100m of rotation under a 1h absolute limit")
	})
}

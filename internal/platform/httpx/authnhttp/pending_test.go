package authnhttp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/authn"
)

type fakeFactor struct {
	calls int
	res   authn.CreateResult
	err   error
}

func (f *fakeFactor) VerifyTOTP(context.Context, authn.PendingHandle, string, netip.Addr) (authn.CreateResult, error) {
	f.calls++
	return f.res, f.err
}

func pendingHandle(t *testing.T) authn.PendingHandle {
	t.Helper()
	tok, _ := mustToken(t) // same shape: <tenant>.<43 chars>
	h, err := authn.ParsePendingHandle(tok.Reveal())
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func Test_pending_cookie_only(t *testing.T) {
	h := pendingHandle(t)
	tok, _ := mustToken(t)
	code := "123456"
	f := &fakeFactor{res: authn.CreateResult{Token: tok}}
	ctx := context.Background()

	// In the URL, in the body, in a header, under another cookie name: all "no pending sign-in".
	req := httptest.NewRequest(http.MethodPost, "/auth/second-factor/totp/verify?pending="+h.Reveal()+"&"+authn.PendingCookieName+"="+h.Reveal(),
		strings.NewReader(`{"code":"`+code+`","pending":"`+h.Reveal()+`"}`))
	req.Header.Set("X-Pending", h.Reveal())
	req.AddCookie(&http.Cookie{Name: "adiq_pending", Value: h.Reveal()})
	req.AddCookie(&http.Cookie{Name: CookieName, Value: h.Reveal()})
	if _, _, err := VerifyTOTPRequest(ctx, f, req, code, netip.Addr{}); !errors.Is(err, authn.ErrPendingInvalid) {
		t.Fatalf("handle outside the cookie: got %v, want ErrPendingInvalid", err)
	}
	bad := httptest.NewRequest(http.MethodPost, "/", nil)
	bad.AddCookie(&http.Cookie{Name: authn.PendingCookieName, Value: "junk"})
	if _, _, err := VerifyTOTPRequest(ctx, f, bad, code, netip.Addr{}); !errors.Is(err, authn.ErrPendingInvalid) {
		t.Fatalf("malformed: %v", err)
	}
	two := httptest.NewRequest(http.MethodPost, "/", nil)
	two.AddCookie(&http.Cookie{Name: authn.PendingCookieName, Value: h.Reveal()})
	two.AddCookie(&http.Cookie{Name: authn.PendingCookieName, Value: h.Reveal()})
	if _, _, err := VerifyTOTPRequest(ctx, f, two, code, netip.Addr{}); !errors.Is(err, authn.ErrPendingInvalid) {
		t.Fatalf("two cookies: %v", err)
	}
	if f.calls != 0 {
		t.Fatalf("verifier called %d times for refused requests, want 0", f.calls)
	}

	ok := httptest.NewRequest(http.MethodPost, "/", nil)
	ok.AddCookie(&http.Cookie{Name: authn.PendingCookieName, Value: h.Reveal()})
	f.res.Session.AbsoluteExpiry = time.Now().Add(time.Hour)
	res, cookies, err := VerifyTOTPRequest(ctx, f, ok, code, netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	if f.calls != 1 || len(cookies) != 2 || cookies[0].Name != CookieName || cookies[0].Value != res.Token.Reveal() ||
		cookies[1].Name != authn.PendingCookieName || cookies[1].MaxAge >= 0 {
		t.Fatalf("cookies = %+v", cookies)
	}
	pc := PendingCookie(h)
	if pc.Name != "__Host-adiq_pending" || !pc.Secure || !pc.HttpOnly || pc.SameSite != http.SameSiteStrictMode || pc.Path != "/" || pc.Domain != "" || pc.MaxAge != 300 {
		t.Fatalf("pending cookie = %+v", pc)
	}
}

func Test_TOTPCookies_adapter_renders_set_cookie_lines(t *testing.T) {
	h := pendingHandle(t)
	tok, _ := mustToken(t)
	f := &fakeFactor{res: authn.CreateResult{Token: tok}}
	f.res.Session.AbsoluteExpiry = time.Now().Add(time.Hour)
	c := TOTPCookies{Factor: f}
	ctx := context.Background()

	if _, _, err := c.VerifyTOTPCookie(ctx, "junk", "123456", netip.Addr{}); !errors.Is(err, authn.ErrPendingInvalid) {
		t.Fatalf("malformed: %v", err)
	}
	if _, _, err := c.VerifyTOTPCookie(ctx, "", "123456", netip.Addr{}); !errors.Is(err, authn.ErrPendingInvalid) {
		t.Fatalf("empty: %v", err)
	}
	if f.calls != 0 {
		t.Fatalf("verifier called %d times for refused cookies", f.calls)
	}
	_, lines, err := c.VerifyTOTPCookie(ctx, h.Reveal(), "123456", netip.Addr{})
	if err != nil || len(lines) != 2 {
		t.Fatalf("lines = %q, err = %v", lines, err)
	}
	sess, _ := http.ParseSetCookie(lines[0])
	clr, _ := http.ParseSetCookie(lines[1])
	if sess.Name != CookieName || sess.Value != tok.Reveal() || !sess.Secure || !sess.HttpOnly || sess.SameSite != http.SameSiteStrictMode || sess.Path != "/" || sess.Domain != "" {
		t.Fatalf("session cookie = %+v", sess)
	}
	if clr.Name != authn.PendingCookieName || clr.Value != "" || clr.MaxAge >= 0 || !clr.Secure || clr.Path != "/" || clr.Domain != "" {
		t.Fatalf("clearing cookie = %+v", clr)
	}
}

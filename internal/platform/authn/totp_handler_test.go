package authn

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/apihost/apitypes"
	"github.com/skenzeriq/activediq/internal/platform/authn/api"
	"github.com/skenzeriq/activediq/internal/platform/secret"
)

func totpInput(pending, code string) api.VerifyTOTPSignInInput {
	return api.VerifyTOTPSignInInput{HostAdiqPending: pending, PeerIP: "192.0.2.7",
		Body: api.TotpCodeRequest{Code: secret.FromBytes([]byte(code))}}
}

// AN-10 acceptance 1: a pending cookie and a correct code give 204 with a session cookie and a
// clearing pending cookie, as two Set-Cookie lines.
func Test_verify_totp_handler_sets_session_and_clears_pending(t *testing.T) {
	eachPending(t, func(t *testing.T, e *pendEnv) {
		h := e.begin(t)
		hd := Handlers{SecondFactor: e.sf}
		out, err := hd.VerifyTOTPSignIn(context.Background(), totpInput(h.Reveal(), e.good()))
		if err != nil {
			t.Fatal(err)
		}
		o, ok := out.(api.VerifyTOTPSignIn204)
		if !ok || o.StatusCode() != 204 || o.ResponseBody() != nil {
			t.Fatalf("out = %#v", out)
		}
		if len(o.SetCookie) != 2 {
			t.Fatalf("Set-Cookie lines = %q", o.SetCookie)
		}
		sess, err := http.ParseSetCookie(o.SetCookie[0])
		if err != nil {
			t.Fatal(err)
		}
		clr, err := http.ParseSetCookie(o.SetCookie[1])
		if err != nil {
			t.Fatal(err)
		}
		if sess.Name != CookieName || sess.Value == "" || !sess.Secure || !sess.HttpOnly || sess.SameSite != http.SameSiteStrictMode || sess.Path != "/" || sess.Domain != "" {
			t.Fatalf("session cookie = %+v", sess)
		}
		if clr.Name != PendingCookieName || clr.Value != "" || clr.MaxAge >= 0 || !clr.Secure || clr.Path != "/" || clr.Domain != "" {
			t.Fatalf("clearing cookie = %+v", clr)
		}
		if n := e.sessions(t); n != 1 {
			t.Fatalf("%d sessions, want 1", n)
		}
		// The pending sign-in is spent: replay is the same 401.
		_, err = hd.VerifyTOTPSignIn(context.Background(), totpInput(h.Reveal(), e.good()))
		wantSignInFailed(t, err)
	})
}

// AN-10 acceptance 2: no cookie (the handle only in the body or elsewhere), a malformed cookie, a
// wrong code: all the same 401 as any sign-in failure, and no session.
func Test_verify_totp_handler_failures_are_one_401(t *testing.T) {
	eachPending(t, func(t *testing.T, e *pendEnv) {
		h := e.begin(t)
		hd := Handlers{SecondFactor: e.sf}
		ctx := context.Background()
		_, err := hd.VerifyTOTPSignIn(ctx, totpInput("", e.good()))
		wantSignInFailed(t, err)
		_, err = hd.VerifyTOTPSignIn(ctx, totpInput("junk", e.good()))
		wantSignInFailed(t, err)
		_, err = hd.VerifyTOTPSignIn(ctx, totpInput(h.Reveal(), e.bad()))
		wantSignInFailed(t, err)
		if n := e.sessions(t); n != 0 {
			t.Fatalf("%d sessions after refusals, want none", n)
		}
		if strings.Contains(err.Error(), h.Reveal()) {
			t.Fatal("the error carries the handle")
		}
	})
}

func Test_verify_totp_handler_unwired_is_501(t *testing.T) {
	_, err := Handlers{}.VerifyTOTPSignIn(context.Background(), totpInput("x", "123456"))
	var p *apitypes.Problem
	if !errors.As(err, &p) || p.Status != 501 {
		t.Fatalf("err = %v", err)
	}
}

func wantSignInFailed(t *testing.T, err error) {
	t.Helper()
	var p *apitypes.Problem
	if !errors.As(err, &p) || p.Status != 401 || p.Type != apitypes.ProblemTypeSignInFailed || p.Detail != nil {
		t.Fatalf("err = %v, want the sign-in-failed 401", err)
	}
}

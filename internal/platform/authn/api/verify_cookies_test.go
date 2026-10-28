package api_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/authn/api"
)

// Both AN-10 verify operations send two Set-Cookie lines (set session, clear pending), built from
// typed http.Cookie values, never hand-built header strings.
func TestVerifySignInCarriesTwoTypedSetCookieLines(t *testing.T) {
	sess := &http.Cookie{Name: "__Host-adiq_session", Value: "tok", Path: "/", MaxAge: 3600, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode}
	clr := &http.Cookie{Name: "__Host-adiq_pending", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode}
	lines := []string{sess.String(), clr.String()}
	for name, resp := range map[string]interface {
		ResponseHeaderLists() map[string][]string
	}{
		"webauthn": api.VerifyWebAuthnSignIn204{SetCookie: lines},
		"totp":     api.VerifyTOTPSignIn204{SetCookie: lines},
	} {
		got := resp.ResponseHeaderLists()["Set-Cookie"]
		if len(got) != 2 {
			t.Fatalf("%s: Set-Cookie lines = %d, want 2", name, len(got))
		}
		for i, wantName := range []string{"__Host-adiq_session=", "__Host-adiq_pending="} {
			if !strings.HasPrefix(got[i], wantName) {
				t.Errorf("%s: line %d = %q, want prefix %s", name, i, got[i], wantName)
			}
			for _, attr := range []string{"Secure", "HttpOnly", "SameSite=Strict", "Path=/"} {
				if !strings.Contains(got[i], attr) {
					t.Errorf("%s: line %d lacks %s: %q", name, i, attr, got[i])
				}
			}
			if strings.Contains(got[i], "Domain=") {
				t.Errorf("%s: line %d has Domain (breaks __Host-)", name, i)
			}
		}
	}
}

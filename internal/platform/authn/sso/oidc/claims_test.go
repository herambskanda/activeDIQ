package oidc

import (
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/authn/sso"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

type claimCase struct {
	name   string
	edit   map[string]any
	reason string // "" means accepted
}

func runClaims(t *testing.T, intent sso.Intent, cases []claimCase) {
	t.Helper()
	for _, c := range cases {
		h := newHarness(t)
		_, err := h.flow(intent, h.goodToken(c.edit), nil)
		if got := sso.ReasonOf(err); got != c.reason || (c.reason == "" && err != nil) {
			t.Errorf("%s: err = %v, want reason %q", c.name, err, c.reason)
		}
	}
}

// OIDC-10
func TestOIDC_RefusesIssuer(t *testing.T) {
	runClaims(t, sso.IntentSignin, []claimCase{
		{"other issuer", map[string]any{"iss": "https://evil.test"}, ReasonIss},
		{"trailing slash", map[string]any{"iss": issuer + "/"}, ReasonIss},
		{"missing", map[string]any{"iss": nil}, ReasonIss},
		{"not a string", map[string]any{"iss": 7}, ReasonIss},
		{"exact", nil, ""},
	})
	const tid = "11111111-2222-3333-4444-555555555555"
	entra := "https://login.microsoftonline.com/" + tid + "/v2.0"
	h := newHarness(t)
	h.cfg.Issuer, h.cfg.Discovery.Issuer, h.cfg.EntraTenantID = entra, entra, tid
	if _, err := h.flow(sso.IntentSignin, h.goodToken(map[string]any{"iss": entra, "tid": tid}), nil); err != nil {
		t.Fatalf("entra: %v", err)
	}
	_, err := h.flow(sso.IntentSignin, h.goodToken(map[string]any{"iss": entra, "tid": "99999999-2222-3333-4444-555555555555"}), nil)
	wantReason(t, err, ReasonIss)
	_, err = h.flow(sso.IntentSignin, h.goodToken(map[string]any{"iss": entra}), nil)
	wantReason(t, err, ReasonIss)
	for _, bad := range []string{
		"https://login.microsoftonline.com/common/v2.0", "https://login.microsoftonline.com/organizations/v2.0",
		"https://login.microsoftonline.com/consumers/v2.0", "https://login.microsoftonline.com/" + tid, "https://login.microsoftonline.com/other/v2.0",
	} {
		h = newHarness(t)
		h.cfg.Issuer, h.cfg.Discovery.Issuer, h.cfg.EntraTenantID = bad, bad, tid
		_, _, err = h.v.Start(t.Context(), tenant.New(), h.idp(), sso.IntentSignin)
		if sso.ReasonOf(err) != ReasonIss {
			t.Errorf("%s: err = %v", bad, err)
		}
	}
}

// OIDC-11
func TestOIDC_RefusesAudience(t *testing.T) {
	runClaims(t, sso.IntentSignin, []claimCase{
		{"another client", map[string]any{"aud": "other-client"}, ReasonAud},
		{"extra value", map[string]any{"aud": []string{clientID, "other-client"}}, ReasonAud},
		{"empty list", map[string]any{"aud": []string{}}, ReasonAud},
		{"missing", map[string]any{"aud": nil}, ReasonAud},
		{"number", map[string]any{"aud": 5}, ReasonAud},
		{"azp mismatch", map[string]any{"azp": "other-client"}, ReasonAud},
		{"azp not a string", map[string]any{"azp": 1}, ReasonAud},
		{"list of one", map[string]any{"aud": []string{clientID}}, ""},
		{"azp equal", map[string]any{"azp": clientID}, ""},
	})
}

// OIDC-12
func TestOIDC_RefusesNonce(t *testing.T) {
	runClaims(t, sso.IntentSignin, []claimCase{
		{"missing", map[string]any{"nonce": nil}, ReasonNonce},
		{"another transaction", map[string]any{"nonce": "nonce-of-another-browser"}, ReasonNonce},
		{"empty", map[string]any{"nonce": ""}, ReasonNonce},
		{"not a string", map[string]any{"nonce": 1}, ReasonNonce},
	})
}

// OIDC-13: skew is 120 s.
func TestOIDC_RefusesTime(t *testing.T) {
	n := baseTime
	u := func(d time.Duration) int64 { return n.Add(d).Unix() }
	runClaims(t, sso.IntentSignin, []claimCase{
		{"expired", map[string]any{"exp": u(-121 * time.Second)}, ReasonTime},
		{"expired within skew", map[string]any{"exp": u(-100 * time.Second)}, ""},
		{"exp missing", map[string]any{"exp": nil}, ReasonTime},
		{"exp a string", map[string]any{"exp": "9999999999"}, ReasonTime},
		{"exp absurd", map[string]any{"exp": 1e15}, ReasonTime},
		{"iat missing", map[string]any{"iat": nil}, ReasonTime},
		{"iat older than 10 min", map[string]any{"iat": u(-11 * time.Minute)}, ReasonTime},
		{"iat 9 min old", map[string]any{"iat": u(-9 * time.Minute), "exp": u(time.Hour)}, ""},
		{"iat in the future", map[string]any{"iat": u(3 * time.Minute)}, ReasonTime},
		{"nbf in the future", map[string]any{"nbf": u(3 * time.Minute)}, ReasonTime},
		{"nbf within skew", map[string]any{"nbf": u(100 * time.Second)}, ""},
		{"nbf not a number", map[string]any{"nbf": "x"}, ReasonTime},
	})
}

// OIDC-14
func TestOIDC_RefusesSubject(t *testing.T) {
	runClaims(t, sso.IntentSignin, []claimCase{
		{"missing", map[string]any{"sub": nil}, ReasonSub},
		{"empty", map[string]any{"sub": ""}, ReasonSub},
		{"256 bytes", map[string]any{"sub": strings.Repeat("a", 256)}, ReasonSub},
		{"not a string", map[string]any{"sub": 12}, ReasonSub},
		{"255 bytes", map[string]any{"sub": strings.Repeat("a", 255)}, ""},
	})
}

// OIDC-15
func TestOIDC_RefusesStaleStepup(t *testing.T) {
	at := func(d time.Duration) int64 { return baseTime.Add(d).Unix() }
	runClaims(t, sso.IntentStepup, []claimCase{
		{"auth_time absent", nil, ReasonStale},
		{"older than 120 s", map[string]any{"auth_time": at(-121 * time.Second)}, ReasonStale},
		{"in the future", map[string]any{"auth_time": at(5 * time.Minute)}, ReasonStale},
		{"not a number", map[string]any{"auth_time": "now"}, ReasonStale},
		{"fresh", map[string]any{"auth_time": at(-30 * time.Second)}, ""},
	})
	// A plain sign-in does not need auth_time.
	runClaims(t, sso.IntentSignin, []claimCase{{"signin without auth_time", nil, ""}})

	h := newHarness(t)
	u, _, err := h.v.Start(t.Context(), tenant.New(), h.idp(), sso.IntentStepup)
	if err != nil {
		t.Fatal(err)
	}
	if q := u.Query(); q.Get("prompt") != "login" || q.Get("max_age") != "0" {
		t.Errorf("step-up did not force re-authentication: %v", q)
	}
}

// OIDC-16: claims come from the ID token only.
func TestOIDC_ClaimsFromIDTokenOnly(t *testing.T) {
	h := newHarness(t)
	h.cfg.GroupClaim = "groups"
	v, err := h.flow(sso.IntentSignin, h.goodToken(map[string]any{
		"hasgroups": true, "_claim_names": map[string]any{"groups": "src1"}, "_claim_sources": map[string]any{"src1": map[string]any{"endpoint": "https://graph.example.test/x"}},
	}), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(v.GroupClaims) != 0 || len(v.Warnings) != 1 || v.Warnings[0] != "oidc.groups_overage" {
		t.Fatalf("overage: %+v", v)
	}
	for path := range h.calls {
		if path != "/token" && path != "/jwks" {
			t.Errorf("unexpected call to %s (UserInfo or a distributed-claim source)", path)
		}
	}
	// A claim of the wrong type yields no groups and a warning, not a partial list.
	v, err = h.flow(sso.IntentSignin, h.goodToken(map[string]any{"groups": []any{"g1", 7}}), nil)
	if err != nil || len(v.GroupClaims) != 0 || len(v.Warnings) != 1 {
		t.Fatalf("malformed groups: %+v %v", v, err)
	}
}

// OIDC-17
func TestOIDC_RefusesChangedDiscovery(t *testing.T) {
	cases := map[string]func(*harness){
		"issuer differs":     func(h *harness) { h.cfg.Discovery.Issuer = "https://evil.test" },
		"http authorization": func(h *harness) { h.cfg.Discovery.AuthorizationEndpoint = "http://idp.example.test/authorize" },
		"http jwks":          func(h *harness) { h.cfg.Discovery.JWKSURI = "http://idp.example.test/jwks" },
		"http issuer":        func(h *harness) { h.cfg.Issuer = "http://idp.example.test"; h.cfg.Discovery.Issuer = h.cfg.Issuer },
		"http redirect":      func(h *harness) { h.cfg.RedirectURI = "http://console.example.test/cb" },
		"empty client":       func(h *harness) { h.cfg.ClientID = "" },
		"endpoint userinfo":  func(h *harness) { h.cfg.Discovery.TokenEndpoint = "https://a:b@idp.example.test/token" },
		"jwks missing":       func(h *harness) { h.cfg.Discovery.JWKSURI = "" },
		"bad mfa evidence":   func(h *harness) { h.cfg.MFAMode, h.cfg.MFAEvidence = "claim", []string{"pwd"} },
		"mfa claim, no rule": func(h *harness) { h.cfg.MFAMode = "claim" },
		"anchor is upn":      func(h *harness) { h.cfg.AnchorClaim = "upn" },
	}
	for name, mod := range cases {
		h := newHarness(t)
		mod(h)
		if _, _, err := h.v.Start(t.Context(), tenant.New(), h.idp(), sso.IntentSignin); sso.ReasonOf(err) == "" {
			t.Errorf("%s: Start accepted the configuration", name)
		}
		if _, err := h.flow2(); sso.ReasonOf(err) == "" {
			t.Errorf("%s: Complete accepted the configuration", name)
		}
	}
	// A disabled IdP refuses at both ends (SSO-2).
	h := newHarness(t)
	idp := h.idp()
	idp.Enabled = false
	if _, _, err := h.v.Start(t.Context(), tenant.New(), idp, sso.IntentSignin); sso.ReasonOf(err) != "sso.idp" {
		t.Errorf("disabled Start: %v", err)
	}
}

// flow2 calls Complete with a transaction that would otherwise pass, to prove config is re-checked there.
func (h *harness) flow2() (sso.Verified, error) {
	tx := sso.Transaction{IdPID: "idp1", Intent: sso.IntentSignin, State: "s", Nonce: "n", Verifier: "v"}
	return h.v.Complete(h.t.Context(), tenant.ID{}, h.idp(), tx, sso.Callback{IdPID: "idp1", Query: map[string][]string{"code": {"c"}, "state": {"s"}}})
}

func TestOIDC_Discover(t *testing.T) {
	h := newHarness(t)
	disc := `{"issuer":"https://idp.example.test","authorization_endpoint":"https://idp.example.test/authorize","token_endpoint":"https://idp.example.test/token","jwks_uri":"https://idp.example.test/jwks","code_challenge_methods_supported":["S256"],"authorization_response_iss_parameter_supported":true}`
	disco := &discoClient{body: disc}
	d, err := Discover(t.Context(), disco, issuer)
	if err != nil || d.Issuer != issuer || !d.IssParamSupported || d.CodeChallengeMethods[0] != "S256" || d.JWKSURI != issuer+"/jwks" {
		t.Fatalf("Discover = %+v %v", d, err)
	}
	if disco.url != issuer+"/.well-known/openid-configuration" {
		t.Errorf("url = %s", disco.url)
	}
	// A document that names another issuer is returned as is and then refused by ValidateConfig.
	h.cfg.Discovery = d
	h.cfg.Discovery.Issuer = "https://evil.test"
	if err := ValidateConfig(&h.cfg); sso.ReasonOf(err) != ReasonConfig {
		t.Errorf("ValidateConfig: %v", err)
	}
	if _, err := Discover(t.Context(), disco, "http://idp.example.test"); sso.ReasonOf(err) != ReasonConfig {
		t.Errorf("http issuer: %v", err)
	}
	if _, err := Discover(t.Context(), &discoClient{body: strings.Repeat("a", 65<<10)}, issuer); sso.ReasonOf(err) != ReasonConfig {
		t.Errorf("oversize: %v", err)
	}
}

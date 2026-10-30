package oidc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json/v2"
	"net/url"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/skenzeriq/activediq/internal/platform/authn/sso"
	"github.com/skenzeriq/activediq/internal/platform/secret"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

func TestOIDC_AcceptsValidResponse(t *testing.T) {
	h := newHarness(t)
	h.cfg.AnchorClaim = "oid"
	h.cfg.MFAMode, h.cfg.MFAEvidence = sso.MFAClaim, []string{"mfa", "hwk"}
	h.cfg.GroupClaim = "groups"
	h.cfg.EntraTenantID = ""
	v, err := h.flow(sso.IntentSignin, h.goodToken(map[string]any{
		"oid": "o-1", "tid": "t-1", "amr": []string{"pwd", "mfa"}, "groups": []string{"g1", "g2"}, "jti": "j-1",
	}), nil)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if v.Issuer != issuer || v.Subject != "user-1" || v.Anchor == nil || v.Anchor.Value != "o-1" || v.Anchor.TID != "t-1" ||
		!v.MFAAsserted || len(v.GroupClaims) != 2 || v.ResponseID != "j-1" || len(v.Methods) != 2 {
		t.Fatalf("Verified = %+v", v)
	}
	// MFA-3: with mode claim and no amr evidence the sign-in is not MFA-asserted.
	v, err = h.flow(sso.IntentSignin, h.goodToken(map[string]any{"oid": "o-1", "tid": "t-1", "amr": []string{"pwd"}}), nil)
	if err != nil || v.MFAAsserted {
		t.Fatalf("no evidence: MFAAsserted=%v err=%v", v.MFAAsserted, err)
	}
	// Mode off: evidence is ignored.
	h.cfg.MFAMode, h.cfg.MFAEvidence = "", nil
	v, err = h.flow(sso.IntentSignin, h.goodToken(map[string]any{"oid": "o-1", "tid": "t-1", "amr": []string{"mfa"}}), nil)
	if err != nil || v.MFAAsserted {
		t.Fatalf("mode off: MFAAsserted=%v err=%v", v.MFAAsserted, err)
	}
}

func TestOIDC_AnchorMissingRefuses(t *testing.T) {
	h := newHarness(t)
	h.cfg.AnchorClaim = "onprem_sid"
	_, err := h.flow(sso.IntentSignin, h.goodToken(nil), nil)
	wantReason(t, err, ReasonClaims)
}

// OIDC-1
func TestOIDC_RefusesFlow(t *testing.T) {
	for _, p := range []string{"id_token", "token", "access_token", "error"} {
		h := newHarness(t)
		_, err := h.flow(sso.IntentSignin, h.goodToken(nil), func(q url.Values, _ *sso.Transaction, _ *sso.Callback) { q.Set(p, "x") })
		wantReason(t, err, ReasonFlow)
		if h.calls["/token"] != 0 {
			t.Fatalf("%s: code exchanged", p)
		}
	}
	h := newHarness(t)
	_, err := h.flow(sso.IntentSignin, h.goodToken(nil), func(q url.Values, _ *sso.Transaction, _ *sso.Callback) { q.Del("code") })
	wantReason(t, err, ReasonFlow)
}

// OIDC-1 (Start side) and OIDC-2
func TestOIDC_StartSendsCodeFlowWithS256(t *testing.T) {
	h := newHarness(t)
	u, tx, err := h.v.Start(t.Context(), tenant.New(), h.idp(), sso.IntentSignin)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	for k, want := range map[string]string{
		"response_type": "code", "response_mode": "query", "client_id": clientID, "code_challenge_method": "S256",
		"state": tx.State, "nonce": tx.Nonce, "scope": "openid",
	} {
		if q.Get(k) != want {
			t.Errorf("%s = %q, want %q", k, q.Get(k), want)
		}
	}
	if q.Has("prompt") || q.Has("max_age") {
		t.Error("sign-in must not force re-authentication")
	}
	if len(tx.State) < 22 || len(tx.Nonce) < 22 || len(tx.Verifier) < 43 || tx.State == tx.Nonce {
		t.Errorf("weak randomness: %d/%d/%d", len(tx.State), len(tx.Nonce), len(tx.Verifier))
	}
	h.idToken = mint(t, std(), h.claims(tx, nil), idpKey)
	if _, err := h.v.Complete(t.Context(), tenant.ID{}, h.idp(), tx, sso.Callback{IdPID: "idp1", Query: url.Values{"code": {"c"}, "state": {tx.State}}}); err != nil {
		t.Fatal(err)
	}
	f := h.forms[0]
	// The verifier sent to the token endpoint hashes to the challenge sent to the authorization endpoint.
	sum := sha256.Sum256([]byte(f.Get("code_verifier")))
	if b64(sum[:]) != q.Get("code_challenge") || f.Get("grant_type") != "authorization_code" || f.Get("redirect_uri") != h.cfg.RedirectURI {
		t.Errorf("token request = %v", f)
	}
}

// OIDC-2 (config side): an IdP whose discovery lacks S256 cannot be used.
func TestOIDC_RefusesNoS256(t *testing.T) {
	for _, methods := range [][]string{nil, {"plain"}} {
		h := newHarness(t)
		h.cfg.Discovery.CodeChallengeMethods = methods
		_, _, err := h.v.Start(t.Context(), tenant.New(), h.idp(), sso.IntentSignin)
		wantReason(t, err, ReasonPKCE)
	}
}

// OIDC-3
func TestOIDC_RefusesState(t *testing.T) {
	cases := map[string]func(url.Values, *sso.Transaction, *sso.Callback){
		"missing":       func(q url.Values, _ *sso.Transaction, _ *sso.Callback) { q.Del("state") },
		"other browser": func(q url.Values, _ *sso.Transaction, _ *sso.Callback) { q.Set("state", "someone-elses-state") },
		"empty tx":      func(_ url.Values, tx *sso.Transaction, _ *sso.Callback) { tx.State = "" },
	}
	for name, mod := range cases {
		h := newHarness(t)
		_, err := h.flow(sso.IntentSignin, h.goodToken(nil), mod)
		wantReason(t, err, ReasonState)
		if h.calls["/token"] != 0 {
			t.Fatalf("%s: code exchanged before state was checked", name)
		}
	}
}

// OIDC-4
func TestOIDC_RefusesMixup(t *testing.T) {
	cases := map[string]struct {
		adv bool
		mod func(url.Values, *sso.Transaction, *sso.Callback)
	}{
		"callback path of another idp": {false, func(_ url.Values, _ *sso.Transaction, cb *sso.Callback) { cb.IdPID = "idp2" }},
		"transaction of another idp":   {false, func(_ url.Values, tx *sso.Transaction, _ *sso.Callback) { tx.IdPID = "idp2" }},
		"iss parameter differs":        {true, func(q url.Values, _ *sso.Transaction, _ *sso.Callback) { q.Set("iss", "https://evil.test") }},
		"iss differs unadvertised":     {false, func(q url.Values, _ *sso.Transaction, _ *sso.Callback) { q.Set("iss", "https://evil.test") }},
		"iss missing but advertised":   {true, func(url.Values, *sso.Transaction, *sso.Callback) {}},
	}
	for name, c := range cases {
		h := newHarness(t)
		h.cfg.Discovery.IssParamSupported = c.adv
		_, err := h.flow(sso.IntentSignin, h.goodToken(nil), c.mod)
		if sso.ReasonOf(err) != ReasonMixup {
			t.Fatalf("%s: err = %v", name, err)
		}
		if h.calls["/token"] != 0 {
			t.Fatalf("%s: code exchanged", name)
		}
	}
	h := newHarness(t)
	h.cfg.Discovery.IssParamSupported = true
	if _, err := h.flow(sso.IntentSignin, h.goodToken(nil), func(q url.Values, _ *sso.Transaction, _ *sso.Callback) { q.Set("iss", issuer) }); err != nil {
		t.Fatalf("matching iss refused: %v", err)
	}
}

// OIDC-5
func TestOIDC_RefusesTokenExchange(t *testing.T) {
	h := newHarness(t)
	h.tokenBody = func(*harness) (int, []byte) { return 500, []byte("{}") }
	_, err := h.flow(sso.IntentSignin, h.goodToken(nil), nil)
	wantReason(t, err, ReasonToken)

	h = newHarness(t)
	h.tokenBody = func(*harness) (int, []byte) { return 200, []byte(`{"id_token":"` + strings.Repeat("a", 65<<10) + `"}`) }
	_, err = h.flow(sso.IntentSignin, h.goodToken(nil), nil)
	wantReason(t, err, ReasonToken)

	h = newHarness(t)
	h.tokenBody = func(*harness) (int, []byte) { return 200, []byte(`{"access_token":"x"}`) }
	_, err = h.flow(sso.IntentSignin, h.goodToken(nil), nil)
	wantReason(t, err, ReasonToken)

	for _, ep := range []string{"http://idp.example.test/token", "", "https://user:pw@idp.example.test/token"} {
		h = newHarness(t)
		h.cfg.Discovery.TokenEndpoint = ep
		_, _, err = h.v.Start(t.Context(), tenant.New(), h.idp(), sso.IntentSignin)
		wantReason(t, err, ReasonConfig)
	}
}

func TestOIDC_ClientAuthentication(t *testing.T) {
	h := newHarness(t) // client_secret_basic, RFC 6749 §2.3.1 encoding
	if _, err := h.flow(sso.IntentSignin, h.goodToken(nil), nil); err != nil {
		t.Fatal(err)
	}
	if got, want := h.auths[0], "Basic YWRxLWNvbnNvbGU6czNjcjN0JTJGJTJCKyUyNg=="; got != want {
		t.Errorf("Authorization = %q, want %q", got, want)
	}
	if h.forms[0].Has("client_secret") || h.forms[0].Has("client_assertion") {
		t.Error("secret or assertion in the body of a basic request")
	}

	h = newHarness(t) // private_key_jwt
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	h.cfg.ClientSecret = secret.Secret{}
	h.cfg.ClientKey, h.cfg.ClientKeyID = ek, "ck1"
	if _, err := h.flow(sso.IntentSignin, h.goodToken(nil), nil); err != nil {
		t.Fatal(err)
	}
	f := h.forms[0]
	if h.auths[0] != "" || f.Get("client_assertion_type") != assertionType {
		t.Fatalf("form = %v auth = %q", f, h.auths[0])
	}
	jws, err := jose.ParseSigned(f.Get("client_assertion"), []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := jws.Verify(&ek.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	_ = json.Unmarshal(payload, &c)
	if c["iss"] != clientID || c["sub"] != clientID || c["aud"] != h.cfg.Discovery.TokenEndpoint || c["jti"] == "" || jws.Signatures[0].Header.KeyID != "ck1" {
		t.Errorf("assertion = %v", c)
	}

	h = newHarness(t) // exactly one credential
	h.cfg.ClientKey = ek
	_, _, err = h.v.Start(t.Context(), tenant.New(), h.idp(), sso.IntentSignin)
	wantReason(t, err, ReasonConfig)
	h.cfg.ClientKey, h.cfg.ClientSecret = nil, secret.Secret{}
	_, _, err = h.v.Start(t.Context(), tenant.New(), h.idp(), sso.IntentSignin)
	wantReason(t, err, ReasonConfig)
}

// OIDC-6
func TestOIDC_RefusesShape(t *testing.T) {
	good := func(h *harness) func(sso.Transaction) string { return h.goodToken(nil) }
	cases := map[string]func(h *harness) func(sso.Transaction) string{
		"too large": func(h *harness) func(sso.Transaction) string {
			return func(tx sso.Transaction) string {
				return mint(t, std(), h.claims(tx, map[string]any{"pad": strings.Repeat("x", 33<<10)}), idpKey)
			}
		},
		"four dots": func(h *harness) func(sso.Transaction) string {
			return func(tx sso.Transaction) string { return good(h)(tx) + ".AAAA" }
		},
		"jwe five parts": func(*harness) func(sso.Transaction) string {
			return func(sso.Transaction) string {
				return "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.AAAA.AAAA.AAAA.AAAA"
			}
		},
		"jwe header, three parts": func(*harness) func(sso.Transaction) string {
			return func(sso.Transaction) string {
				return b64([]byte(`{"alg":"RS256","enc":"A256GCM","kid":"k1"}`)) + ".AAAA.AAAA"
			}
		},
		"header not base64": func(*harness) func(sso.Transaction) string {
			return func(sso.Transaction) string { return "!!!.AAAA.AAAA" }
		},
		"two parts": func(h *harness) func(sso.Transaction) string {
			return func(tx sso.Transaction) string {
				tok := good(h)(tx)
				return tok[:strings.LastIndex(tok, ".")]
			}
		},
	}
	for name, mk := range cases {
		h := newHarness(t)
		_, err := h.flow(sso.IntentSignin, mk(h), nil)
		if sso.ReasonOf(err) != ReasonShape {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

// Package oidc is the OIDC half of console SSO (ADM-143, T-0201). It implements sso.Verifier and the
// numbered checks OIDC-1..17 of knowledge/development/architecture/console-sso.md §4; each refusal carries
// the reason code of that table and each check has a test named for it (TestOIDC_Refuses*).
//
// This is the only package that imports go-jose (FIT-SSO-1). The ID token is verified here with go-jose
// directly rather than through go-oidc's IDTokenVerifier: go-oidc maps nothing to a stable reason per
// check, applies a fixed 5-minute not-before leeway, and refreshes keys without the one-per-minute bound
// of OIDC-8. The checks that go-oidc would do (signature first, iss, aud, exp) are therefore ours.
package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"math"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"golang.org/x/oauth2"

	"github.com/skenzeriq/activediq/internal/platform/authn/sso"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

const (
	skew          = 120 * time.Second // OIDC-13, fixed
	maxIAT        = 10 * time.Minute
	stepupMaxAge  = 120 * time.Second // OIDC-15
	maxSubBytes   = 255               // OIDC-14
	maxCodeBytes  = 4096
	maxGroups     = 1000
	randomBytes   = 32
	minRSAKeyBits = 2048
)

// Verifier implements sso.Verifier for OIDC. Safe for concurrent use.
type Verifier struct {
	hc  HTTPClient
	now func() time.Time

	mu   sync.Mutex
	sets map[string]*keySet
}

var _ sso.Verifier = (*Verifier)(nil)

// New returns a Verifier that makes its outbound calls through hc. now defaults to time.Now.
func New(hc HTTPClient, now func() time.Time) *Verifier {
	if now == nil {
		now = time.Now
	}
	return &Verifier{hc: hc, now: now, sets: map[string]*keySet{}}
}

func (v *Verifier) keySet(t tenant.ID, idpID, uri string) *keySet {
	key := t.String() + "\x00" + idpID + "\x00" + uri
	v.mu.Lock()
	defer v.mu.Unlock()
	ks := v.sets[key]
	if ks == nil {
		ks = &keySet{uri: uri}
		v.sets[key] = ks
	}
	return ks
}

// usable is SSO-2 plus the config checks, run by both entry points.
func usable(idp sso.IdP) (*sso.OIDCConfig, error) {
	if idp.Protocol != sso.ProtocolOIDC || !idp.Enabled || idp.ID == "" {
		return nil, sso.Refuse("sso.idp")
	}
	if err := ValidateConfig(idp.OIDC); err != nil {
		return nil, err
	}
	return idp.OIDC, nil
}

// Start builds the authorization redirect and the Transaction it must come back to. It always sends
// response_type=code, response_mode=query (OIDC-1) and a PKCE S256 challenge (OIDC-2), never plain.
func (v *Verifier) Start(_ context.Context, _ tenant.ID, idp sso.IdP, intent sso.Intent) (*url.URL, sso.Transaction, error) {
	cfg, err := usable(idp)
	if err != nil {
		return nil, sso.Transaction{}, err
	}
	if intent != sso.IntentSignin && intent != sso.IntentStepup {
		return nil, sso.Transaction{}, sso.Refuse("sso.intent")
	}
	state, err1 := token()
	nonce, err2 := token()
	if err1 != nil || err2 != nil {
		return nil, sso.Transaction{}, sso.Refuse(ReasonConfig)
	}
	verifier := oauth2.GenerateVerifier() // 32 bytes of CSPRNG
	u, err := url.Parse(cfg.Discovery.AuthorizationEndpoint)
	if err != nil {
		return nil, sso.Transaction{}, sso.Refuse(ReasonConfig)
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("response_mode", "query")
	q.Set("client_id", cfg.ClientID)
	q.Set("redirect_uri", cfg.RedirectURI)
	q.Set("scope", "openid")
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", oauth2.S256ChallengeFromVerifier(verifier))
	q.Set("code_challenge_method", "S256")
	if intent == sso.IntentStepup {
		q.Set("prompt", "login")
		q.Set("max_age", "0")
	}
	u.RawQuery = q.Encode()
	return u, sso.Transaction{IdPID: idp.ID, Intent: intent, State: state, Nonce: nonce, Verifier: verifier, CreatedAt: v.now()}, nil
}

func token() (string, error) {
	b := make([]byte, randomBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Complete verifies the callback against tx. Order matters: everything that needs no network (flow,
// mix-up, state) is checked before the code is exchanged, and the signature is verified before any claim
// is read.
func (v *Verifier) Complete(ctx context.Context, t tenant.ID, idp sso.IdP, tx sso.Transaction, cb sso.Callback) (sso.Verified, error) {
	cfg, err := usable(idp)
	if err != nil {
		return sso.Verified{}, err
	}
	// OIDC-4: the callback path, the Transaction and the IdP must name the same IdP.
	if tx.IdPID == "" || cb.IdPID != tx.IdPID || tx.IdPID != idp.ID {
		return sso.Verified{}, sso.Refuse(ReasonMixup)
	}
	q := cb.Query
	// OIDC-1: authorization code flow only.
	for _, p := range []string{"id_token", "token", "access_token"} {
		if q.Has(p) {
			return sso.Verified{}, sso.Refuse(ReasonFlow)
		}
	}
	// OIDC-3: state, before the code is exchanged.
	if tx.State == "" || !equal(q.Get("state"), tx.State) {
		return sso.Verified{}, sso.Refuse(ReasonState)
	}
	if q.Has("error") || len(q["code"]) != 1 || q.Get("code") == "" || len(q.Get("code")) > maxCodeBytes {
		return sso.Verified{}, sso.Refuse(ReasonFlow)
	}
	// OIDC-4: RFC 9207. Required when advertised; a present but different iss is always a mix-up.
	if iss := q["iss"]; len(iss) > 1 || (len(iss) == 1 && iss[0] != cfg.Issuer) || (cfg.Discovery.IssParamSupported && len(iss) == 0) {
		return sso.Verified{}, sso.Refuse(ReasonMixup)
	}
	if tx.Verifier == "" || tx.Nonce == "" {
		return sso.Verified{}, sso.Refuse(ReasonPKCE)
	}
	raw, err := v.exchange(ctx, cfg, q.Get("code"), tx.Verifier)
	if err != nil {
		return sso.Verified{}, err
	}
	payload, err := v.verifySignature(ctx, t, idp.ID, cfg, raw)
	if err != nil {
		return sso.Verified{}, err
	}
	return v.claims(cfg, tx, payload, raw)
}

// verifySignature runs OIDC-6 to OIDC-9 and returns the payload of a token whose signature verified.
func (v *Verifier) verifySignature(ctx context.Context, t tenant.ID, idpID string, cfg *sso.OIDCConfig, raw string) ([]byte, error) {
	// OIDC-6: compact JWS shape before any parsing.
	if len(raw) > maxIDTokenBytes || strings.Count(raw, ".") != 2 {
		return nil, sso.Refuse(ReasonShape)
	}
	hdrB, _, _ := strings.Cut(raw, ".")
	hdrJSON, err := base64.RawURLEncoding.DecodeString(hdrB)
	if err != nil {
		return nil, sso.Refuse(ReasonShape)
	}
	var hdr map[string]any
	if err := json.Unmarshal(hdrJSON, &hdr); err != nil {
		return nil, sso.Refuse(ReasonShape)
	}
	if _, enc := hdr["enc"]; enc { // a JWE header on a three-part string
		return nil, sso.Refuse(ReasonShape)
	}
	// OIDC-7: the header alg is the pinned one. none and HS* cannot equal it (ValidateConfig).
	if alg, _ := hdr["alg"].(string); alg != cfg.Alg {
		return nil, sso.Refuse(ReasonAlg)
	}
	// OIDC-8: no crit; keys come from the cached JWKS by kid. jku, x5u, jwk and x5c are never read.
	if _, crit := hdr["crit"]; crit {
		return nil, sso.Refuse(ReasonKey)
	}
	kid, _ := hdr["kid"].(string)
	if kid == "" {
		return nil, sso.Refuse(ReasonKey)
	}
	jws, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.SignatureAlgorithm(cfg.Alg)})
	if err != nil || len(jws.Signatures) != 1 {
		return nil, sso.Refuse(ReasonShape)
	}
	key, err := v.keySet(t, idpID, cfg.Discovery.JWKSURI).lookup(ctx, v.hc, v.now(), kid)
	if err != nil {
		return nil, err
	}
	if !keyFits(key, cfg.Alg) {
		return nil, sso.Refuse(ReasonAlg)
	}
	// OIDC-9: signature before any claim.
	payload, err := jws.Verify(key.Key)
	if err != nil {
		return nil, sso.Refuse(ReasonSignature)
	}
	return payload, nil
}

// keyFits is the second half of OIDC-7: the key type matches the algorithm, RSA is at least 2048 bits,
// and a key restricted by use or alg is not used for anything else.
func keyFits(k jose.JSONWebKey, alg string) bool {
	if (k.Use != "" && k.Use != "sig") || (k.Algorithm != "" && k.Algorithm != alg) {
		return false
	}
	switch pub := k.Key.(type) {
	case *rsa.PublicKey:
		return (strings.HasPrefix(alg, "RS") || strings.HasPrefix(alg, "PS")) && pub.N.BitLen() >= minRSAKeyBits
	case *ecdsa.PublicKey:
		return (alg == "ES256" && pub.Curve == elliptic.P256()) || (alg == "ES384" && pub.Curve == elliptic.P384())
	}
	return false
}

// claims runs OIDC-10 to OIDC-16 on a verified payload.
func (v *Verifier) claims(cfg *sso.OIDCConfig, tx sso.Transaction, payload []byte, raw string) (sso.Verified, error) {
	var m map[string]any // encoding/json/v2 refuses duplicate member names
	if err := json.Unmarshal(payload, &m); err != nil {
		return sso.Verified{}, sso.Refuse(ReasonClaims)
	}
	now := v.now()
	// OIDC-10: iss, and for Entra the tenant.
	if iss, _ := m["iss"].(string); iss != cfg.Issuer {
		return sso.Verified{}, sso.Refuse(ReasonIss)
	}
	if cfg.EntraTenantID != "" {
		if tid, _ := m["tid"].(string); !strings.EqualFold(tid, cfg.EntraTenantID) {
			return sso.Verified{}, sso.Refuse(ReasonIss)
		}
	}
	// OIDC-11: aud is the client and nothing else; azp, when present, is the client.
	aud, ok := audience(m["aud"])
	if !ok || len(aud) == 0 || slices.ContainsFunc(aud, func(a string) bool { return a != cfg.ClientID }) {
		return sso.Verified{}, sso.Refuse(ReasonAud)
	}
	if azp, present := m["azp"]; present && azp != cfg.ClientID {
		return sso.Verified{}, sso.Refuse(ReasonAud)
	}
	// OIDC-12: nonce.
	if n, _ := m["nonce"].(string); n == "" || !equal(n, tx.Nonce) {
		return sso.Verified{}, sso.Refuse(ReasonNonce)
	}
	// OIDC-13: time.
	exp, okExp := unix(m["exp"])
	iat, okIat := unix(m["iat"])
	if !okExp || !okIat || !exp.After(now.Add(-skew)) || iat.After(now.Add(skew)) || iat.Before(now.Add(-maxIAT)) {
		return sso.Verified{}, sso.Refuse(ReasonTime)
	}
	if nb, present := m["nbf"]; present {
		if nbf, ok := unix(nb); !ok || nbf.After(now.Add(skew)) {
			return sso.Verified{}, sso.Refuse(ReasonTime)
		}
	}
	// OIDC-14: sub.
	sub, _ := m["sub"].(string)
	if sub == "" || len(sub) > maxSubBytes {
		return sso.Verified{}, sso.Refuse(ReasonSub)
	}
	// OIDC-15: a step-up proves a fresh authentication.
	var authTime time.Time
	if at, present := m["auth_time"]; present {
		authTime, ok = unix(at)
		if !ok {
			return sso.Verified{}, sso.Refuse(ReasonStale)
		}
	}
	if tx.Intent == sso.IntentStepup {
		if authTime.IsZero() || authTime.After(now.Add(skew)) || now.Sub(authTime) > stepupMaxAge {
			return sso.Verified{}, sso.Refuse(ReasonStale)
		}
	}
	out := sso.Verified{Issuer: cfg.Issuer, Subject: sub, AuthTime: authTime, ResponseID: responseID(m, raw)}
	// Anchor (DM-30.I5): the claim the IdP configuration names, or the sign-in cannot be bound.
	switch cfg.AnchorClaim {
	case "oid":
		oid, _ := m["oid"].(string)
		tid, _ := m["tid"].(string)
		if oid == "" || tid == "" {
			return sso.Verified{}, sso.Refuse(ReasonClaims)
		}
		out.Anchor = &sso.Anchor{Claim: "oid", Value: oid, TID: tid}
	case "onprem_sid":
		sid, _ := m["onprem_sid"].(string)
		if sid == "" {
			return sso.Verified{}, sso.Refuse(ReasonClaims)
		}
		out.Anchor = &sso.Anchor{Claim: "onprem_sid", Value: sid}
	}
	// MFA-1/MFA-3: evidence is in this response, or MFAAsserted stays false.
	out.Methods = stringList(m["amr"])
	if cfg.MFAMode == sso.MFAClaim {
		out.MFAAsserted = slices.ContainsFunc(out.Methods, func(a string) bool { return slices.Contains(cfg.MFAEvidence, a) })
	}
	// OIDC-16: groups from the ID token only; overage yields none and a warning.
	if cfg.GroupClaim != "" {
		out.GroupClaims, out.Warnings = groups(m, cfg.GroupClaim)
	}
	return out, nil
}

func groups(m map[string]any, claim string) ([]string, []string) {
	if names, ok := m["_claim_names"].(map[string]any); ok {
		if _, over := names[claim]; over {
			return nil, []string{"oidc.groups_overage"}
		}
	}
	if has, _ := m["hasgroups"].(bool); has {
		return nil, []string{"oidc.groups_overage"}
	}
	val, present := m[claim]
	if !present {
		return nil, nil
	}
	g := stringList(val)
	if arr, ok := val.([]any); !ok || len(g) != len(arr) || len(g) > maxGroups {
		return nil, []string{"oidc.groups_malformed"}
	}
	return g, nil
}

func stringList(v any) []string {
	arr, _ := v.([]any)
	var out []string
	for _, e := range arr {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func audience(v any) ([]string, bool) {
	switch a := v.(type) {
	case string:
		return []string{a}, true
	case []any:
		out := make([]string, 0, len(a))
		for _, e := range a {
			s, ok := e.(string)
			if !ok {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	}
	return nil, false
}

// unix reads a NumericDate. Values outside a sane range are refused rather than wrapped.
func unix(v any) (time.Time, bool) {
	f, ok := v.(float64)
	if !ok || math.IsNaN(f) || f < 0 || f > 1e11 {
		return time.Time{}, false
	}
	return time.Unix(int64(f), 0), true
}

func responseID(m map[string]any, raw string) string {
	if jti, ok := m["jti"].(string); ok && jti != "" && len(jti) <= 128 {
		return jti
	}
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:16])
}

func equal(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

package oidc

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/authn/sso"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// OIDC-7
func TestOIDC_RefusesAlg(t *testing.T) {
	h := newHarness(t)
	rsaDER, _ := x509.MarshalPKIXPublicKey(&idpKey.PublicKey)
	rsaPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: rsaDER})
	unsigned := func(alg string) func(sso.Transaction) string {
		return func(tx sso.Transaction) string {
			hdr, _ := json.Marshal(map[string]any{"alg": alg, "kid": kid})
			c, _ := json.Marshal(h.claims(tx, nil))
			return b64(hdr) + "." + b64(c) + "."
		}
	}
	cases := map[string]func(sso.Transaction) string{
		"none":      unsigned("none"),
		"empty alg": unsigned(""),
		"HS256 keyed with the RSA public key": func(tx sso.Transaction) string {
			hdr, _ := json.Marshal(map[string]any{"alg": "HS256", "kid": kid})
			c, _ := json.Marshal(h.claims(tx, nil))
			in := b64(hdr) + "." + b64(c)
			m := hmac.New(sha256.New, rsaPEM)
			m.Write([]byte(in))
			return in + "." + b64(m.Sum(nil))
		},
		"trusted key, algorithm other than the pinned one": func(tx sso.Transaction) string {
			hdr := std()
			hdr["alg"] = "RS384"
			return mint(t, hdr, h.claims(tx, nil), idpKey)
		},
	}
	for name, mk := range cases {
		_, err := h.flow(sso.IntentSignin, mk, nil)
		if sso.ReasonOf(err) != ReasonAlg {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	// RSA-1024 in the JWKS.
	h = newHarness(t)
	h.jwksKeys = []map[string]any{jwk(&weakKey.PublicKey, "weak")}
	hdr := std()
	hdr["kid"] = "weak"
	_, err := h.flow(sso.IntentSignin, func(tx sso.Transaction) string { return mint(t, hdr, h.claims(tx, nil), weakKey) }, nil)
	wantReason(t, err, ReasonAlg)
	// A key pinned to another algorithm by its own alg member.
	h = newHarness(t)
	h.jwksKeys[0]["alg"] = "RS384"
	_, err = h.flow(sso.IntentSignin, h.goodToken(nil), nil)
	wantReason(t, err, ReasonAlg)
	// A key reserved for encryption.
	h = newHarness(t)
	h.jwksKeys[0]["use"] = "enc"
	_, err = h.flow(sso.IntentSignin, h.goodToken(nil), nil)
	wantReason(t, err, ReasonAlg)
	// Config time: none and HS* cannot be pinned, and so cannot be saved.
	for _, alg := range []string{"none", "HS256", "HS512", "", "RS1", "ES512"} {
		h = newHarness(t)
		h.cfg.Alg = alg
		_, _, err = h.v.Start(t.Context(), tenant.New(), h.idp(), sso.IntentSignin)
		if sso.ReasonOf(err) != ReasonAlg {
			t.Errorf("config alg %q: err = %v", alg, err)
		}
	}
}

// OIDC-8
func TestOIDC_RefusesKey(t *testing.T) {
	evilJWK := jwk(&evilKey.PublicKey, "evil")
	for _, extra := range []string{"jku", "x5u", "jwk", "x5c"} {
		h := newHarness(t)
		hdr := std()
		hdr["kid"] = "evil"
		switch extra {
		case "jku", "x5u":
			hdr[extra] = "https://evil.test/keys"
		case "jwk":
			hdr[extra] = evilJWK
		case "x5c":
			tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "evil"}, NotBefore: baseTime.Add(-time.Hour), NotAfter: baseTime.Add(time.Hour)}
			der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &evilKey.PublicKey, evilKey)
			if err != nil {
				t.Fatal(err)
			}
			hdr[extra] = []string{base64.StdEncoding.EncodeToString(der)}
		}
		_, err := h.flow(sso.IntentSignin, func(tx sso.Transaction) string { return mint(t, hdr, h.claims(tx, nil), evilKey) }, nil)
		if sso.ReasonOf(err) != ReasonKey {
			t.Errorf("%s: err = %v", extra, err)
		}
		if h.calls["/keys"] != 0 {
			t.Errorf("%s: the jku URL was fetched", extra)
		}
	}
	// A trusted kid with a header that names an attacker key: the header is ignored, the signature fails.
	h := newHarness(t)
	hdr := std()
	hdr["jwk"] = evilJWK
	_, err := h.flow(sso.IntentSignin, func(tx sso.Transaction) string { return mint(t, hdr, h.claims(tx, nil), evilKey) }, nil)
	wantReason(t, err, ReasonSignature)

	h = newHarness(t)
	hdr = std()
	hdr["crit"] = []string{"exp"}
	_, err = h.flow(sso.IntentSignin, func(tx sso.Transaction) string { return mint(t, hdr, h.claims(tx, nil), idpKey) }, nil)
	wantReason(t, err, ReasonKey)

	h = newHarness(t)
	hdr = std()
	delete(hdr, "kid")
	_, err = h.flow(sso.IntentSignin, func(tx sso.Transaction) string { return mint(t, hdr, h.claims(tx, nil), idpKey) }, nil)
	wantReason(t, err, ReasonKey)
}

func TestOIDC_UnknownKidRefreshesOncePerMinute(t *testing.T) {
	h := newHarness(t)
	unknown := std()
	unknown["kid"] = "rotated"
	tok := func(tx sso.Transaction) string { return mint(t, unknown, h.claims(tx, nil), idpKey) }
	for i := 0; i < 3; i++ {
		_, err := h.flow(sso.IntentSignin, tok, nil)
		wantReason(t, err, ReasonKey)
	}
	if h.calls["/jwks"] != 1 {
		t.Fatalf("jwks fetched %d times in one minute, want 1 (first fill only)", h.calls["/jwks"])
	}
	// The IdP rotates in the new key; after a minute the next unknown kid refreshes and succeeds.
	h.jwksKeys = append(h.jwksKeys, jwk(&idpKey.PublicKey, "rotated"))
	h.now = h.now.Add(61 * time.Second)
	if _, err := h.flow(sso.IntentSignin, tok, nil); err != nil {
		t.Fatalf("after rotation: %v", err)
	}
	if h.calls["/jwks"] != 2 {
		t.Fatalf("jwks fetched %d times, want 2", h.calls["/jwks"])
	}
	// An unreachable JWKS refuses, with a cause that carries no token.
	h = newHarness(t)
	h.cfg.Discovery.JWKSURI = issuer + "/gone"
	_, err := h.flow(sso.IntentSignin, h.goodToken(nil), nil)
	wantReason(t, err, ReasonKey)
}

// OIDC-9: the signature is verified before any claim is read, so a forged token with wrong claims is a
// signature refusal, never an iss or aud one.
func TestOIDC_RefusesSignature(t *testing.T) {
	cases := map[string]func(tx sso.Transaction, good string) string{
		"signed by another key": func(tx sso.Transaction, _ string) string { return mint(t, std(), map[string]any{"iss": "x"}, evilKey) },
		"payload changed": func(tx sso.Transaction, good string) string {
			p := strings.Split(good, ".")
			c, _ := json.Marshal(map[string]any{"iss": issuer, "aud": clientID, "sub": "admin", "nonce": tx.Nonce, "iat": baseTime.Unix(), "exp": baseTime.Add(time.Hour).Unix()})
			return p[0] + "." + b64(c) + "." + p[2]
		},
		"signature bit flipped": func(_ sso.Transaction, good string) string {
			p := strings.Split(good, ".")
			sig := []byte(p[2])
			if sig[3] == 'A' {
				sig[3] = 'B'
			} else {
				sig[3] = 'A'
			}
			return p[0] + "." + p[1] + "." + string(sig)
		},
		"empty signature": func(_ sso.Transaction, good string) string { return good[:strings.LastIndex(good, ".")+1] },
	}
	for name, mk := range cases {
		h := newHarness(t)
		_, err := h.flow(sso.IntentSignin, func(tx sso.Transaction) string { return mk(tx, mint(t, std(), h.claims(tx, nil), idpKey)) }, nil)
		if r := sso.ReasonOf(err); r != ReasonSignature && !(name == "empty signature" && r == ReasonShape) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

// A failed JWKS refresh must not keep keys alive past the one-hour limit: a key the IdP rotated out after a
// compromise must stop verifying even while the JWKS endpoint is unreachable.
func TestOIDC_RefusesStaleKeysAfterFailedRefresh(t *testing.T) {
	h := newHarness(t)
	if _, err := h.flow(sso.IntentSignin, h.goodToken(nil), nil); err != nil {
		t.Fatalf("first sign-in: %v", err)
	}
	h.jwksDown = true
	h.now = h.now.Add(61 * time.Minute)
	before := h.calls["/jwks"]
	for i := 0; i < 2; i++ {
		_, err := h.flow(sso.IntentSignin, h.goodToken(nil), nil)
		wantReason(t, err, ReasonKey)
		h.now = h.now.Add(5 * time.Second)
	}
	if n := h.calls["/jwks"] - before; n != 1 {
		t.Fatalf("jwks fetched %d times in the minute, want 1", n)
	}
	h.jwksDown = false
	h.now = h.now.Add(time.Minute)
	if _, err := h.flow(sso.IntentSignin, h.goodToken(nil), nil); err != nil {
		t.Fatalf("after recovery: %v", err)
	}
}

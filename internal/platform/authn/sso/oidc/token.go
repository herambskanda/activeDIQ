package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json/v2"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/skenzeriq/activediq/internal/platform/authn/sso"
)

const assertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// exchange redeems code at the pinned token endpoint (OIDC-5) and returns the raw id_token. The access and
// refresh tokens in the response are never read (OIDC-16).
func (v *Verifier) exchange(ctx context.Context, c *sso.OIDCConfig, code, codeVerifier string) (string, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {c.RedirectURI},
		"code_verifier": {codeVerifier},
	}
	var basic string
	if c.ClientKey != nil {
		assertion, err := v.clientAssertion(c)
		if err != nil {
			return "", sso.Refuse(ReasonToken)
		}
		form.Set("client_id", c.ClientID)
		form.Set("client_assertion_type", assertionType)
		form.Set("client_assertion", assertion)
	} else {
		// RFC 6749 §2.3.1: both parts are form-urlencoded before the Basic encoding.
		c.ClientSecret.Expose(func(s []byte) {
			basic = base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(c.ClientID) + ":" + url.QueryEscape(string(s))))
		})
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Discovery.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", sso.Refuse(ReasonToken)
	}
	if basic != "" {
		req.Header.Set("Authorization", "Basic "+basic)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	body, err := fetch(v.hc, req, maxTokenBytes)
	if err != nil {
		return "", &sso.Refusal{Reason: ReasonToken, Cause: err}
	}
	var resp struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &resp); err != nil || resp.IDToken == "" {
		return "", sso.Refuse(ReasonToken)
	}
	return resp.IDToken, nil
}

// clientAssertion builds the private_key_jwt of RFC 7523 §2.2, valid for one minute.
func (v *Verifier) clientAssertion(c *sso.OIDCConfig) (string, error) {
	var alg jose.SignatureAlgorithm
	switch k := c.ClientKey.(type) {
	case *rsa.PrivateKey:
		alg = jose.RS256
	case *ecdsa.PrivateKey:
		switch k.Curve {
		case elliptic.P256():
			alg = jose.ES256
		case elliptic.P384():
			alg = jose.ES384
		default:
			return "", sso.Refuse(ReasonConfig)
		}
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: alg, Key: jose.JSONWebKey{Key: c.ClientKey, KeyID: c.ClientKeyID}},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return "", err
	}
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	now := v.now()
	payload, err := json.Marshal(map[string]any{
		"iss": c.ClientID, "sub": c.ClientID, "aud": c.Discovery.TokenEndpoint,
		"jti": base64.RawURLEncoding.EncodeToString(jti),
		"iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
	})
	if err != nil {
		return "", err
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return jws.CompactSerialize()
}

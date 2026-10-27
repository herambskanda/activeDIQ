package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json/v2"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/skenzeriq/activediq/internal/platform/authn/sso"
)

// HTTPClient is the outbound client. Production passes an *egress.Client (TM-TB9-T1); this package builds no
// transport of its own.
type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

const (
	maxDiscoveryBytes = 64 << 10
	maxJWKSBytes      = 1 << 20
	maxTokenBytes     = 64 << 10 // OIDC-5: token response body
	maxIDTokenBytes   = 32 << 10 // OIDC-6
)

// Reason codes of the refusals (spec §4).
const (
	ReasonFlow      = "oidc.flow"
	ReasonPKCE      = "oidc.pkce"
	ReasonState     = "oidc.state"
	ReasonMixup     = "oidc.mixup"
	ReasonToken     = "oidc.token"
	ReasonShape     = "oidc.shape"
	ReasonAlg       = "oidc.alg"
	ReasonKey       = "oidc.key"
	ReasonSignature = "oidc.signature"
	ReasonIss       = "oidc.iss"
	ReasonAud       = "oidc.aud"
	ReasonNonce     = "oidc.nonce"
	ReasonTime      = "oidc.time"
	ReasonSub       = "oidc.sub"
	ReasonStale     = "oidc.stale"
	ReasonClaims    = "oidc.claims"
	ReasonConfig    = "oidc.config"
)

// pinnable are the algorithms an administrator may pin (OIDC-7). "none" and HS* are not on it.
var pinnable = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384"}

// mfaForbidden cannot be evidence of MFA: each names at most one factor (spec MFA-1).
var mfaForbidden = []string{"pwd", "kba", "sms", "tel", "user"}

// Discover fetches and parses the discovery document of issuer. It is a setup-time call (OIDC-17): the
// result is pinned in the IdP configuration and checked by ValidateConfig.
func Discover(ctx context.Context, hc HTTPClient, issuer string) (sso.Discovery, error) {
	if err := httpsURL(issuer); err != nil {
		return sso.Discovery{}, sso.Refuse(ReasonConfig)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(issuer, "/")+"/.well-known/openid-configuration", nil)
	if err != nil {
		return sso.Discovery{}, sso.Refuse(ReasonConfig)
	}
	req.Header.Set("Accept", "application/json")
	body, err := fetch(hc, req, maxDiscoveryBytes)
	if err != nil {
		return sso.Discovery{}, &sso.Refusal{Reason: ReasonConfig, Cause: err}
	}
	var doc struct {
		Issuer      string   `json:"issuer"`
		AuthzURL    string   `json:"authorization_endpoint"`
		TokenURL    string   `json:"token_endpoint"`
		JWKSURI     string   `json:"jwks_uri"`
		Challenges  []string `json:"code_challenge_methods_supported"`
		IssParamSup bool     `json:"authorization_response_iss_parameter_supported"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return sso.Discovery{}, sso.Refuse(ReasonConfig)
	}
	return sso.Discovery{
		Issuer: doc.Issuer, AuthorizationEndpoint: doc.AuthzURL, TokenEndpoint: doc.TokenURL, JWKSURI: doc.JWKSURI,
		CodeChallengeMethods: doc.Challenges, IssParamSupported: doc.IssParamSup,
	}, nil
}

// fetch performs req and returns the body, refusing a non-200 status or a body over limit.
func fetch(hc HTTPClient, req *http.Request, limit int64) ([]byte, error) {
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("response over %d bytes", limit)
	}
	return b, nil
}

// ValidateConfig is the config-time (and per-call) refusal of an OIDC IdP that cannot be verified safely:
// OIDC-2 (S256 advertised), OIDC-7 (algorithm on the allow-list, never none or HS*), OIDC-10 (no
// multi-tenant Entra issuer), OIDC-17 (discovery issuer equals the configured issuer, every endpoint HTTPS).
func ValidateConfig(c *sso.OIDCConfig) error {
	if c == nil || c.ClientID == "" || httpsURL(c.Issuer) != nil || httpsURL(c.RedirectURI) != nil {
		return sso.Refuse(ReasonConfig)
	}
	if !slices.Contains(pinnable, c.Alg) {
		return sso.Refuse(ReasonAlg)
	}
	d := c.Discovery
	if d.Issuer != c.Issuer {
		return sso.Refuse(ReasonConfig)
	}
	for _, e := range []string{d.AuthorizationEndpoint, d.TokenEndpoint, d.JWKSURI} {
		if httpsURL(e) != nil {
			return sso.Refuse(ReasonConfig)
		}
	}
	if !slices.Contains(d.CodeChallengeMethods, "S256") {
		return sso.Refuse(ReasonPKCE)
	}
	if err := checkEntraIssuer(c); err != nil {
		return err
	}
	switch hasSecret, hasKey := !c.ClientSecret.IsEmpty(), c.ClientKey != nil; {
	case hasSecret == hasKey:
		return sso.Refuse(ReasonConfig) // exactly one client credential
	case hasKey:
		switch c.ClientKey.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
		default:
			return sso.Refuse(ReasonConfig)
		}
	}
	if !slices.Contains([]string{"", "oid", "onprem_sid"}, c.AnchorClaim) {
		return sso.Refuse(ReasonConfig)
	}
	switch c.MFAMode {
	case "", sso.MFAOff:
		if len(c.MFAEvidence) != 0 {
			return sso.Refuse(ReasonConfig)
		}
	case sso.MFAClaim:
		if len(c.MFAEvidence) == 0 {
			return sso.Refuse(ReasonConfig)
		}
		for _, e := range c.MFAEvidence {
			if e == "" || slices.Contains(mfaForbidden, e) {
				return sso.Refuse(ReasonConfig)
			}
		}
	default:
		return sso.Refuse(ReasonConfig)
	}
	return nil
}

// checkEntraIssuer pins an Entra issuer to one tenant: https://login.microsoftonline.com/{tid}/v2.0, never the
// common, organizations or consumers templates (OIDC-10).
func checkEntraIssuer(c *sso.OIDCConfig) error {
	u, err := url.Parse(c.Issuer)
	if err != nil || u.Hostname() != "login.microsoftonline.com" {
		return nil
	}
	seg := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(seg) != 2 || seg[1] != "v2.0" || c.EntraTenantID == "" || !strings.EqualFold(seg[0], c.EntraTenantID) ||
		slices.Contains([]string{"common", "organizations", "consumers"}, strings.ToLower(seg[0])) {
		return sso.Refuse(ReasonIss)
	}
	return nil
}

// httpsURL reports whether s is an absolute https URL with a host and no user information.
func httpsURL(s string) error {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
		return fmt.Errorf("not an https URL")
	}
	return nil
}

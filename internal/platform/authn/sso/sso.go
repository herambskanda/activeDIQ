// Package sso is the protocol-neutral contract of console single sign-on (ADM-143; spec
// knowledge/development/architecture/console-sso.md §3). Verifier is implemented once per protocol:
// sso/oidc (T-0201) and sso/saml (T-0202). Nothing else in the product parses an IdP response (SSO-D1).
//
// This package holds only types. It imports no JOSE, XML or HTTP-server code, so FIT-SSO-1 can fence the
// libraries inside the two protocol packages.
package sso

import (
	"context"
	"crypto"
	"errors"
	"net/url"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/secret"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// Protocol names the IdP protocol.
type Protocol string

// The supported protocols.
const (
	ProtocolOIDC Protocol = "oidc"
	ProtocolSAML Protocol = "saml"
)

// Intent is why a Transaction exists (spec §3). A stepup Transaction forces re-authentication at the IdP.
type Intent string

// The intents.
const (
	IntentSignin Intent = "signin"
	IntentStepup Intent = "stepup"
)

// Transaction is what Start produces and Complete consumes. Persisting it (hashed handle, five-minute
// lifetime, consume-first, SSO-1) and the browser-binding cookie belong to the callback handler (T-0203);
// the verifier only reads the fields it was given.
type Transaction struct {
	IdPID      string
	Intent     Intent
	State      string // OIDC state
	Nonce      string // OIDC nonce
	Verifier   string // OIDC PKCE code_verifier
	RequestID  string // SAML AuthnRequest ID
	ReturnPath string // set by the caller; never taken from the callback
	CreatedAt  time.Time
}

// Callback is the browser's return from the IdP. IdPID is the {idpId} path segment of the URL it hit.
type Callback struct {
	IdPID string
	Query url.Values // OIDC authorization response (response_mode=query)
	Form  url.Values // SAML ACS POST
}

// Anchor is the directory-binding claim of DM-30.I5: "oid" with the tenant ID, or "onprem_sid".
type Anchor struct {
	Claim string
	Value string
	TID   string // the Entra tenant, set for Claim "oid"
}

// Verified is protocol-neutral. The callback handler sees only this, and only when every check held.
type Verified struct {
	Issuer      string
	Subject     string
	Anchor      *Anchor
	AuthTime    time.Time
	MFAAsserted bool
	Methods     []string // amr / AuthnContextClassRef values, for audit
	GroupClaims []string // only the claim the mapping names; IDs, not names
	SessionCap  time.Time
	ResponseID  string   // audit only
	Warnings    []string // audit warnings, e.g. "oidc.groups_overage"
}

// Verifier is the one entry-point pair of a protocol.
type Verifier interface {
	// Start builds the redirect to the IdP and the Transaction it must come back to.
	Start(ctx context.Context, t tenant.ID, idp IdP, intent Intent) (*url.URL, Transaction, error)
	// Complete verifies a callback against one Transaction. It returns Verified only when every check
	// holds; otherwise a *Refusal. It never returns partial claims.
	Complete(ctx context.Context, t tenant.ID, idp IdP, tx Transaction, cb Callback) (Verified, error)
}

// IdP is the verifier's view of an identity provider (DM-39).
type IdP struct {
	ID       string
	Protocol Protocol
	Enabled  bool
	OIDC     *OIDCConfig
}

// MFA modes of an IdP (spec §6.1).
const (
	MFAOff   = "off"
	MFAClaim = "claim"
)

// OIDCConfig is the pinned configuration of an OIDC IdP (spec §4). Changing any of it is an IdP
// configuration change (OIDC-17), made by the caller with step-up and audit.
type OIDCConfig struct {
	Issuer      string
	ClientID    string
	RedirectURI string // https://<console-host>/auth/sso/{idpId}/callback
	Alg         string // the one signing algorithm
	Discovery   Discovery

	// Client authentication: exactly one of ClientSecret (client_secret_basic) or ClientKey
	// (private_key_jwt; *rsa.PrivateKey or *ecdsa.PrivateKey) is set. Both come unsealed from the tenant
	// data key (TM-D7).
	ClientSecret secret.Secret
	ClientKey    crypto.Signer
	ClientKeyID  string

	EntraTenantID string   // when set, tid must equal it
	AnchorClaim   string   // "", "oid" or "onprem_sid"
	GroupClaim    string   // the one claim the role mapping names
	MFAMode       string   // MFAOff (default) or MFAClaim
	MFAEvidence   []string // amr values that count; only with MFAClaim
}

// Discovery is the OIDC discovery document as pinned at setup (OIDC-17).
type Discovery struct {
	Issuer                string
	AuthorizationEndpoint string
	TokenEndpoint         string
	JWKSURI               string
	CodeChallengeMethods  []string
	IssParamSupported     bool // authorization_response_iss_parameter_supported (RFC 9207)
}

// ErrRefused matches every *Refusal under errors.Is.
var ErrRefused = errors.New("sso: sign-in refused")

// Refusal is a failed check. Reason is the stable code of the spec ("oidc.nonce", "saml.wrap"...). The
// user sees one generic page for every reason; the code goes to audit and the log. Cause, when set,
// is a transport error that carries no token or assertion bytes.
type Refusal struct {
	Reason string
	Cause  error
}

func (r *Refusal) Error() string        { return "sso: refused: " + r.Reason }
func (r *Refusal) Unwrap() error        { return r.Cause }
func (r *Refusal) Is(target error) bool { return target == ErrRefused }

// Refuse returns a Refusal with reason.
func Refuse(reason string) error { return &Refusal{Reason: reason} }

// ReasonOf returns the reason code of err, or "" when err is not a Refusal.
func ReasonOf(err error) string {
	var r *Refusal
	if errors.As(err, &r) {
		return r.Reason
	}
	return ""
}

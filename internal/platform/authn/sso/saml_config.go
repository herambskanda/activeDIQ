package sso

import "crypto/x509"

// SAMLConfig is the pinned configuration of a SAML IdP (spec §5, "Configuration fixes, per IdP"). The
// stored values, not a metadata URL, are what verification uses. Changing any of it is an IdP configuration
// change made by the caller with step-up and audit.
type SAMLConfig struct {
	EntityID string // the IdP's entityID; Issuer must equal it exactly (SAML-10)
	SSOURL   string // the IdP's HTTP-Redirect endpoint for our AuthnRequest

	// Certs are the IdP's signing certificates: one, or two during a rollover. They are the only trust
	// source (SAML-5).
	Certs []*x509.Certificate
	// Alg is the one XML-DSig SignatureMethod URI the IdP signs with (SAML-7).
	Alg string

	SPEntityID string // our entityID, the Audience (SAML-14)
	ACSURL     string // https://<console-host>/auth/sso/{idpId}/callback

	// SubjectAttribute names the attribute that holds the immutable account subject. Empty means the
	// persistent NameID (SAML-18).
	SubjectAttribute string

	AnchorClaim     string // "", "oid" or "onprem_sid" (DM-30.I5)
	AnchorAttribute string // the attribute carrying the oid or the SID
	TenantAttribute string // the attribute carrying the Entra tid, with AnchorClaim "oid"
	EntraTenantID   string // when set, the tid attribute must equal it
	GroupAttribute  string // the one attribute the role mapping names

	MFAMode      string   // MFAOff (default) or MFAClaim
	MFAAttribute string   // attribute holding evidence; empty means AuthnContextClassRef
	MFAEvidence  []string // values that count; only with MFAClaim
}

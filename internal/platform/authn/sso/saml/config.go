package saml

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"net/url"
	"slices"
	"strings"

	"github.com/skenzeriq/activediq/internal/platform/authn/sso"
)

// Reason codes: the "Refusal reason" column of spec §5. Audit and the log carry these; the user sees one
// generic page.
const (
	ReasonBinding      = "saml.binding"      // SAML-1
	ReasonXML          = "saml.xml"          // SAML-2
	ReasonStructure    = "saml.structure"    // SAML-3
	ReasonUnsigned     = "saml.unsigned"     // SAML-4
	ReasonKey          = "saml.key"          // SAML-5
	ReasonWrapped      = "saml.wrapped"      // SAML-6
	ReasonAlg          = "saml.alg"          // SAML-7
	ReasonTransform    = "saml.transform"    // SAML-8
	ReasonStatus       = "saml.status"       // SAML-9
	ReasonIssuer       = "saml.issuer"       // SAML-10
	ReasonDestination  = "saml.destination"  // SAML-11
	ReasonRecipient    = "saml.recipient"    // SAML-12
	ReasonInResponseTo = "saml.inresponseto" // SAML-13
	ReasonAudience     = "saml.audience"     // SAML-14
	ReasonTime         = "saml.time"         // SAML-15
	ReasonReplay       = "saml.replay"       // SAML-16
	ReasonAuthn        = "saml.authn"        // SAML-17
	ReasonSubject      = "saml.subject"      // SAML-18
	ReasonLogout       = "saml.logout"       // SAML-19

	// Reasons that are not one of the numbered checks.
	ReasonConfig = "saml.config" // the IdP configuration cannot be used
	ReasonAnchor = "saml.anchor" // the configured anchor attribute is missing or malformed (DM-30.I5)
	ReasonIdP    = "sso.idp"     // SSO-2: the callback, the Transaction and the IdP name different IdPs
)

// XML-DSig URIs. The pin set of SAML-7 and SAML-8 is exactly these.
const (
	algRSASHA256   = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	algRSASHA384   = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
	algRSASHA512   = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
	algECDSASHA256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
	algECDSASHA384 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"

	digestSHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
	digestSHA384 = "http://www.w3.org/2001/04/xmldsig-more#sha384"
	digestSHA512 = "http://www.w3.org/2001/04/xmlenc#sha512"

	transformEnveloped = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
	c14nExclusive      = "http://www.w3.org/2001/10/xml-exc-c14n#"

	minRSABits = 2048
)

// Exported for the test IdP and the settings screen.
const (
	AlgRSASHA256   = algRSASHA256
	AlgRSASHA384   = algRSASHA384
	AlgRSASHA512   = algRSASHA512
	AlgECDSASHA256 = algECDSASHA256
	AlgECDSASHA384 = algECDSASHA384
)

// oasisClassPrefix is the namespace of the SAML 2.0 authentication context classes. None of them proves a
// second factor (PasswordProtectedTransport is a password over TLS), so none can be configured as MFA
// evidence (spec MFA-2a); evidence is an IdP-specific class or an attribute value.
const oasisClassPrefix = "urn:oasis:names:tc:SAML:2.0:ac:classes:"

// singleFactorNamespaces are namespaces whose members name one factor or an ambient sign-in, never a second
// factor (spec MFA-2b): the OASIS 2.0 classes (MFA-2a), the AD FS classes (`urn:federation:authentication:windows`
// is Integrated Windows Authentication), the Microsoft authenticationmethod URIs (`.../password`, `.../windows`)
// and the SAML 1.x authentication methods: the `urn:oasis:names:tc:SAML:1.0:am:` namespace and, because SAML 1.1
// core §7.1 puts four methods outside it, the `urn:ietf:rfc:` namespace (Kerberos 1510, SRP 2945, TLS client 2246,
// XML-DSig 3075). An RFC number names a generic mechanism, never an IdP's MFA class. The Microsoft
// `http://schemas.microsoft.com/claims/multipleauthn` value is in none of them and stays acceptable. Matching is
// case-insensitive (ASCII fold; evidence is compared exact-string against the IdP, so a Unicode lookalike never
// matches a real value): the NID of a URN is case-insensitive (RFC 8141), and a scheme and host are too, so a case
// variant must not slip past a rule that only an exact-case IdP would trip.
var singleFactorNamespaces = []string{
	oasisClassPrefix,
	"urn:federation:authentication:",
	"http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/",
	// Microsoft's SAML token reference writes the same value as a claim-type namespace. [UNVERIFIED that any IdP
	// emits it]; refusing it costs one line.
	"http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod/",
	"urn:oasis:names:tc:SAML:1.0:am:",
	"urn:ietf:rfc:",
}

// singleFactorValues are single identifiers, not namespaces, that name one factor: the REFEDS Single Factor
// Authentication profile (its whole purpose is to tell the relying party that one factor was used; the MFA profile
// `https://refeds.org/profile/mfa` stays acceptable) and the AD FS `wiaormultiauthn` claim, which Integrated
// Windows Authentication alone satisfies.
var singleFactorValues = []string{
	"https://refeds.org/profile/sfa",
	"http://schemas.microsoft.com/claims/wiaormultiauthn",
}

// mfaEvidenceAllowed reports whether v may be configured as SAML MFA evidence. Evidence is compared exact-string
// against what the IdP sent, so a value with surrounding whitespace is refused rather than trimmed: trimming
// would store a value different from the one an operator reviewed.
func mfaEvidenceAllowed(v string) bool {
	if v == "" || v != strings.TrimSpace(v) {
		return false
	}
	for _, sf := range singleFactorValues {
		if strings.EqualFold(v, sf) {
			return false
		}
	}
	for _, ns := range singleFactorNamespaces {
		if len(v) >= len(ns) && strings.EqualFold(v[:len(ns)], ns) {
			return false
		}
	}
	return true
}

// mfaAttributeAuthnMethods is the one attribute that may carry MFA evidence besides AuthnContextClassRef: the
// Entra ID and AD FS preset (spec MFA-2). It lists authentication methods by definition.
const mfaAttributeAuthnMethods = "http://schemas.microsoft.com/claims/authnmethodsreferences"

// mfaAttributeAllowed is MFA-2c: the evidence attribute is an allow-list, because the value deny-lists of MFA-2a
// and MFA-2b cannot stop an attribute every response carries with a constant value (`.../identity/claims/tenantid`,
// `identityprovider`, a group claim). Empty means AuthnContextClassRef. Attribute names are compared exact-string,
// so a case or whitespace variant is refused rather than saved as config that never matches. A new attribute
// needs a spec change and a source showing it carries authentication methods.
func mfaAttributeAllowed(a string) bool {
	return a == "" || a == mfaAttributeAuthnMethods
}

var (
	pinnable      = []string{algRSASHA256, algRSASHA384, algRSASHA512, algECDSASHA256, algECDSASHA384}
	digestAllowed = []string{digestSHA256, digestSHA384, digestSHA512}
)

// ValidateConfig checks an IdP configuration against spec §5 before it is stored and before every use. It
// returns a *sso.Refusal: saml.alg for an algorithm or key the pin set excludes, saml.config otherwise.
func ValidateConfig(c *sso.SAMLConfig) error {
	if c == nil || c.EntityID == "" || c.SPEntityID == "" || httpsURL(c.SSOURL) != nil || httpsURL(c.ACSURL) != nil {
		return sso.Refuse(ReasonConfig)
	}
	if !slices.Contains(pinnable, c.Alg) {
		return sso.Refuse(ReasonAlg)
	}
	if n := len(c.Certs); n < 1 || n > 2 {
		return sso.Refuse(ReasonConfig)
	}
	for _, cert := range c.Certs {
		if cert == nil || !keyMatchesAlg(cert.PublicKey, c.Alg) {
			return sso.Refuse(ReasonAlg)
		}
	}
	if !mfaAttributeAllowed(c.MFAAttribute) {
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
			if !mfaEvidenceAllowed(e) {
				return sso.Refuse(ReasonConfig)
			}
		}
	default:
		return sso.Refuse(ReasonConfig)
	}
	switch c.AnchorClaim {
	case "":
	case "oid":
		if c.AnchorAttribute == "" || c.TenantAttribute == "" {
			return sso.Refuse(ReasonConfig)
		}
	case "onprem_sid":
		if c.AnchorAttribute == "" {
			return sso.Refuse(ReasonConfig)
		}
	default:
		return sso.Refuse(ReasonConfig)
	}
	return nil
}

// keyMatchesAlg: RSA keys of at least 2048 bits for rsa-*, and P-256 / P-384 for the matching ecdsa-*.
func keyMatchesAlg(pub any, alg string) bool {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return k.N.BitLen() >= minRSABits && (alg == algRSASHA256 || alg == algRSASHA384 || alg == algRSASHA512)
	case *ecdsa.PublicKey:
		return (alg == algECDSASHA256 && k.Curve == elliptic.P256()) || (alg == algECDSASHA384 && k.Curve == elliptic.P384())
	}
	return false
}

// certsUsable reports whether every configured certificate satisfies the key rules; used at verify time too.
func certsUsable(certs []*x509.Certificate, alg string) bool {
	for _, c := range certs {
		if c == nil || !keyMatchesAlg(c.PublicKey, alg) {
			return false
		}
	}
	return true
}

func httpsURL(s string) error {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Fragment != "" || u.User != nil {
		return sso.Refuse(ReasonConfig)
	}
	return nil
}

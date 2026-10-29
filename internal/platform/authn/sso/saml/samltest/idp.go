// Package samltest is the in-process SAML IdP of the TM-F-SSO proof (spec §10.1). It signs responses with
// its own keys under a fixed clock, records every (issuer, subject, response ID) it signed so a fuzz oracle
// can tell a forgery from an acceptance, and exposes the mutations the corpus builders apply. It lives under
// sso/saml because it imports the XML libraries (FIT-SSO-1); it is test support and is imported only by tests.
package samltest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net/url"
	"sync"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/russellhaering/goxmldsig/etreeutils"

	"github.com/skenzeriq/activediq/internal/platform/authn/sso"
)

// Fixed names of the test deployment.
const (
	EntityID   = "https://idp.example.test/entity"
	SSOURL     = "https://idp.example.test/sso"
	SPEntityID = "https://console.example.test/sp"
	ACSURL     = "https://console.example.test/auth/sso/idp-1/callback"
	IdPID      = "idp-1"
	Subject    = "f1c3a2e0-0000-4000-8000-000000000001"
)

// Namespaces.
const (
	NSSAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
	NSSAML  = "urn:oasis:names:tc:SAML:2.0:assertion"
	Persist = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
)

// Key is a signing key with a self-signed certificate.
type Key struct {
	Signer crypto.Signer
	Cert   *x509.Certificate
}

var (
	keysOnce                                          sync.Once
	trusted, attacker, weak, p256Key, otherTrustedKey *Key
)

func mk(s crypto.Signer, cn string) *Key {
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, s.Public(), s)
	if err != nil {
		panic(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &Key{Signer: s, Cert: c}
}

func initKeys() {
	keysOnce.Do(func() {
		r2048 := func() *rsa.PrivateKey { k, _ := rsa.GenerateKey(rand.Reader, 2048); return k }
		trusted, attacker, otherTrustedKey = mk(r2048(), "idp"), mk(r2048(), "attacker"), mk(r2048(), "idp-next")
		w, _ := rsa.GenerateKey(rand.Reader, 1024)
		weak = mk(w, "weak")
		e, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		p256Key = mk(e, "ec")
	})
}

// Keys returns the trusted IdP key, an attacker key, a 1024-bit key, a P-256 key and a second trusted key.
func Keys() (idp, atk, wk, ec, next *Key) {
	initKeys()
	return trusted, attacker, weak, p256Key, otherTrustedKey
}

// Env is one test deployment: the IdP, the pinned configuration and the fixed clock.
type Env struct {
	Now    time.Time
	Key    *Key
	Config sso.SAMLConfig
}

// Tuple is what the IdP actually signed; a Verified that is not one is a forgery accepted.
type Tuple struct{ Issuer, Subject, ResponseID string }

// NewEnv returns the known-good deployment at a fixed instant.
func NewEnv() *Env {
	initKeys()
	return &Env{
		Now: time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC),
		Key: trusted,
		Config: sso.SAMLConfig{EntityID: EntityID, SSOURL: SSOURL, Certs: []*x509.Certificate{trusted.Cert},
			Alg: dsig.RSASHA256SignatureMethod, SPEntityID: SPEntityID, ACSURL: ACSURL,
			GroupAttribute: "groups"},
	}
}

// IdP returns the sso.IdP for the verifier.
func (e *Env) IdP() sso.IdP {
	c := e.Config
	return sso.IdP{ID: IdPID, Protocol: sso.ProtocolSAML, Enabled: true, SAML: &c}
}

// Tx is a Transaction as Start would have created it, one second ago.
func (e *Env) Tx(intent sso.Intent) sso.Transaction {
	return sso.Transaction{IdPID: IdPID, Intent: intent, RequestID: "_req-1", CreatedAt: e.Now.Add(-time.Second)}
}

// Signed reports whether the IdP signed exactly this tuple.
func (e *Env) Signed(t Tuple) bool { signedMu.Lock(); defer signedMu.Unlock(); return signedSet[t] }

// The set is process-wide so a fuzz seed built by any Env counts; only the trusted key records into it.
var (
	signedMu  sync.Mutex
	signedSet = map[Tuple]bool{}
)

// Spec describes a response. Zero values are not "good"; use Good.
type Spec struct {
	ResponseID, AssertionID string
	InResponseTo            string
	Destination             string
	Recipient               string
	SCInResponseTo          string
	ConfirmMethod           string
	Status                  string
	Issuer, ResponseIssuer  string
	NameID, NameIDFormat    string
	Audiences               [][]string // one entry per AudienceRestriction
	IssueInstant            time.Time
	NotBefore, NotOnOrAfter time.Time
	SCNotOnOrAfter          time.Time
	AuthnInstant            time.Time
	SessionNotOnOrAfter     time.Time
	ClassRef                string
	Attributes              map[string][]string
	SignAssertion           bool
	SignResponse            bool
	Key                     *Key
	Alg                     string
}

// Good is the known-good spec for tx.
func (e *Env) Good(tx sso.Transaction) Spec {
	return Spec{
		ResponseID: "_resp-1", AssertionID: "_asrt-1", InResponseTo: tx.RequestID, SCInResponseTo: tx.RequestID,
		Destination: ACSURL, Recipient: ACSURL, ConfirmMethod: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
		Status: "urn:oasis:names:tc:SAML:2.0:status:Success", Issuer: EntityID,
		NameID: Subject, NameIDFormat: Persist, Audiences: [][]string{{SPEntityID}},
		IssueInstant: e.Now.Add(-10 * time.Second), NotBefore: e.Now.Add(-30 * time.Second),
		NotOnOrAfter: e.Now.Add(4 * time.Minute), SCNotOnOrAfter: e.Now.Add(4 * time.Minute),
		AuthnInstant: e.Now.Add(-20 * time.Second), ClassRef: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
		Attributes:    map[string][]string{"groups": {"g-1", "g-2"}},
		SignAssertion: true, Key: e.Key, Alg: e.Config.Alg,
	}
}

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func el(parent *etree.Element, name string, kv ...string) *etree.Element {
	c := parent.CreateElement(name)
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] != "" {
			c.CreateAttr(kv[i], kv[i+1])
		}
	}
	return c
}

// Build renders s as an unsigned Response document.
func (e *Env) Build(s Spec) *etree.Document {
	doc := etree.NewDocument()
	doc.CreateProcInst("xml", `version="1.0" encoding="UTF-8"`)
	r := el(&doc.Element, "samlp:Response", "xmlns:samlp", NSSAMLP, "xmlns:saml", NSSAML, "ID", s.ResponseID, "Version", "2.0",
		"IssueInstant", ts(s.IssueInstant), "Destination", s.Destination, "InResponseTo", s.InResponseTo)
	if s.ResponseIssuer != "" {
		el(r, "saml:Issuer").SetText(s.ResponseIssuer)
	}
	st := el(r, "samlp:Status")
	el(st, "samlp:StatusCode", "Value", s.Status)
	a := el(r, "saml:Assertion", "ID", s.AssertionID, "Version", "2.0", "IssueInstant", ts(s.IssueInstant))
	el(a, "saml:Issuer").SetText(s.Issuer)
	sub := el(a, "saml:Subject")
	el(sub, "saml:NameID", "Format", s.NameIDFormat).SetText(s.NameID)
	sc := el(sub, "saml:SubjectConfirmation", "Method", s.ConfirmMethod)
	el(sc, "saml:SubjectConfirmationData", "Recipient", s.Recipient, "InResponseTo", s.SCInResponseTo, "NotOnOrAfter", ts(s.SCNotOnOrAfter))
	c := el(a, "saml:Conditions", "NotOnOrAfter", ts(s.NotOnOrAfter))
	if !s.NotBefore.IsZero() {
		c.CreateAttr("NotBefore", ts(s.NotBefore))
	}
	for _, r := range s.Audiences {
		ar := el(c, "saml:AudienceRestriction")
		for _, au := range r {
			el(ar, "saml:Audience").SetText(au)
		}
	}
	if len(s.Attributes) > 0 {
		as := el(a, "saml:AttributeStatement")
		for _, name := range sortedKeys(s.Attributes) {
			at := el(as, "saml:Attribute", "Name", name)
			for _, v := range s.Attributes[name] {
				el(at, "saml:AttributeValue").SetText(v)
			}
		}
	}
	an := el(a, "saml:AuthnStatement", "AuthnInstant", ts(s.AuthnInstant))
	if !s.SessionNotOnOrAfter.IsZero() {
		an.CreateAttr("SessionNotOnOrAfter", ts(s.SessionNotOnOrAfter))
	}
	el(el(an, "saml:AuthnContext"), "saml:AuthnContextClassRef").SetText(s.ClassRef)
	return doc
}

func sortedKeys(m map[string][]string) []string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	for i := range ks {
		for j := i + 1; j < len(ks); j++ {
			if ks[j] < ks[i] {
				ks[i], ks[j] = ks[j], ks[i]
			}
		}
	}
	return ks
}

// Sign adds an enveloped signature to target (after its Issuer) with key and alg, exclusive C14N.
func Sign(target *etree.Element, key *Key, alg string) *etree.Element {
	sc, err := dsig.NewSigningContext(key.Signer, [][]byte{key.Cert.Raw})
	if err != nil {
		panic(err)
	}
	if err := sc.SetSignatureMethod(alg); err != nil {
		panic(err)
	}
	sc.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	pctx, err := etreeutils.NSBuildParentContext(target)
	if err != nil {
		panic(err)
	}
	detached, err := etreeutils.NSDetatch(pctx, target)
	if err != nil {
		panic(err)
	}
	sig, err := sc.ConstructSignature(detached, true)
	if err != nil {
		panic(err)
	}
	idx := 0
	for i, c := range target.ChildElements() {
		if c.Tag == "Issuer" {
			idx = c.Index() + 1
			_ = i
		}
	}
	target.InsertChildAt(idx, sig)
	return sig
}

// Render builds, signs per the spec and serialises s; the tuple is recorded as signed.
func (e *Env) Render(s Spec) []byte {
	doc := e.Build(s)
	if s.SignAssertion {
		Sign(doc.Root().FindElement("./saml:Assertion"), s.Key, s.Alg)
	}
	if s.SignResponse {
		Sign(doc.Root(), s.Key, s.Alg)
	}
	e.record(s)
	b, err := doc.WriteToBytes()
	if err != nil {
		panic(err)
	}
	return b
}

func (e *Env) record(s Spec) {
	if s.Key != trusted || !s.SignAssertion {
		return
	}
	signedMu.Lock()
	defer signedMu.Unlock()
	signedSet[Tuple{Issuer: s.Issuer, Subject: s.NameID, ResponseID: s.AssertionID}] = true
}

// Form wraps a document the way the browser POSTs it.
func Form(doc []byte) url.Values {
	return url.Values{"SAMLResponse": {base64.StdEncoding.EncodeToString(doc)}, "RelayState": {"x"}}
}

// Callback is the sso.Callback for a POSTed document.
func Callback(doc []byte) sso.Callback { return sso.Callback{IdPID: IdPID, Form: Form(doc)} }

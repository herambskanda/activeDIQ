package saml

import (
	"crypto/x509"
	"encoding/base64"
	"regexp"
	"slices"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/russellhaering/goxmldsig/etreeutils"

	"github.com/skenzeriq/activediq/internal/platform/authn/sso"
)

var ws = regexp.MustCompile(`\s+`)

// checkSignature runs SAML-4, SAML-5, SAML-7 and SAML-8 for the one ds:Signature directly under owner, and
// returns owner as the library verified it: a fresh tree rebuilt from the canonical bytes that were
// digested, not the element that arrived (SAML-6). The shape rules are ours and run before any
// cryptography, so an excluded algorithm or transform is refused whatever the library would do with it.
func checkSignature(owner *etree.Element, cfg *sso.SAMLConfig, now time.Time) (*etree.Element, error) {
	sigs := children(owner, nsDS, "Signature")
	if len(sigs) != 1 {
		return nil, sso.Refuse(ReasonUnsigned)
	}
	sig := sigs[0]
	// Nothing but SignedInfo, SignatureValue and at most one KeyInfo (the library's validateShape, kept
	// here so the reason is ours).
	if one(sig, nsDS, "SignedInfo") == nil || one(sig, nsDS, "SignatureValue") == nil || len(children(sig, nsDS, "KeyInfo")) > 1 {
		return nil, sso.Refuse(ReasonUnsigned)
	}
	si := one(sig, nsDS, "SignedInfo")

	// SAML-8: canonicalisation of SignedInfo is exclusive C14N without comments.
	cm := one(si, nsDS, "CanonicalizationMethod")
	if cm == nil || cm.SelectAttrValue("Algorithm", "") != c14nExclusive {
		return nil, sso.Refuse(ReasonTransform)
	}
	// SAML-7: the configured signature algorithm, nothing else (SHA-1, DSA and HMAC cannot equal a pinned value).
	sm := one(si, nsDS, "SignatureMethod")
	if sm == nil || sm.SelectAttrValue("Algorithm", "") != cfg.Alg {
		return nil, sso.Refuse(ReasonAlg)
	}
	// SAML-4: exactly one Reference, to this owner's ID. An empty URI (the whole document) is refused.
	refs := children(si, nsDS, "Reference")
	if len(refs) != 1 {
		return nil, sso.Refuse(ReasonUnsigned)
	}
	ref := refs[0]
	id := owner.SelectAttrValue("ID", "")
	if uri := ref.SelectAttrValue("URI", ""); id == "" || uri != "#"+id {
		return nil, sso.Refuse(ReasonUnsigned)
	}
	// SAML-8: the transforms are enveloped-signature, then exclusive C14N without comments.
	tr := one(ref, nsDS, "Transforms")
	if tr == nil {
		return nil, sso.Refuse(ReasonTransform)
	}
	ts := children(tr, nsDS, "Transform")
	if len(ts) != 2 || len(tr.ChildElements()) != 2 ||
		ts[0].SelectAttrValue("Algorithm", "") != transformEnveloped || ts[1].SelectAttrValue("Algorithm", "") != c14nExclusive {
		return nil, sso.Refuse(ReasonTransform)
	}
	// SAML-7: digest method.
	dm := one(ref, nsDS, "DigestMethod")
	if dm == nil || !slices.Contains(digestAllowed, dm.SelectAttrValue("Algorithm", "")) {
		return nil, sso.Refuse(ReasonAlg)
	}

	// SAML-5: KeyInfo is never a trust source. If it carries anything but configured certificates, refuse.
	if ki := one(sig, nsDS, "KeyInfo"); ki != nil || len(children(sig, nsDS, "KeyInfo")) > 0 {
		if err := keyInfoConfigured(ki, cfg.Certs); err != nil {
			return nil, err
		}
	}

	// Cryptography, by the library, against each configured certificate alone.
	if !certsUsable(cfg.Certs, cfg.Alg) {
		return nil, sso.Refuse(ReasonAlg)
	}
	for _, cert := range cfg.Certs {
		vc := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}})
		vc.Clock = dsig.NewFakeClockAt(now)
		detached, err := detach(owner)
		if err != nil {
			return nil, sso.Refuse(ReasonUnsigned)
		}
		if verified, err := vc.Validate(detached); err == nil && verified != nil {
			return verified, nil
		}
	}
	return nil, sso.Refuse(ReasonUnsigned)
}

// keyInfoConfigured accepts a KeyInfo only if it holds X509Data whose certificates are all configured.
func keyInfoConfigured(ki *etree.Element, certs []*x509.Certificate) error {
	if ki == nil {
		return sso.Refuse(ReasonKey)
	}
	data := children(ki, nsDS, "X509Data")
	if len(ki.ChildElements()) != 1 || len(data) != 1 {
		return sso.Refuse(ReasonKey)
	}
	cs := children(data[0], nsDS, "X509Certificate")
	if len(cs) == 0 || len(cs) != len(data[0].ChildElements()) {
		return sso.Refuse(ReasonKey)
	}
	for _, c := range cs {
		der, err := base64.StdEncoding.DecodeString(ws.ReplaceAllString(c.Text(), ""))
		if err != nil {
			return sso.Refuse(ReasonKey)
		}
		found := false
		for _, want := range certs {
			if want != nil && string(want.Raw) == string(der) {
				found = true
			}
		}
		if !found {
			return sso.Refuse(ReasonKey)
		}
	}
	return nil
}

// detach copies e with the namespace declarations it inherits, so its canonical form is the one the signer
// digested.
func detach(e *etree.Element) (*etree.Element, error) {
	ctx, err := etreeutils.NSBuildParentContext(e)
	if err != nil {
		return nil, err
	}
	return etreeutils.NSDetatch(ctx, e)
}

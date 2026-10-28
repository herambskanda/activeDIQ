// Package saml is the SAML half of console SSO (ADM-143, T-0202). It implements sso.Verifier and the
// numbered checks SAML-1..19 of knowledge/development/architecture/console-sso.md §5; each refusal carries
// the reason code of that table and each check has a test named for it (TestSAML_Refuses*).
//
// This is the only package that imports the XML-DSig and XML-tree libraries and the only one under
// platform/authn that imports encoding/xml (FIT-SSO-1). The order is fixed: bounds and hygiene, structure,
// signature (shape rules ours, cryptography the library's), and only then the claims, read from the tree
// the signature verified (SAML-6) and never from the document that arrived.
//
// gosaml2 itself is not imported: its response decoder bundles several of these checks behind one error and
// accepts a Response-level signature alone, so no per-check reason code and no SAML-4 would be ours.
// goxmldsig supplies the signature and canonicalisation, which is where the library risk lives (§3.1).
package saml

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/beevik/etree"

	"github.com/skenzeriq/activediq/internal/platform/authn/sso"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

const (
	skew         = 120 * time.Second // SAML-15, fixed
	maxTxAge     = 5 * time.Minute   // SAML-13
	maxAssertAge = 5 * time.Minute   // SAML-15
	stepupMaxAge = 120 * time.Second // SAML-17
	maxSubject   = 255               // bytes
	maxGroups    = 150               // MAP-5, Entra's SAML limit
	statusOK     = "urn:oasis:names:tc:SAML:2.0:status:Success"
	cmBearer     = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
	nameIDPersis = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
)

// Verifier implements sso.Verifier for SAML. Safe for concurrent use.
type Verifier struct {
	replay ReplayCache
	now    func() time.Time
}

var _ sso.Verifier = (*Verifier)(nil)

// New returns a Verifier that records assertion IDs in replay. now defaults to time.Now.
func New(replay ReplayCache, now func() time.Time) *Verifier {
	if now == nil {
		now = time.Now
	}
	return &Verifier{replay: replay, now: now}
}

// usable is SSO-2 plus the config checks, run by both entry points.
func usable(idp sso.IdP) (*sso.SAMLConfig, error) {
	if idp.Protocol != sso.ProtocolSAML || !idp.Enabled || idp.ID == "" {
		return nil, sso.Refuse(ReasonIdP)
	}
	if err := ValidateConfig(idp.SAML); err != nil {
		return nil, err
	}
	return idp.SAML, nil
}

// Start builds the AuthnRequest redirect (HTTP-Redirect binding) and the Transaction it must come back to.
// A step-up request sets ForceAuthn so the IdP re-authenticates (spec §3).
func (v *Verifier) Start(_ context.Context, _ tenant.ID, idp sso.IdP, intent sso.Intent) (*url.URL, sso.Transaction, error) {
	cfg, err := usable(idp)
	if err != nil {
		return nil, sso.Transaction{}, err
	}
	if intent != sso.IntentSignin && intent != sso.IntentStepup {
		return nil, sso.Transaction{}, sso.Refuse("sso.intent")
	}
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, sso.Transaction{}, sso.Refuse(ReasonConfig)
	}
	id := "_" + hex.EncodeToString(idBytes)
	now := v.now().UTC()

	doc := etree.NewDocument()
	req := doc.CreateElement("samlp:AuthnRequest")
	req.CreateAttr("xmlns:samlp", nsSAMLP)
	req.CreateAttr("xmlns:saml", nsSAML)
	req.CreateAttr("ID", id)
	req.CreateAttr("Version", "2.0")
	req.CreateAttr("IssueInstant", now.Format(time.RFC3339))
	req.CreateAttr("Destination", cfg.SSOURL)
	req.CreateAttr("ProtocolBinding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST")
	req.CreateAttr("AssertionConsumerServiceURL", cfg.ACSURL)
	if intent == sso.IntentStepup {
		req.CreateAttr("ForceAuthn", "true")
	}
	req.CreateElement("saml:Issuer").SetText(cfg.SPEntityID)
	xmlBytes, err := doc.WriteToBytes()
	if err != nil {
		return nil, sso.Transaction{}, sso.Refuse(ReasonConfig)
	}
	var buf bytes.Buffer
	fw, _ := flate.NewWriter(&buf, flate.BestCompression)
	_, _ = fw.Write(xmlBytes)
	_ = fw.Close()

	u, err := url.Parse(cfg.SSOURL)
	if err != nil {
		return nil, sso.Transaction{}, sso.Refuse(ReasonConfig)
	}
	q := u.Query()
	q.Set("SAMLRequest", base64.StdEncoding.EncodeToString(buf.Bytes()))
	u.RawQuery = q.Encode()
	return u, sso.Transaction{IdPID: idp.ID, Intent: intent, RequestID: id, CreatedAt: now}, nil
}

// Complete verifies the ACS POST against tx. It returns Verified only when every check of spec §5 holds.
func (v *Verifier) Complete(ctx context.Context, t tenant.ID, idp sso.IdP, tx sso.Transaction, cb sso.Callback) (sso.Verified, error) {
	cfg, err := usable(idp)
	if err != nil {
		return sso.Verified{}, err
	}
	// SSO-2: the callback path, the Transaction and the IdP name the same IdP.
	if tx.IdPID == "" || cb.IdPID != tx.IdPID || tx.IdPID != idp.ID {
		return sso.Verified{}, sso.Refuse(ReasonIdP)
	}
	now := v.now()

	raw, err := decode(cb.Form)
	if err != nil {
		return sso.Verified{}, err
	}
	if err := hygiene(raw); err != nil {
		return sso.Verified{}, err
	}
	p, err := structure(raw)
	if err != nil {
		return sso.Verified{}, err
	}

	// SAML-4/5/7/8: the Assertion signature, always. A Response signature is verified as well but never
	// stands in for it.
	verified, err := checkSignature(p.assertion, cfg, now)
	if err != nil {
		return sso.Verified{}, err
	}
	if len(children(p.response, nsDS, "Signature")) > 0 {
		if _, err := checkSignature(p.response, cfg, now); err != nil {
			return sso.Verified{}, err
		}
	}
	// SAML-6: what the library verified is the Assertion SAML-3 found.
	if verified.Tag != "Assertion" || verified.NamespaceURI() != nsSAML || verified.SelectAttrValue("ID", "") != p.asrtID {
		return sso.Verified{}, sso.Refuse(ReasonWrapped)
	}

	// From here on, claims come from `verified` only. The Response attributes below (Status, Destination,
	// InResponseTo) are refusal conditions: a forged value can only cause a refusal, never an acceptance,
	// because the Assertion's own signed Recipient, InResponseTo and Audience must also hold.
	if err := checkResponse(p.response, cfg, tx, now); err != nil {
		return sso.Verified{}, err
	}
	a, err := readAssertion(verified)
	if err != nil {
		return sso.Verified{}, err
	}
	if err := a.check(cfg, tx, now); err != nil {
		return sso.Verified{}, err
	}
	out, err := a.verified(cfg, tx, now)
	if err != nil {
		return sso.Verified{}, err
	}

	// SAML-16, last, so that only a response that passed everything else uses up its ID.
	// The expiry MUST be a pure function of signed fields (NotOnOrAfter, IssueInstant), never of the clock:
	// the replay cache trims expired rows, and a replay after the trim is refused only because it recomputes
	// the same past expiry (see replay_pg.go sqlReplayTrim). Do not change this to now+X.
	fresh, err := v.replay.Remember(ctx, t, idp.ID, a.id, a.replayUntil().Add(skew))
	if err != nil {
		return sso.Verified{}, &sso.Refusal{Reason: ReasonReplay, Cause: err}
	}
	if !fresh {
		return sso.Verified{}, sso.Refuse(ReasonReplay)
	}
	return out, nil
}

// checkResponse covers SAML-9 (Status), SAML-10 (Response Issuer), SAML-11 (Destination) and the Response
// half of SAML-13.
func checkResponse(r *etree.Element, cfg *sso.SAMLConfig, tx sso.Transaction, now time.Time) error {
	st := one(r, nsSAMLP, "Status")
	if st == nil {
		return sso.Refuse(ReasonStatus)
	}
	sc := one(st, nsSAMLP, "StatusCode")
	if sc == nil || sc.SelectAttrValue("Value", "") != statusOK {
		return sso.Refuse(ReasonStatus)
	}
	if iss := children(r, nsSAML, "Issuer"); len(iss) > 1 || (len(iss) == 1 && !exactText(iss[0], cfg.EntityID)) {
		return sso.Refuse(ReasonIssuer)
	}
	if r.SelectAttrValue("Destination", "") != cfg.ACSURL {
		return sso.Refuse(ReasonDestination)
	}
	if tx.RequestID == "" || tx.CreatedAt.IsZero() || now.Sub(tx.CreatedAt) > maxTxAge || tx.CreatedAt.After(now.Add(skew)) ||
		r.SelectAttrValue("InResponseTo", "") != tx.RequestID {
		return sso.Refuse(ReasonInResponseTo)
	}
	return nil
}

func exactText(e *etree.Element, want string) bool {
	s, ok := leafText(e)
	return ok && s == want
}

// leafText is the text of an element that has no child elements; anything else is not a plain value.
func leafText(e *etree.Element) (string, bool) {
	if len(e.ChildElements()) != 0 {
		return "", false
	}
	return e.Text(), true
}

func parseTime(s string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339Nano, s)
	return t, err == nil
}

// assertion is the verified Assertion, read once.
type assertion struct {
	id           string
	issuer       *etree.Element
	issuerCount  int
	issueInstant time.Time
	issueOK      bool
	subject      *etree.Element
	conditions   *etree.Element
	authn        []*etree.Element
	attrs        map[string][]string
}

func readAssertion(e *etree.Element) (*assertion, error) {
	a := &assertion{id: e.SelectAttrValue("ID", ""), attrs: map[string][]string{}}
	if e.SelectAttrValue("Version", "") != "2.0" {
		return nil, sso.Refuse(ReasonStructure)
	}
	a.issueInstant, a.issueOK = parseTime(e.SelectAttrValue("IssueInstant", ""))
	iss := children(e, nsSAML, "Issuer")
	a.issuerCount = len(iss)
	if len(iss) == 1 {
		a.issuer = iss[0]
	}
	a.subject = one(e, nsSAML, "Subject")
	a.conditions = one(e, nsSAML, "Conditions")
	a.authn = children(e, nsSAML, "AuthnStatement")
	for _, st := range children(e, nsSAML, "AttributeStatement") {
		for _, at := range children(st, nsSAML, "Attribute") {
			name := at.SelectAttrValue("Name", "")
			for _, av := range children(at, nsSAML, "AttributeValue") {
				s, ok := leafText(av)
				if !ok {
					return nil, sso.Refuse(ReasonStructure)
				}
				a.attrs[name] = append(a.attrs[name], s)
			}
		}
	}
	return a, nil
}

// check covers SAML-10 (Assertion Issuer), SAML-12, SAML-13, SAML-14, SAML-15 and SAML-17.
func (a *assertion) check(cfg *sso.SAMLConfig, tx sso.Transaction, now time.Time) error {
	if a.issuerCount != 1 || !exactText(a.issuer, cfg.EntityID) {
		return sso.Refuse(ReasonIssuer)
	}
	if err := a.bearer(cfg, tx, now); err != nil {
		return err
	}
	if err := a.audience(cfg); err != nil {
		return err
	}
	return a.timing(now)
}

// bearer is SAML-12 and the Assertion half of SAML-13.
func (a *assertion) bearer(cfg *sso.SAMLConfig, tx sso.Transaction, now time.Time) error {
	if a.subject == nil {
		return sso.Refuse(ReasonRecipient)
	}
	addressed := false
	for _, sc := range children(a.subject, nsSAML, "SubjectConfirmation") {
		if sc.SelectAttrValue("Method", "") != cmBearer {
			continue
		}
		d := one(sc, nsSAML, "SubjectConfirmationData")
		if d == nil || d.SelectAttrValue("Recipient", "") != cfg.ACSURL {
			continue
		}
		if noa, ok := parseTime(d.SelectAttrValue("NotOnOrAfter", "")); !ok || !noa.After(now.Add(-skew)) {
			continue
		}
		addressed = true
		if tx.RequestID != "" && d.SelectAttrValue("InResponseTo", "") == tx.RequestID {
			return nil
		}
	}
	if addressed {
		return sso.Refuse(ReasonInResponseTo)
	}
	return sso.Refuse(ReasonRecipient)
}

// audience is SAML-14: every AudienceRestriction restricts, so every one must contain our entityID.
func (a *assertion) audience(cfg *sso.SAMLConfig) error {
	if a.conditions == nil {
		return sso.Refuse(ReasonAudience)
	}
	rs := children(a.conditions, nsSAML, "AudienceRestriction")
	if len(rs) == 0 {
		return sso.Refuse(ReasonAudience)
	}
	for _, r := range rs {
		ok := false
		for _, au := range children(r, nsSAML, "Audience") {
			if exactText(au, cfg.SPEntityID) {
				ok = true
			}
		}
		if !ok {
			return sso.Refuse(ReasonAudience)
		}
	}
	return nil
}

// timing is SAML-15.
func (a *assertion) timing(now time.Time) error {
	if !a.issueOK || a.issueInstant.After(now.Add(skew)) || now.Sub(a.issueInstant) > maxAssertAge+skew {
		return sso.Refuse(ReasonTime)
	}
	if nb := a.conditions.SelectAttrValue("NotBefore", ""); nb != "" {
		t, ok := parseTime(nb)
		if !ok || t.After(now.Add(skew)) {
			return sso.Refuse(ReasonTime)
		}
	}
	noa, ok := parseTime(a.conditions.SelectAttrValue("NotOnOrAfter", ""))
	if !ok || !noa.After(now.Add(-skew)) {
		return sso.Refuse(ReasonTime)
	}
	return nil
}

// replayUntil is when the assertion can no longer be accepted by SAML-15, before the skew is added.
func (a *assertion) replayUntil() time.Time {
	noa, _ := parseTime(a.conditions.SelectAttrValue("NotOnOrAfter", ""))
	if lim := a.issueInstant.Add(maxAssertAge); lim.After(noa) {
		return lim
	}
	return noa
}

// verified is SAML-17 (AuthnStatement), SAML-18 (subject), the anchor, the group claim and MFA evidence.
func (a *assertion) verified(cfg *sso.SAMLConfig, tx sso.Transaction, now time.Time) (sso.Verified, error) {
	out := sso.Verified{Issuer: cfg.EntityID, ResponseID: a.id}

	if len(a.authn) == 0 {
		return out, sso.Refuse(ReasonAuthn)
	}
	var classRefs []string
	for i, as := range a.authn {
		inst, ok := parseTime(as.SelectAttrValue("AuthnInstant", ""))
		if !ok || inst.After(now.Add(skew)) {
			return out, sso.Refuse(ReasonAuthn)
		}
		if tx.Intent == sso.IntentStepup && now.Sub(inst) > stepupMaxAge+skew {
			return out, sso.Refuse(ReasonAuthn)
		}
		if i == 0 || inst.Before(out.AuthTime) {
			out.AuthTime = inst // the oldest authentication is the one the session may rely on
		}
		if s := as.SelectAttrValue("SessionNotOnOrAfter", ""); s != "" {
			t, ok := parseTime(s)
			if !ok {
				return out, sso.Refuse(ReasonAuthn)
			}
			if out.SessionCap.IsZero() || t.Before(out.SessionCap) {
				out.SessionCap = t
			}
		}
		if ctx := one(as, nsSAML, "AuthnContext"); ctx != nil {
			for _, ref := range children(ctx, nsSAML, "AuthnContextClassRef") {
				if s, ok := leafText(ref); ok && s != "" {
					classRefs = append(classRefs, s)
				}
			}
		}
	}
	if tx.Intent == sso.IntentStepup && now.Sub(out.AuthTime) > stepupMaxAge+skew {
		return out, sso.Refuse(ReasonAuthn)
	}

	sub, err := a.accountSubject(cfg)
	if err != nil {
		return out, err
	}
	out.Subject = sub

	if out.Anchor, err = a.anchor(cfg); err != nil {
		return out, err
	}
	if cfg.GroupAttribute != "" {
		groups := a.attrs[cfg.GroupAttribute]
		if len(groups) > maxGroups {
			out.Warnings = append(out.Warnings, "saml.groups_overage")
		} else {
			out.GroupClaims = slices.Clone(groups)
		}
	}

	out.Methods = slices.Clone(classRefs)
	if cfg.MFAMode == sso.MFAClaim {
		have := classRefs
		if cfg.MFAAttribute != "" {
			have = a.attrs[cfg.MFAAttribute]
			out.Methods = append(out.Methods, have...)
		}
		for _, ev := range cfg.MFAEvidence {
			if slices.Contains(have, ev) {
				out.MFAAsserted = true
			}
		}
	}
	return out, nil
}

// accountSubject is SAML-18: a persistent NameID by default, or the one named attribute. Transient,
// email-format and unspecified NameIDs are never the subject.
func (a *assertion) accountSubject(cfg *sso.SAMLConfig) (string, error) {
	var sub string
	if cfg.SubjectAttribute != "" {
		vals := a.attrs[cfg.SubjectAttribute]
		if len(vals) != 1 {
			return "", sso.Refuse(ReasonSubject)
		}
		sub = vals[0]
	} else {
		ids := children(a.subject, nsSAML, "NameID")
		if len(ids) != 1 || ids[0].SelectAttrValue("Format", "") != nameIDPersis {
			return "", sso.Refuse(ReasonSubject)
		}
		s, ok := leafText(ids[0])
		if !ok {
			return "", sso.Refuse(ReasonSubject)
		}
		sub = s
	}
	if sub == "" || len(sub) > maxSubject || strings.TrimSpace(sub) != sub {
		return "", sso.Refuse(ReasonSubject)
	}
	return sub, nil
}

func (a *assertion) anchor(cfg *sso.SAMLConfig) (*sso.Anchor, error) {
	if cfg.AnchorClaim == "" {
		return nil, nil
	}
	vals := a.attrs[cfg.AnchorAttribute]
	if len(vals) != 1 || vals[0] == "" {
		return nil, sso.Refuse(ReasonAnchor)
	}
	an := &sso.Anchor{Claim: cfg.AnchorClaim, Value: vals[0]}
	if cfg.AnchorClaim == "oid" {
		tid := a.attrs[cfg.TenantAttribute]
		if len(tid) != 1 || tid[0] == "" || (cfg.EntraTenantID != "" && tid[0] != cfg.EntraTenantID) {
			return nil, sso.Refuse(ReasonAnchor)
		}
		an.TID = tid[0]
	}
	return an, nil
}

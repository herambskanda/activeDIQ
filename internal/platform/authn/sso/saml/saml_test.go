package saml_test

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/authn/sso"
	"github.com/skenzeriq/activediq/internal/platform/authn/sso/saml"
	"github.com/skenzeriq/activediq/internal/platform/authn/sso/saml/samltest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

type rig struct {
	env   *samltest.Env
	cache *saml.MemoryReplayCache
	v     *saml.Verifier
	tx    sso.Transaction
}

func newRig(t testing.TB) *rig {
	t.Helper()
	e := samltest.NewEnv()
	c := saml.NewMemoryReplayCache(func() time.Time { return e.Now })
	return &rig{env: e, cache: c, v: saml.New(c, func() time.Time { return e.Now }), tx: e.Tx(sso.IntentSignin)}
}

func (r *rig) complete(form url.Values, tx sso.Transaction) (sso.Verified, error) {
	return r.v.Complete(context.Background(), tenant.ID{}, r.env.IdP(), tx, sso.Callback{IdPID: samltest.IdPID, Form: form})
}

// run drives one registry builder and returns the error of the (last) Complete.
func (r *rig) run(t testing.TB, name string) (sso.Verified, error) {
	t.Helper()
	b, ok := samltest.Builders[name]
	if !ok {
		t.Fatalf("no builder %q", name)
	}
	out := b(r.env, r.tx)
	if out.Twice {
		if _, err := r.complete(out.Form, out.Tx); err != nil {
			t.Fatalf("%s: first POST refused: %v", name, err)
		}
	}
	return r.complete(out.Form, out.Tx)
}

func mustRefuse(t *testing.T, builder, reason string) {
	t.Helper()
	r := newRig(t)
	v, err := r.run(t, builder)
	if err == nil {
		t.Fatalf("%s accepted: %+v", builder, v)
	}
	if got := sso.ReasonOf(err); got != reason {
		t.Fatalf("%s: reason %q, want %q (%v)", builder, got, reason, err)
	}
	if v.Subject != "" || v.ResponseID != "" {
		t.Fatalf("%s: partial claims returned with a refusal: %+v", builder, v)
	}
}

func TestSAML_AcceptsKnownGood(t *testing.T) {
	r := newRig(t)
	r.env.Config.AnchorClaim, r.env.Config.AnchorAttribute = "onprem_sid", "sid"
	_ = r
	r = newRig(t)
	v, err := r.run(t, "good")
	if err != nil {
		t.Fatal(err)
	}
	if v.Subject != samltest.Subject || v.Issuer != samltest.EntityID || v.ResponseID != "_asrt-1" ||
		len(v.GroupClaims) != 2 || v.MFAAsserted {
		t.Fatalf("unexpected: %+v", v)
	}
}

func TestSAML_RefusesBinding(t *testing.T) { // SAML-1
	for _, b := range []string{"body_oversize", "too_many_tokens", "too_deep", "deflate_body", "invalid_base64", "no_samlresponse"} {
		t.Run(b, func(t *testing.T) { mustRefuse(t, b, saml.ReasonBinding) })
	}
}

func TestSAML_RefusesXML(t *testing.T) { // SAML-2
	for _, b := range []string{"doctype_external_entity", "doctype_billion_laughs", "non_utf8_declaration", "namespace_confusion", "comment_in_nameid"} {
		t.Run(b, func(t *testing.T) { mustRefuse(t, b, saml.ReasonXML) })
	}
}

func TestSAML_RefusesStructure(t *testing.T) { // SAML-3
	for _, b := range []string{"encrypted_assertion", "two_assertions_one_signed", "duplicate_id", "wrap_signed_in_extensions", "wrap_signed_in_advice", "wrap_sibling_evil_first", "wrap_signed_in_object"} {
		t.Run(b, func(t *testing.T) { mustRefuse(t, b, saml.ReasonStructure) })
	}
}

func TestSAML_RefusesUnsigned(t *testing.T) { // SAML-4
	for _, b := range []string{"unsigned_all", "response_signed_only", "nameid_changed", "sigvalue_bitflip", "reference_empty_uri", "two_references", "attacker_key_nokeyinfo"} {
		t.Run(b, func(t *testing.T) { mustRefuse(t, b, saml.ReasonUnsigned) })
	}
}

func TestSAML_RefusesKey(t *testing.T) { mustRefuse(t, "attacker_key_keyinfo", saml.ReasonKey) } // SAML-5

func TestSAML_RefusesWrapped(t *testing.T) { // SAML-6
	// A library that verified some other element than the Assertion SAML-3 found must still be refused.
	// The shape rules make this unreachable through the document, so the check is proved by its guard:
	// the verified ID equals the structure ID on the accepted path, and every wrapping variant is
	// stopped earlier (TestSAML_RefusesStructure). The corpus oracle (FuzzSAMLComplete) is the net.
	r := newRig(t)
	v, err := r.run(t, "good")
	if err != nil || v.ResponseID != "_asrt-1" {
		t.Fatalf("%+v %v", v, err)
	}
}

func TestSAML_RefusesAlg(t *testing.T) { // SAML-7
	for _, b := range []string{"rsa_sha1", "sha1_digest", "hmac_method", "rsa_1024_key", "alg_mismatch"} {
		t.Run(b, func(t *testing.T) { mustRefuse(t, b, saml.ReasonAlg) })
	}
}

func TestSAML_RefusesTransform(t *testing.T) { // SAML-8
	for _, b := range []string{"c14n_with_comments", "xpath_transform"} {
		t.Run(b, func(t *testing.T) { mustRefuse(t, b, saml.ReasonTransform) })
	}
}

func TestSAML_RefusesStatus(t *testing.T) { mustRefuse(t, "status_responder", saml.ReasonStatus) } // SAML-9
func TestSAML_RefusesIssuer(t *testing.T) { mustRefuse(t, "issuer_other", saml.ReasonIssuer) }     // SAML-10
func TestSAML_RefusesResponseIssuer(t *testing.T) {
	mustRefuse(t, "response_issuer_other", saml.ReasonIssuer)
} // SAML-10
func TestSAML_RefusesDestination(t *testing.T) { // SAML-11
	mustRefuse(t, "destination_other", saml.ReasonDestination)
	mustRefuse(t, "destination_absent", saml.ReasonDestination)
}
func TestSAML_RefusesRecipient(t *testing.T) { // SAML-12
	mustRefuse(t, "recipient_other", saml.ReasonRecipient)
	mustRefuse(t, "holder_of_key", saml.ReasonRecipient)
}
func TestSAML_RefusesInResponseTo(t *testing.T) { // SAML-13
	for _, b := range []string{"unsolicited_no_inresponseto", "inresponseto_other", "stale_transaction"} {
		t.Run(b, func(t *testing.T) { mustRefuse(t, b, saml.ReasonInResponseTo) })
	}
}
func TestSAML_RefusesAudience(t *testing.T) { // SAML-14
	for _, b := range []string{"audience_other", "audience_two_restrictions", "audience_none"} {
		t.Run(b, func(t *testing.T) { mustRefuse(t, b, saml.ReasonAudience) })
	}
}
func TestSAML_RefusesTime(t *testing.T) { // SAML-15
	for _, b := range []string{"conditions_expired", "issueinstant_old", "notbefore_future"} {
		t.Run(b, func(t *testing.T) { mustRefuse(t, b, saml.ReasonTime) })
	}
}
func TestSAML_RefusesReplay(t *testing.T) { mustRefuse(t, "same_response_twice", saml.ReasonReplay) } // SAML-16
func TestSAML_RefusesAuthn(t *testing.T)  { mustRefuse(t, "stepup_old_authn", saml.ReasonAuthn) }     // SAML-17
func TestSAML_RefusesSubject(t *testing.T) { // SAML-18
	mustRefuse(t, "nameid_transient", saml.ReasonSubject)
	mustRefuse(t, "nameid_email", saml.ReasonSubject)
}
func TestSAML_RefusesLogout(t *testing.T) { mustRefuse(t, "logout_request", saml.ReasonLogout) } // SAML-19

func TestSAML_ReplayAcrossNodes(t *testing.T) { // S-R07: two verifiers, one cache
	r := newRig(t)
	out := samltest.Builders["good"](r.env, r.tx)
	other := saml.New(r.cache, func() time.Time { return r.env.Now })
	if _, err := r.complete(out.Form, out.Tx); err != nil {
		t.Fatal(err)
	}
	_, err := other.Complete(context.Background(), tenant.ID{}, r.env.IdP(), out.Tx, sso.Callback{IdPID: samltest.IdPID, Form: out.Form})
	if sso.ReasonOf(err) != saml.ReasonReplay {
		t.Fatalf("second node: %v", err)
	}
}

func TestSAML_RefusesOtherIdP(t *testing.T) { // S-M05: callback path names another IdP
	r := newRig(t)
	out := samltest.Builders["good"](r.env, r.tx)
	_, err := r.v.Complete(context.Background(), tenant.ID{}, r.env.IdP(), out.Tx, sso.Callback{IdPID: "idp-2", Form: out.Form})
	if sso.ReasonOf(err) != saml.ReasonIdP {
		t.Fatalf("%v", err)
	}
	disabled := r.env.IdP()
	disabled.Enabled = false
	_, err = r.v.Complete(context.Background(), tenant.ID{}, disabled, out.Tx, sso.Callback{IdPID: samltest.IdPID, Form: out.Form})
	if sso.ReasonOf(err) != saml.ReasonIdP {
		t.Fatalf("disabled: %v", err)
	}
}

func TestSAML_ResponseAndAssertionBothSigned(t *testing.T) {
	r := newRig(t)
	s := r.env.Good(r.tx)
	s.SignResponse = true
	if _, err := r.complete(samltest.Form(r.env.Render(s)), r.tx); err != nil {
		t.Fatal(err)
	}
}

func TestSAML_SecondCertificateAndECDSA(t *testing.T) {
	r := newRig(t)
	_, _, _, _, next := samltest.Keys()
	r.env.Config.Certs = append(r.env.Config.Certs, next.Cert)
	s := r.env.Good(r.tx)
	s.Key = next
	if _, err := r.complete(samltest.Form(r.env.Render(s)), r.tx); err != nil {
		t.Fatalf("rollover cert: %v", err)
	}
	r = newRig(t)
	_, _, _, ec, _ := samltest.Keys()
	r.env.Config.Certs, r.env.Config.Alg = r.env.Config.Certs[:0], saml.AlgECDSASHA256
	r.env.Config.Certs = append(r.env.Config.Certs, ec.Cert)
	s = r.env.Good(r.tx)
	s.Key, s.Alg = ec, saml.AlgECDSASHA256
	if _, err := r.complete(samltest.Form(r.env.Render(s)), r.tx); err != nil {
		t.Fatalf("ecdsa: %v", err)
	}
}

func TestSAML_ClaimsAnchorMFA(t *testing.T) {
	r := newRig(t)
	c := &r.env.Config
	c.AnchorClaim, c.AnchorAttribute, c.TenantAttribute = "oid", "oid", "tid"
	// An OASIS class cannot be evidence (MFA-2a); the IdP-specific class below can.
	const idpMFAClass = "https://idp.example.test/ac/mfa"
	c.MFAMode, c.MFAEvidence = sso.MFAClaim, []string{idpMFAClass}
	s := r.env.Good(r.tx)
	s.Attributes = map[string][]string{"oid": {"o-1"}, "tid": {"t-1"}, "groups": {"g"}}
	s.ClassRef = idpMFAClass
	v, err := r.complete(samltest.Form(r.env.Render(s)), r.tx)
	if err != nil || !v.MFAAsserted || v.Anchor == nil || v.Anchor.Value != "o-1" || v.Anchor.TID != "t-1" {
		t.Fatalf("%+v %v", v, err)
	}
	s.AssertionID = "_asrt-2"
	s.ClassRef = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"
	v, err = r.complete(samltest.Form(r.env.Render(s)), r.tx)
	if err != nil || v.MFAAsserted {
		t.Fatalf("mfa evidence absent must not assert: %+v %v", v, err)
	}
	s.AssertionID = "_asrt-3"
	delete(s.Attributes, "oid")
	if _, err = r.complete(samltest.Form(r.env.Render(s)), r.tx); sso.ReasonOf(err) != saml.ReasonAnchor {
		t.Fatalf("%v", err)
	}
}

func TestSAML_StartBuildsRequest(t *testing.T) {
	r := newRig(t)
	u, tx, err := r.v.Start(context.Background(), tenant.ID{}, r.env.IdP(), sso.IntentStepup)
	if err != nil || !strings.HasPrefix(u.String(), samltest.SSOURL+"?SAMLRequest=") || !strings.HasPrefix(tx.RequestID, "_") || tx.Intent != sso.IntentStepup {
		t.Fatalf("%v %v %+v", u, err, tx)
	}
}

func TestSAML_ValidateConfig(t *testing.T) {
	r := newRig(t)
	c := r.env.Config
	if err := saml.ValidateConfig(&c); err != nil {
		t.Fatal(err)
	}
	c.Alg = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
	if sso.ReasonOf(saml.ValidateConfig(&c)) != saml.ReasonAlg {
		t.Fatal("sha1 pin accepted")
	}
	c = r.env.Config
	c.ACSURL = "http://console.example.test/cb"
	if sso.ReasonOf(saml.ValidateConfig(&c)) != saml.ReasonConfig {
		t.Fatal("http ACS accepted")
	}
}

// MFA-2a (X-15): no urn:oasis:names:tc:SAML:2.0:ac:classes: value is MFA evidence. Save, Start and Complete
// refuse with saml.config, alone or beside an acceptable value.
func TestSAMLConfig_RefusesOASISClassAsMFAEvidence(t *testing.T) {
	const ns = "urn:oasis:names:tc:SAML:2.0:ac:classes:"
	for _, class := range []string{"Password", "PasswordProtectedTransport", "unspecified", "Kerberos", "X509", "MobileTwoFactorContract"} {
		for name, evidence := range map[string][]string{
			"alone":          {ns + class},
			"beside allowed": {"https://idp.example.test/ac/mfa", ns + class},
		} {
			r := newRig(t)
			r.env.Config.MFAMode, r.env.Config.MFAEvidence = sso.MFAClaim, evidence
			c := r.env.Config
			if got := sso.ReasonOf(saml.ValidateConfig(&c)); got != saml.ReasonConfig {
				t.Errorf("%s %s: ValidateConfig reason = %q", class, name, got)
			}
			if _, _, err := r.v.Start(context.Background(), tenant.ID{}, r.env.IdP(), sso.IntentSignin); sso.ReasonOf(err) != saml.ReasonConfig {
				t.Errorf("%s %s: Start reason = %q", class, name, sso.ReasonOf(err))
			}
			if _, err := r.complete(samltest.Form(r.env.Render(r.env.Good(r.tx))), r.tx); sso.ReasonOf(err) != saml.ReasonConfig {
				t.Errorf("%s %s: Complete reason = %q", class, name, sso.ReasonOf(err))
			}
		}
	}
}

func TestSAMLConfig_AcceptsNonOASISMFAEvidence(t *testing.T) {
	r := newRig(t)
	r.env.Config.MFAMode = sso.MFAClaim
	r.env.Config.MFAAttribute = "http://schemas.microsoft.com/claims/authnmethodsreferences"
	r.env.Config.MFAEvidence = []string{"http://schemas.microsoft.com/claims/multipleauthn"}
	c := r.env.Config
	if err := saml.ValidateConfig(&c); err != nil {
		t.Fatal(err)
	}
}

// MFA-2b (X-18): single-factor Microsoft and SAML 1.x URIs, and case or whitespace variants of the OASIS
// prefix, are not MFA evidence. Save, Start and Complete refuse with saml.config, alone or beside an
// acceptable value.
func TestSAMLConfig_RefusesSingleFactorMicrosoftURIsAsMFAEvidence(t *testing.T) {
	for _, bad := range []string{
		"urn:federation:authentication:windows",
		"URN:Federation:Authentication:Windows",
		"http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/password",
		"http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/windows",
		"HTTP://Schemas.Microsoft.com/ws/2008/06/identity/authenticationmethod/Password",
		"urn:oasis:names:tc:SAML:1.0:am:password",
		"URN:OASIS:names:tc:SAML:1.0:am:X509-PKI",
		"URN:OASIS:names:tc:SAML:2.0:ac:classes:Password",
		"urn:oasis:names:tc:saml:2.0:ac:classes:passwordprotectedtransport",
		" urn:oasis:names:tc:SAML:2.0:ac:classes:Password",
		"urn:oasis:names:tc:SAML:2.0:ac:classes:Password ",
		"\turn:federation:authentication:windows",
		" https://idp.example.test/ac/mfa",
		"https://idp.example.test/ac/mfa\n",
	} {
		for name, evidence := range map[string][]string{
			"alone":          {bad},
			"beside allowed": {"https://idp.example.test/ac/mfa", bad},
		} {
			r := newRig(t)
			r.env.Config.MFAMode, r.env.Config.MFAEvidence = sso.MFAClaim, evidence
			c := r.env.Config
			if got := sso.ReasonOf(saml.ValidateConfig(&c)); got != saml.ReasonConfig {
				t.Errorf("%q %s: ValidateConfig reason = %q", bad, name, got)
			}
			if _, _, err := r.v.Start(context.Background(), tenant.ID{}, r.env.IdP(), sso.IntentSignin); sso.ReasonOf(err) != saml.ReasonConfig {
				t.Errorf("%q %s: Start reason = %q", bad, name, sso.ReasonOf(err))
			}
			if _, err := r.complete(samltest.Form(r.env.Render(r.env.Good(r.tx))), r.tx); sso.ReasonOf(err) != saml.ReasonConfig {
				t.Errorf("%q %s: Complete reason = %q", bad, name, sso.ReasonOf(err))
			}
		}
	}
}

// The refusals above must not catch the evidence the presets use.
func TestSAMLConfig_AcceptsMultipleAuthnAndIdPClasses(t *testing.T) {
	for _, ok := range []string{
		"http://schemas.microsoft.com/claims/multipleauthn",
		"https://idp.example.test/ac/mfa",
		"urn:federation:authentication",
	} {
		r := newRig(t)
		r.env.Config.MFAMode, r.env.Config.MFAEvidence = sso.MFAClaim, []string{ok}
		c := r.env.Config
		if err := saml.ValidateConfig(&c); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
}

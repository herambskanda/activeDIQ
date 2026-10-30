package samltest

import (
	"bytes"
	"compress/flate"
	"crypto/x509"
	"net/url"
	"strings"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/russellhaering/goxmldsig/etreeutils"

	"github.com/skenzeriq/activediq/internal/platform/authn/sso"
)

// Out is what a corpus builder produces: the form to POST, the Transaction to complete against, and whether
// the same POST is made twice (the second must be the one refused).
type Out struct {
	Form  url.Values
	Tx    sso.Transaction
	Twice bool
}

// Builder produces the bytes of one corpus case from a known-good response (spec §10.1). A builder may
// change e.Config before the verifier is built (a weak certificate, a different pin).
type Builder func(e *Env, tx sso.Transaction) Out

func raw(tx sso.Transaction, doc []byte) Out { return Out{Form: Form(doc), Tx: tx} }

func parse(b []byte) *etree.Document {
	d := etree.NewDocument()
	if err := d.ReadFromBytes(b); err != nil {
		panic(err)
	}
	return d
}

func write(d *etree.Document) []byte {
	b, err := d.WriteToBytes()
	if err != nil {
		panic(err)
	}
	return b
}

func assertionOf(d *etree.Document) *etree.Element { return d.Root().FindElement("./saml:Assertion") }

func sigOf(parent *etree.Element) *etree.Element { return parent.FindElement("./ds:Signature") }

// spec edits a known-good Spec, signs and renders it.
func spec(edit func(*Env, *Spec)) Builder {
	return func(e *Env, tx sso.Transaction) Out {
		s := e.Good(tx)
		edit(e, &s)
		return raw(tx, e.Render(s))
	}
}

// post-sign edit of the XML of a known-good signed response.
func doc(edit func(*Env, *etree.Document)) Builder {
	return func(e *Env, tx sso.Transaction) Out {
		d := parse(e.Render(e.Good(tx)))
		edit(e, d)
		return raw(tx, write(d))
	}
}

func setAlg(tag, alg string) func(*Env, *etree.Document) {
	return func(_ *Env, d *etree.Document) {
		sigOf(assertionOf(d)).FindElement("./ds:SignedInfo/ds:" + tag).RemoveAttr("Algorithm")
		sigOf(assertionOf(d)).FindElement("./ds:SignedInfo/ds:"+tag).CreateAttr("Algorithm", alg)
	}
}

// evil returns an Assertion for the attacker's subject copying the structure of the good one.
func evil(e *Env, tx sso.Transaction, id string) *etree.Element {
	s := e.Good(tx)
	s.AssertionID, s.NameID, s.SignAssertion = id, "attacker-subject", false
	a := assertionOf(e.Build(s))
	ctx, err := etreeutils.NSBuildParentContext(a)
	if err != nil {
		panic(err)
	}
	d, err := etreeutils.NSDetatch(ctx, a)
	if err != nil {
		panic(err)
	}
	return d
}

// Builders is the registry the corpus records name in their "build" field.
var Builders = map[string]Builder{
	"good": spec(func(*Env, *Spec) {}),

	// forged
	"unsigned_all":         spec(func(_ *Env, s *Spec) { s.SignAssertion = false }),
	"response_signed_only": spec(func(_ *Env, s *Spec) { s.SignAssertion, s.SignResponse = false, true }),
	"attacker_key_keyinfo": spec(func(_ *Env, s *Spec) { s.Key = attacker }),
	"attacker_key_nokeyinfo": func(e *Env, tx sso.Transaction) Out {
		s := e.Good(tx)
		s.Key = attacker
		d := e.Build(s)
		sg := Sign(assertionOf(d), attacker, s.Alg)
		sg.RemoveChild(sg.FindElement("./ds:KeyInfo"))
		return raw(tx, write(d))
	},
	"nameid_changed": doc(func(_ *Env, d *etree.Document) {
		assertionOf(d).FindElement("./saml:Subject/saml:NameID").SetText("admin-subject")
	}),
	"sigvalue_bitflip": doc(func(_ *Env, d *etree.Document) {
		v := sigOf(assertionOf(d)).FindElement("./ds:SignatureValue")
		t := []byte(v.Text())
		if t[10] == 'A' {
			t[10] = 'B'
		} else {
			t[10] = 'A'
		}
		v.SetText(string(t))
	}),
	"c14n_with_comments": doc(func(e *Env, d *etree.Document) {
		setAlg("CanonicalizationMethod", string(dsig.CanonicalXML10ExclusiveWithCommentsAlgorithmId))(e, d)
	}),
	"comment_in_nameid": doc(func(_ *Env, d *etree.Document) {
		n := assertionOf(d).FindElement("./saml:Subject/saml:NameID")
		n.SetText(Subject[:5])
		n.CreateComment("")
		n.CreateCharData(Subject[5:])
	}),
	"rsa_sha1": doc(setAlg("SignatureMethod", dsig.RSASHA1SignatureMethod)),
	"sha1_digest": doc(func(_ *Env, d *etree.Document) {
		sigOf(assertionOf(d)).FindElement("./ds:SignedInfo/ds:Reference/ds:DigestMethod").RemoveAttr("Algorithm")
		sigOf(assertionOf(d)).FindElement("./ds:SignedInfo/ds:Reference/ds:DigestMethod").CreateAttr("Algorithm", "http://www.w3.org/2000/09/xmldsig#sha1")
	}),
	"hmac_method": doc(setAlg("SignatureMethod", "http://www.w3.org/2000/09/xmldsig#hmac-sha1")),
	"rsa_1024_key": func(e *Env, tx sso.Transaction) Out {
		e.Config.Certs = []*x509.Certificate{weak.Cert}
		s := e.Good(tx)
		s.Key = weak
		return raw(tx, e.Render(s))
	},
	"alg_mismatch": spec(func(_ *Env, s *Spec) { s.Alg = dsig.RSASHA512SignatureMethod }),
	"xpath_transform": doc(func(_ *Env, d *etree.Document) {
		tr := sigOf(assertionOf(d)).FindElements("./ds:SignedInfo/ds:Reference/ds:Transforms/ds:Transform")
		tr[1].RemoveAttr("Algorithm")
		tr[1].CreateAttr("Algorithm", "http://www.w3.org/TR/1999/REC-xpath-19991116")
	}),
	"encrypted_assertion": doc(func(_ *Env, d *etree.Document) {
		d.Root().CreateElement("saml:EncryptedAssertion").CreateElement("xenc:EncryptedData")
	}),

	// wrapped
	"wrap_sibling_evil_first": func(e *Env, tx sso.Transaction) Out {
		d := parse(e.Render(e.Good(tx)))
		d.Root().InsertChildAt(assertionOf(d).Index(), evil(e, tx, "_evil"))
		return raw(tx, write(d))
	},
	"wrap_signed_in_extensions": func(e *Env, tx sso.Transaction) Out {
		d := parse(e.Render(e.Good(tx)))
		orig := assertionOf(d)
		d.Root().RemoveChild(orig)
		ext := d.Root().CreateElement("samlp:Extensions")
		ext.AddChild(orig)
		d.Root().AddChild(evil(e, tx, "_evil"))
		return raw(tx, write(d))
	},
	"wrap_signed_in_advice": func(e *Env, tx sso.Transaction) Out {
		d := parse(e.Render(e.Good(tx)))
		orig := assertionOf(d)
		d.Root().RemoveChild(orig)
		ev := evil(e, tx, "_evil")
		ev.CreateElement("saml:Advice").AddChild(orig)
		d.Root().AddChild(ev)
		return raw(tx, write(d))
	},
	"wrap_signed_in_object": func(e *Env, tx sso.Transaction) Out {
		d := parse(e.Render(e.Good(tx)))
		orig := assertionOf(d)
		d.Root().RemoveChild(orig)
		ev := evil(e, tx, "_evil")
		Sign(ev, e.Key, e.Config.Alg) // evil carries a valid signature of itself ...
		sg := sigOf(ev)
		sg.CreateElement("ds:Object").AddChild(orig) // ... and hides the original in ds:Object
		d.Root().AddChild(ev)
		return raw(tx, write(d))
	},
	"two_assertions_one_signed": func(e *Env, tx sso.Transaction) Out {
		d := parse(e.Render(e.Good(tx)))
		d.Root().AddChild(evil(e, tx, "_evil"))
		return raw(tx, write(d))
	},
	"duplicate_id": func(e *Env, tx sso.Transaction) Out {
		d := parse(e.Render(e.Good(tx)))
		d.Root().AddChild(evil(e, tx, "_asrt-1"))
		return raw(tx, write(d))
	},
	"reference_empty_uri": doc(func(_ *Env, d *etree.Document) {
		r := sigOf(assertionOf(d)).FindElement("./ds:SignedInfo/ds:Reference")
		r.RemoveAttr("URI")
		r.CreateAttr("URI", "")
	}),
	"two_references": doc(func(_ *Env, d *etree.Document) {
		si := sigOf(assertionOf(d)).FindElement("./ds:SignedInfo")
		si.AddChild(si.FindElement("./ds:Reference").Copy())
	}),
	"namespace_confusion": func(e *Env, tx sso.Transaction) Out {
		b := e.Render(e.Good(tx))
		return raw(tx, bytes.Replace(b, []byte("<saml:Assertion "), []byte("<saml:Assertion xmlns:s2=\""+NSSAML+"\" s2:Foo=\"1\" saml:Foo=\"2\" "), 1))
	},

	// replayed
	"same_response_twice":         func(e *Env, tx sso.Transaction) Out { o := raw(tx, e.Render(e.Good(tx))); o.Twice = true; return o },
	"unsolicited_no_inresponseto": spec(func(_ *Env, s *Spec) { s.InResponseTo, s.SCInResponseTo = "", "" }),
	"inresponseto_other":          spec(func(_ *Env, s *Spec) { s.InResponseTo, s.SCInResponseTo = "_consumed", "_consumed" }),
	"conditions_expired":          spec(func(e *Env, s *Spec) { s.NotOnOrAfter = e.Now.Add(-10 * time.Minute) }),
	"issueinstant_old":            spec(func(e *Env, s *Spec) { s.IssueInstant = e.Now.Add(-20 * time.Minute) }),
	"notbefore_future":            spec(func(e *Env, s *Spec) { s.NotBefore = e.Now.Add(10 * time.Minute) }),
	"stepup_old_authn": func(e *Env, tx sso.Transaction) Out {
		tx.Intent = sso.IntentStepup
		s := e.Good(tx)
		s.AuthnInstant = e.Now.Add(-10 * time.Minute)
		return raw(tx, e.Render(s))
	},

	// misaddressed
	"audience_other":            spec(func(_ *Env, s *Spec) { s.Audiences = [][]string{{"https://other.example.test/sp"}} }),
	"audience_two_restrictions": spec(func(_ *Env, s *Spec) { s.Audiences = [][]string{{SPEntityID}, {"https://other.example.test/sp"}} }),
	"audience_none":             spec(func(_ *Env, s *Spec) { s.Audiences = nil }),
	"recipient_other":           spec(func(_ *Env, s *Spec) { s.Recipient = "https://console.example.test/auth/sso/idp-2/callback" }),
	"destination_other":         spec(func(_ *Env, s *Spec) { s.Destination = "https://console.example.test/auth/sso/idp-2/callback" }),
	"destination_absent":        spec(func(_ *Env, s *Spec) { s.Destination = "" }),
	"issuer_other":              spec(func(_ *Env, s *Spec) { s.Issuer = "https://idp-b.example.test/entity" }),
	"response_issuer_other":     spec(func(_ *Env, s *Spec) { s.ResponseIssuer = "https://idp-b.example.test/entity" }),
	"status_responder":          spec(func(_ *Env, s *Spec) { s.Status = "urn:oasis:names:tc:SAML:2.0:status:Responder" }),
	"holder_of_key":             spec(func(_ *Env, s *Spec) { s.ConfirmMethod = "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key" }),
	"nameid_transient":          spec(func(_ *Env, s *Spec) { s.NameIDFormat = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient" }),
	"nameid_email": spec(func(_ *Env, s *Spec) {
		s.NameIDFormat, s.NameID = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", "a@corp.example"
	}),
	"logout_request": func(e *Env, tx sso.Transaction) Out {
		return raw(tx, []byte(`<samlp:LogoutRequest xmlns:samlp="`+NSSAMLP+`" ID="_lo" Version="2.0"/>`))
	},

	// malformed
	"body_oversize": func(e *Env, tx sso.Transaction) Out {
		return raw(tx, append([]byte("<a>"), bytes.Repeat([]byte("x"), 200<<10)...))
	},
	"too_many_tokens": func(e *Env, tx sso.Transaction) Out {
		return raw(tx, []byte("<a>"+strings.Repeat("<b/>", 30000)+"</a>"))
	},
	"too_deep": func(e *Env, tx sso.Transaction) Out {
		return raw(tx, []byte(strings.Repeat("<a>", 80)+strings.Repeat("</a>", 80)))
	},
	"doctype_external_entity": func(e *Env, tx sso.Transaction) Out {
		return raw(tx, []byte(`<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><samlp:Response xmlns:samlp="`+NSSAMLP+`">&x;</samlp:Response>`))
	},
	"doctype_billion_laughs": func(e *Env, tx sso.Transaction) Out {
		return raw(tx, []byte(`<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;">]><samlp:Response xmlns:samlp="`+NSSAMLP+`">&b;</samlp:Response>`))
	},
	"deflate_body": func(e *Env, tx sso.Transaction) Out {
		var buf bytes.Buffer
		w, _ := flate.NewWriter(&buf, flate.BestCompression)
		_, _ = w.Write(e.Render(e.Good(tx)))
		_ = w.Close()
		return raw(tx, buf.Bytes())
	},
	"invalid_base64": func(e *Env, tx sso.Transaction) Out {
		return Out{Form: url.Values{"SAMLResponse": {"!!!not base64!!!"}}, Tx: tx}
	},
	"non_utf8_declaration": func(e *Env, tx sso.Transaction) Out {
		b := e.Render(e.Good(tx))
		return raw(tx, bytes.Replace(b, []byte(`encoding="UTF-8"`), []byte(`encoding="ISO-8859-1"`), 1))
	},
	"no_samlresponse": func(e *Env, tx sso.Transaction) Out { return Out{Form: url.Values{}, Tx: tx} },
	"stale_transaction": func(e *Env, tx sso.Transaction) Out {
		tx.CreatedAt = e.Now.Add(-10 * time.Minute)
		return raw(tx, e.Render(e.Good(tx)))
	},
}

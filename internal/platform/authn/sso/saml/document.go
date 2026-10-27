package saml

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/beevik/etree"
	validator "github.com/mattermost/xml-roundtrip-validator"

	"github.com/skenzeriq/activediq/internal/platform/authn/sso"
)

// Limits of SAML-1.
const (
	maxFieldBytes   = 256 << 10 // the form field, base64 (the request-body cap is the HTTP layer's)
	maxDecodedBytes = 192 << 10
	maxTokens       = 50000
	maxDepth        = 64
)

const (
	nsSAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
	nsSAML  = "urn:oasis:names:tc:SAML:2.0:assertion"
	nsDS    = "http://www.w3.org/2000/09/xmldsig#"
)

// parsed is the response document after SAML-1 to SAML-3: one Response with exactly one Assertion that is
// its direct child. Everything in it is still unverified.
type parsed struct {
	doc       *etree.Document
	response  *etree.Element
	assertion *etree.Element
	asrtID    string
}

// decode is SAML-1: HTTP-POST binding, plain base64, bounded size.
func decode(form map[string][]string) ([]byte, error) {
	vals := form["SAMLResponse"]
	if len(vals) != 1 || vals[0] == "" || len(vals[0]) > maxFieldBytes {
		return nil, sso.Refuse(ReasonBinding)
	}
	// A conforming POST binding is standard base64, optionally wrapped in line breaks.
	clean := strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, vals[0])
	raw, err := base64.StdEncoding.DecodeString(clean)
	if err != nil || len(raw) == 0 || len(raw) > maxDecodedBytes {
		return nil, sso.Refuse(ReasonBinding)
	}
	// DEFLATE (the Redirect binding) or anything else that is not an XML document.
	if raw[0] != '<' {
		return nil, sso.Refuse(ReasonBinding)
	}
	return raw, nil
}

// hygiene is the XML half of SAML-1 (token and depth bounds) and SAML-2 (UTF-8, no DOCTYPE, no processing
// instruction other than the declaration, no comments, round-trip stable).
func hygiene(raw []byte) error {
	if !utf8.Valid(raw) {
		return sso.Refuse(ReasonXML)
	}
	dec := xml.NewDecoder(bytes.NewReader(raw))
	dec.Strict = true
	dec.CharsetReader = func(string, io.Reader) (io.Reader, error) { return nil, errors.New("charset") }
	var tokens, depth int
	first := true
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return sso.Refuse(ReasonXML)
		}
		if tokens++; tokens > maxTokens {
			return sso.Refuse(ReasonBinding)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if depth++; depth > maxDepth {
				return sso.Refuse(ReasonBinding)
			}
		case xml.EndElement:
			depth--
		case xml.Directive, xml.Comment:
			return sso.Refuse(ReasonXML)
		case xml.ProcInst:
			if !first || t.Target != "xml" {
				return sso.Refuse(ReasonXML)
			}
		}
		first = false
	}
	if err := validator.Validate(bytes.NewReader(raw)); err != nil {
		return sso.Refuse(ReasonXML)
	}
	return nil
}

// structure is SAML-3, run on the parsed tree and independent of the signature library. It also
// recognises a LogoutRequest/LogoutResponse (SAML-19) before anything else is concluded about the root.
func structure(raw []byte) (*parsed, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		return nil, sso.Refuse(ReasonXML)
	}
	root := doc.Root()
	if root == nil {
		return nil, sso.Refuse(ReasonStructure)
	}
	if root.NamespaceURI() == nsSAMLP && (root.Tag == "LogoutRequest" || root.Tag == "LogoutResponse") {
		return nil, sso.Refuse(ReasonLogout)
	}
	if root.NamespaceURI() != nsSAMLP || root.Tag != "Response" {
		return nil, sso.Refuse(ReasonStructure)
	}
	var (
		assertions []*etree.Element
		bad        bool
		ids        = map[string]bool{}
	)
	var walk func(e *etree.Element)
	walk = func(e *etree.Element) {
		switch e.Tag {
		case "EncryptedAssertion":
			bad = true
		case "Assertion":
			assertions = append(assertions, e)
		case "Signature":
			// A ds:Signature is legitimate only as a direct child of the Response or of the Assertion.
			if e.NamespaceURI() == nsDS {
				p := e.Parent()
				if p == nil || !(p == root || (p.Tag == "Assertion" && p.NamespaceURI() == nsSAML && p.Parent() == root)) {
					bad = true
				}
			}
		}
		for _, a := range e.Attr {
			switch a.Key {
			case "ID", "Id", "id", "AssertionID":
				if ids[a.Value] {
					bad = true
				}
				ids[a.Value] = true
			}
		}
		for _, c := range e.ChildElements() {
			walk(c)
		}
	}
	walk(root)
	if bad || len(assertions) != 1 {
		return nil, sso.Refuse(ReasonStructure)
	}
	a := assertions[0]
	if a.NamespaceURI() != nsSAML || a.Parent() != root {
		return nil, sso.Refuse(ReasonStructure)
	}
	id := a.SelectAttrValue("ID", "")
	if id == "" || root.SelectAttrValue("ID", "") == "" {
		return nil, sso.Refuse(ReasonStructure)
	}
	return &parsed{doc: doc, response: root, assertion: a, asrtID: id}, nil
}

// children returns the direct child elements of e with the given namespace and local name.
func children(e *etree.Element, ns, tag string) []*etree.Element {
	var out []*etree.Element
	for _, c := range e.ChildElements() {
		if c.Tag == tag && c.NamespaceURI() == ns {
			out = append(out, c)
		}
	}
	return out
}

// one returns the single such child, or nil when there are none or several.
func one(e *etree.Element, ns, tag string) *etree.Element {
	if cs := children(e, ns, tag); len(cs) == 1 {
		return cs[0]
	}
	return nil
}

func text(e *etree.Element) string { return e.Text() }

package negotiate

import (
	"bytes"
	"errors"
)

// MaxTokenBytes is the cap on a decoded Negotiate token. A Kerberos ticket carrying a large PAC needs
// tens of KiB (threat model §7.6 rule 6); the HTTP binding caps the header at the same 64 KiB and
// answers 431 above it, and this check keeps the parser safe when called without that binding.
const MaxTokenBytes = 64 << 10

// ErrNotKerberos is returned for any token that is not a SPNEGO NegTokenInit whose first (preferred)
// mechanism is Kerberos with a Kerberos AP-REQ as its optimistic token: an NTLM-only token, a raw
// NTLMSSP message, a continuation token, or garbage. The caller answers all of them with the one
// generic failure (rule 5): there is no NTLM fallback to downgrade to.
var ErrNotKerberos = errors.New("negotiate: not a Kerberos SPNEGO token")

// DER of the object identifiers that matter, content octets only.
var (
	oidSPNEGO   = []byte{0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}                   // 1.3.6.1.5.5.2
	oidKerberos = []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02} // 1.2.840.113554.1.2.2
	oidMSKrb5   = []byte{0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02} // 1.2.840.48018.1.2.2 (legacy MS)
	tokIDAPReq  = []byte{0x01, 0x00}                                           // krb5 TOK_ID of an AP-REQ
	ntlmSSP     = []byte("NTLMSSP\x00")                                        // raw NTLM message signature
)

const (
	tagAppl0 = 0x60 // [APPLICATION 0] constructed: GSS InitialContextToken
	tagCtx0  = 0xa0 // [0] constructed
	tagSeq   = 0x30
	tagOID   = 0x06
	tagOctet = 0x04
	tagAPReq = 0x6e // [APPLICATION 14] constructed: Kerberos AP-REQ
)

// tlv reads one definite-length DER element from b and returns its tag, content and the rest. It
// refuses indefinite lengths, lengths above 4 bytes, and any length that runs past the input, so no
// allocation is sized by attacker input and no slice can overrun.
func tlv(b []byte) (tag byte, content, rest []byte, ok bool) {
	if len(b) < 2 {
		return 0, nil, nil, false
	}
	tag = b[0]
	if tag&0x1f == 0x1f { // high-tag-number form: none of the tags we accept use it
		return 0, nil, nil, false
	}
	l := int(b[1])
	off := 2
	if l&0x80 != 0 {
		n := l & 0x7f
		if n == 0 || n > 3 || len(b) < 2+n {
			return 0, nil, nil, false
		}
		l = 0
		for _, c := range b[2 : 2+n] {
			l = l<<8 | int(c)
		}
		off += n
		if l < 0x80 { // not minimal DER
			return 0, nil, nil, false
		}
	}
	if l < 0 || l > len(b)-off {
		return 0, nil, nil, false
	}
	return tag, b[off : off+l], b[off+l:], true
}

// expect reads one element and requires its tag.
func expect(b []byte, tag byte) (content, rest []byte, ok bool) {
	t, c, r, ok := tlv(b)
	if !ok || t != tag {
		return nil, nil, false
	}
	return c, r, true
}

func isKerberosOID(oid []byte) bool {
	return bytes.Equal(oid, oidKerberos) || bytes.Equal(oid, oidMSKrb5)
}

// RequireKerberos checks that token is a SPNEGO NegTokenInit that offers Kerberos first and carries a
// Kerberos AP-REQ as its optimistic mechanism token. It does not authenticate anything: the Acceptor
// does. It exists so NTLM is refused by structure, before any acceptor (and any NTLM code path) sees
// the bytes. Input is untrusted (RT-13); the parser is bounded and never panics.
func RequireKerberos(token []byte) error {
	if len(token) == 0 || len(token) > MaxTokenBytes || bytes.HasPrefix(token, ntlmSSP) {
		return ErrNotKerberos
	}
	// GSS InitialContextToken: [APPLICATION 0] { thisMech OID, innerToken }.
	body, rest, ok := expect(token, tagAppl0)
	if !ok || len(rest) != 0 {
		return ErrNotKerberos
	}
	mech, inner, ok := expect(body, tagOID)
	if !ok || !bytes.Equal(mech, oidSPNEGO) {
		return ErrNotKerberos
	}
	// NegotiationToken CHOICE: only [0] NegTokenInit starts a context.
	initBody, rest, ok := expect(inner, tagCtx0)
	if !ok || len(rest) != 0 {
		return ErrNotKerberos
	}
	seq, rest, ok := expect(initBody, tagSeq)
	if !ok || len(rest) != 0 {
		return ErrNotKerberos
	}
	// mechTypes [0] MechTypeList is required and first.
	mtl, seq, ok := expect(seq, tagCtx0)
	if !ok {
		return ErrNotKerberos
	}
	list, rest, ok := expect(mtl, tagSeq)
	if !ok || len(rest) != 0 {
		return ErrNotKerberos
	}
	first, _, ok := expect(list, tagOID)
	if !ok || !isKerberosOID(first) {
		return ErrNotKerberos // NTLM first, or no mechanism: the optimistic token is not Kerberos
	}
	// Optional reqFlags [1] and then mechToken [2] OCTET STRING. Skip [1] if present.
	for len(seq) > 0 {
		t, c, r, ok := tlv(seq)
		if !ok {
			return ErrNotKerberos
		}
		seq = r
		if t == 0xa1 { // reqFlags
			continue
		}
		if t != 0xa2 {
			return ErrNotKerberos // mechListMIC without a token, or something unknown
		}
		oct, rest, ok := expect(c, tagOctet)
		if !ok || len(rest) != 0 {
			return ErrNotKerberos
		}
		return requireAPReq(oct)
	}
	return ErrNotKerberos // no optimistic token: nothing to accept in this leg
}

// requireAPReq checks the krb5 GSS token: [APPLICATION 0] { krb5 OID, TOK_ID 0x0100, AP-REQ }.
func requireAPReq(tok []byte) error {
	body, rest, ok := expect(tok, tagAppl0)
	if !ok || len(rest) != 0 {
		return ErrNotKerberos
	}
	mech, after, ok := expect(body, tagOID)
	if !ok || !isKerberosOID(mech) {
		return ErrNotKerberos
	}
	if len(after) < 2 || !bytes.Equal(after[:2], tokIDAPReq) {
		return ErrNotKerberos
	}
	if t, _, r, ok := tlv(after[2:]); !ok || t != tagAPReq || len(r) != 0 {
		return ErrNotKerberos
	}
	return nil
}

package negotiate

import (
	"bytes"
	"testing"
)

// der builds one definite-length DER element.
func der(tag byte, content ...[]byte) []byte {
	c := bytes.Join(content, nil)
	var l []byte
	switch {
	case len(c) < 0x80:
		l = []byte{byte(len(c))}
	case len(c) < 0x100:
		l = []byte{0x81, byte(len(c))}
	default:
		l = []byte{0x82, byte(len(c) >> 8), byte(len(c))}
	}
	return append(append([]byte{tag}, l...), c...)
}

var oidNTLM = []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a} // 1.3.6.1.4.1.311.2.2.10

// krbToken is a krb5 GSS token around a stand-in AP-REQ body.
func krbToken() []byte {
	return der(tagAppl0, der(tagOID, oidKerberos), tokIDAPReq, der(tagAPReq, []byte("ap-req-body")))
}

// negInit builds a NegTokenInit offering mechs, with an optimistic token.
func negInit(mechs [][]byte, token []byte) []byte {
	var oids [][]byte
	for _, m := range mechs {
		oids = append(oids, der(tagOID, m))
	}
	parts := [][]byte{der(tagCtx0, der(tagSeq, oids...))}
	if token != nil {
		parts = append(parts, der(0xa2, der(tagOctet, token)))
	}
	return der(tagAppl0, der(tagOID, oidSPNEGO), der(tagCtx0, der(tagSeq, parts...)))
}

func Test_require_kerberos_accepts_the_browser_shape(t *testing.T) {
	for name, tok := range map[string][]byte{
		"kerberos":           negInit([][]byte{oidKerberos}, krbToken()),
		"ms legacy oid":      negInit([][]byte{oidMSKrb5, oidKerberos, oidNTLM}, krbToken()),
		"kerberos then ntlm": negInit([][]byte{oidKerberos, oidNTLM}, krbToken()),
	} {
		if err := RequireKerberos(tok); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func Test_an9_refuses_ntlm(t *testing.T) {
	ntlmMsg := append([]byte("NTLMSSP\x00\x01\x00\x00\x00"), make([]byte, 20)...)
	for name, tok := range map[string][]byte{
		"ntlm-only negotiate":      negInit([][]byte{oidNTLM}, ntlmMsg),
		"ntlm first, krb second":   negInit([][]byte{oidNTLM, oidKerberos}, ntlmMsg),
		"ntlm token under krb oid": negInit([][]byte{oidKerberos}, ntlmMsg),
		"ntlm-only without token":  negInit([][]byte{oidNTLM}, nil),
		"raw ntlmssp":              ntlmMsg,
		"kerberos without token":   negInit([][]byte{oidKerberos}, nil),
		"empty":                    nil,
		"truncated":                negInit([][]byte{oidKerberos}, krbToken())[:20],
		"oversize":                 make([]byte, MaxTokenBytes+1),
	} {
		if err := RequireKerberos(tok); err != ErrNotKerberos {
			t.Errorf("%s: got %v, want ErrNotKerberos", name, err)
		}
	}
}

func Fuzz_require_kerberos(f *testing.F) {
	f.Add(negInit([][]byte{oidKerberos}, krbToken()))
	f.Add(negInit([][]byte{oidNTLM}, []byte("NTLMSSP\x00")))
	f.Add([]byte{0x60, 0x84, 0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, b []byte) {
		if RequireKerberos(b) == nil {
			// Whatever passes must really be a Kerberos-first NegTokenInit: never NTLM bytes.
			if bytes.HasPrefix(b, ntlmSSP) {
				t.Fatalf("accepted raw NTLMSSP %x", b)
			}
		}
	})
}

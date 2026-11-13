package ops_test

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"strings"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/write/ops"
	"github.com/skenzeriq/activediq/internal/directory/attr/unicodepwd"
	"github.com/skenzeriq/activediq/internal/platform/secret"
)

// verifiedLink is a Link whose TLS state passes unicodepwd.Acquire: TLS 1.3, a verified chain, a leaf
// naming dc.example.test. The generation can be bumped to model a reconnect.
type verifiedLink struct{ gen uint64 }

func (l *verifiedLink) Generation() uint64 { return l.gen }
func (l *verifiedLink) ConnectionState() (tls.ConnectionState, bool) {
	leaf := &x509.Certificate{DNSNames: []string{"dc.example.test"}}
	return tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13,
		PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf}}}, true
}

type recorder struct{ sent []*ldap.ModifyRequest }

func (r *recorder) Modify(m *ldap.ModifyRequest) error { r.sent = append(r.sent, m); return nil }

func acquire(t *testing.T, l *verifiedLink) unicodepwd.SecureConn {
	t.Helper()
	sc, err := unicodepwd.Acquire(l, "dc.example.test")
	if err != nil {
		t.Fatal(err)
	}
	return sc
}

func utf16Quoted(s string) string {
	var b []byte
	for _, r := range `"` + s + `"` { // BMP only in the test
		b = append(b, byte(r), byte(r>>8))
	}
	return string(b)
}

func TestResetPasswordBuildsExactlyOneModify(t *testing.T) {
	for _, mustChange := range []bool{false, true} {
		rec := &recorder{}
		send := ops.ResetPassword(secret.FromBytes([]byte("Passw0rd!")), mustChange)
		if err := send(rec, "<GUID=x>", acquire(t, &verifiedLink{})); err != nil {
			t.Fatal(err)
		}
		if len(rec.sent) != 1 {
			t.Fatalf("%d modifies", len(rec.sent))
		}
		req := rec.sent[0]
		wantChanges := 1
		if mustChange {
			wantChanges = 2
		}
		if len(req.Changes) != wantChanges {
			t.Fatalf("mustChange=%v: %d changes", mustChange, len(req.Changes))
		}
		c := req.Changes[0]
		if c.Operation != ldap.ReplaceAttribute || !strings.EqualFold(c.Modification.Type, "unicodePwd") ||
			len(c.Modification.Vals) != 1 || c.Modification.Vals[0] != utf16Quoted("Passw0rd!") {
			t.Fatalf("first change is not replace unicodePwd with the quoted UTF-16LE value")
		}
		if mustChange {
			c := req.Changes[1]
			if c.Operation != ldap.ReplaceAttribute || !strings.EqualFold(c.Modification.Type, "pwdLastSet") ||
				len(c.Modification.Vals) != 1 || c.Modification.Vals[0] != "0" {
				t.Fatalf("second change must be pwdLastSet=0, got %+v", c)
			}
		}
		if len(req.Controls) != 1 {
			t.Fatalf("%d controls", len(req.Controls))
		}
		ctl := req.Controls[0]
		if ctl.GetControlType() != "1.2.840.113556.1.4.2239" {
			t.Fatalf("control %s", ctl.GetControlType())
		}
		// Decode the wire form: SEQUENCE { OCTET STRING oid, [no criticality], OCTET STRING { SEQUENCE { INTEGER 1 } } }.
		p := ber.DecodePacket(ctl.Encode().Bytes())
		if len(p.Children) != 2 {
			t.Fatalf("control has %d parts: it must be non-critical with a value", len(p.Children))
		}
		if p.Children[1].Tag != ber.TagOctetString {
			t.Fatal("control value is not an OCTET STRING")
		}
		inner := ber.DecodePacket(p.Children[1].Data.Bytes())
		if inner.Tag != ber.TagSequence || len(inner.Children) != 1 || inner.Children[0].Tag != ber.TagInteger ||
			inner.Children[0].Value.(int64) != 1 {
			t.Fatal("control value is not SEQUENCE{INTEGER 1}")
		}
	}
}

func TestResetPasswordSendsNothingOnZeroOrStaleConn(t *testing.T) {
	rec := &recorder{}
	send := ops.ResetPassword(secret.FromBytes([]byte("Passw0rd!")), true)
	err := send(rec, "<GUID=x>", unicodepwd.SecureConn{})
	if err == nil || len(rec.sent) != 0 {
		t.Fatalf("zero SecureConn: err=%v sent=%d", err, len(rec.sent))
	}
	l := &verifiedLink{}
	sc := acquire(t, l)
	l.gen++ // reconnect since Acquire
	err = send(rec, "<GUID=x>", sc)
	if err == nil || len(rec.sent) != 0 {
		t.Fatalf("stale SecureConn: err=%v sent=%d", err, len(rec.sent))
	}
	var e *ad.Error
	if !errors.As(err, &e) || e.Code != ad.CodeInsecure {
		t.Fatalf("want a CodeInsecure error (TRANSPORT_SECURITY/NEVER), got %v", err)
	}
}

// S3 defence in depth: a secret the encoder rejects is a classified error, never a DC-unreachable one.
func TestResetPasswordEncodeFailureIsClassified(t *testing.T) {
	rec := &recorder{}
	send := ops.ResetPassword(secret.Secret{}, false)
	err := send(rec, "<GUID=x>", acquire(t, &verifiedLink{}))
	if err == nil || ad.CodeOf(err) != ad.CodeInvalidArgument || len(rec.sent) != 0 {
		t.Fatalf("err=%v code=%q sent=%d", err, ad.CodeOf(err), len(rec.sent))
	}
}

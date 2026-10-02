package krb5gssapi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/gssapi"
	"github.com/go-krb5/krb5/iana/etypeID"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/types"
)

func testCert(t *testing.T) *x509.Certificate {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "dc1.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}, &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "dc1.test"}}, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// RFC 5929 §4: tls-server-end-point = hash(DER cert); ECDSA-SHA256 → SHA-256. The GSS channel-binding
// application-data is the prefix "tls-server-end-point:" plus the hash.
func TestChannelBindingIsRFC5929(t *testing.T) {
	c := testCert(t)
	cb, err := ChannelBindingFromCert(c)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(c.Raw)
	if want := append([]byte("tls-server-end-point:"), h[:]...); string(cb.ApplicationData) != string(want) {
		t.Fatalf("application data = %q, want %q", cb.ApplicationData, want)
	}
	if cb.Bnd() == [16]byte{} {
		t.Fatal("Bnd is the all-zero 'no bindings' value")
	}
	st := tls.ConnectionState{PeerCertificates: []*x509.Certificate{c}}
	if got, err := ChannelBindingFromTLS(st, true); err != nil || got.Bnd() != cb.Bnd() {
		t.Fatalf("FromTLS differs from FromCert: %v", err)
	}
	if _, err := ChannelBindingFromTLS(st, false); err == nil {
		t.Fatal("a non-TLS connection must not produce a channel binding")
	}
}

func serverOffer(t *testing.T, key types.EncryptionKey, subkeyFlag byte, layers byte) []byte {
	t.Helper()
	et, _ := crypto.GetEType(key.KeyType)
	wt := gssapi.WrapToken{Flags: gssapi.FlagSentByAcceptor | subkeyFlag, EC: uint16(et.GetHMACBitLength() / 8), Payload: []byte{layers, 0, 0xff, 0xff}}
	if err := wt.SetCheckSum(key, keyusage.GSSAPI_ACCEPTOR_SEAL); err != nil {
		t.Fatal(err)
	}
	b, err := wt.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func newKey(t *testing.T) types.EncryptionKey {
	et, _ := crypto.GetEType(etypeID.AES256_CTS_HMAC_SHA1_96)
	raw := make([]byte, et.GetKeySeedBitLength()/8)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	k := et.RandomToKey(raw)
	return types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: k}
}

// The reply must select "no security layer" (the TLS channel protects the data), carry the acceptor-subkey flag
// when the AP-REP had a subkey, and verify under the initiator key usage.
func TestNegotiateSelectsNoLayerOverTLS(t *testing.T) {
	sub := newKey(t)
	c := &Client{ekey: newKey(t), subkey: sub, mutualOK: true}
	out, err := c.NegotiateSaslAuth(serverOffer(t, sub, gssapi.FlagAcceptorSubkey, 0x07), "")
	if err != nil {
		t.Fatal(err)
	}
	var wt gssapi.WrapToken
	if err := wt.Unmarshal(out, false); err != nil {
		t.Fatal(err)
	}
	if ok, err := wt.Verify(sub, keyusage.GSSAPI_INITIATOR_SEAL); !ok || err != nil {
		t.Fatalf("reply does not verify under the acceptor subkey: %v", err)
	}
	if wt.Flags&gssapi.FlagAcceptorSubkey == 0 || wt.Flags&gssapi.FlagSentByAcceptor != 0 || wt.Flags&gssapi.FlagSealed != 0 {
		t.Fatalf("flags %#x", wt.Flags)
	}
	if len(wt.Payload) != 4 || wt.Payload[0] != byte(gssapi.SecurityLayerNone) || wt.Payload[1]|wt.Payload[2]|wt.Payload[3] != 0 {
		t.Fatalf("payload %x: want layer=none, maxbuf=0", wt.Payload)
	}
}

func TestNegotiateRefusesServerWithoutNoLayer(t *testing.T) {
	k := newKey(t)
	c := &Client{ekey: k, mutualOK: true}
	if _, err := c.NegotiateSaslAuth(serverOffer(t, k, 0, 0x06), ""); err == nil { // integrity+confidentiality only
		t.Fatal("must refuse a server that only offers SASL layers over TLS")
	}
}

func TestNegotiateRefusesBeforeMutualAuth(t *testing.T) {
	k := newKey(t)
	c := &Client{ekey: k}
	if _, err := c.NegotiateSaslAuth(serverOffer(t, k, 0, 0x01), ""); err == nil {
		t.Fatal("must refuse when the AP-REP was never verified")
	}
}

func TestNegotiateRejectsTamperedOffer(t *testing.T) {
	k := newKey(t)
	c := &Client{ekey: k, mutualOK: true}
	b := serverOffer(t, k, 0, 0x01)
	b[16] ^= 0x01 // flip a payload bit
	if _, err := c.NegotiateSaslAuth(b, ""); err == nil {
		t.Fatal("must reject an offer whose checksum does not verify")
	}
}

func TestDeleteSecContextWipesKeys(t *testing.T) {
	k := newKey(t)
	c := &Client{ekey: k}
	kv := c.ekey.KeyValue
	_ = c.DeleteSecContext()
	for _, b := range kv {
		if b != 0 {
			t.Fatal("key material not zeroed")
		}
	}
}

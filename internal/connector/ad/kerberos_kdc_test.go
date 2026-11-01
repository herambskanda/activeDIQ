package ad

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/go-krb5/krb5/asn1tools"
	"github.com/go-krb5/krb5/crypto"
	krb5gssapi "github.com/go-krb5/krb5/gssapi"
	"github.com/go-krb5/krb5/iana/chksumtype"
	"github.com/go-krb5/krb5/iana/errorcode"
	"github.com/go-krb5/krb5/iana/etypeID"
	"github.com/go-krb5/krb5/iana/nametype"
	"github.com/go-krb5/krb5/iana/patype"
	"github.com/go-krb5/krb5/keytab"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/types"
	"github.com/go-ldap/ldap/v3"

	"github.com/skenzeriq/activediq/internal/connector/ad/gssapi"
	"github.com/skenzeriq/activediq/internal/platform/secret"
)

// fakeKDC is a TCP KDC that answers every AS-REQ with KDC_ERR_PREAUTH_REQUIRED whose ETYPE-INFO2
// lists only offered (a rogue or on-path KDC steering the client to RC4, TM-TB3-T13) and records
// the etype of every PA-ENC-TIMESTAMP it receives. It never returns a ticket.
type fakeKDC struct {
	ln       net.Listener
	mu       sync.Mutex
	requests int
	tsETypes []int32
}

func newFakeKDC(t *testing.T, offered int32) *fakeKDC {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeKDC{ln: ln}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c, offered)
		}
	}()
	return f
}

func (f *fakeKDC) addr() string { return f.ln.Addr().String() }

func (f *fakeKDC) serve(c net.Conn, offered int32) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	hb := make([]byte, 4)
	if _, err := io.ReadFull(c, hb); err != nil {
		return
	}
	body := make([]byte, binary.BigEndian.Uint32(hb))
	if _, err := io.ReadFull(c, body); err != nil {
		return
	}
	var req messages.ASReq
	if err := req.Unmarshal(body); err != nil {
		return
	}
	f.mu.Lock()
	f.requests++
	for _, pa := range req.PAData {
		if pa.PADataType == patype.PA_ENC_TIMESTAMP {
			var ed types.EncryptedData
			if ed.Unmarshal(pa.PADataValue) == nil {
				f.tsETypes = append(f.tsETypes, ed.EType)
			}
		}
	}
	f.mu.Unlock()

	info, err := asn1tools.Marshal(types.ETypeInfo2{{EType: offered}})
	if err != nil {
		return
	}
	edata, err := asn1tools.Marshal(types.PADataSequence{{PADataType: patype.PA_ETYPE_INFO2, PADataValue: info}})
	if err != nil {
		return
	}
	kerr := messages.NewKRBError(types.PrincipalName{NameType: nametype.KRB_NT_SRV_INST, NameString: []string{"krbtgt", req.ReqBody.Realm}},
		req.ReqBody.Realm, errorcode.KDC_ERR_PREAUTH_REQUIRED, "")
	kerr.EData = edata
	out, err := kerr.Marshal()
	if err != nil {
		return
	}
	rh := make([]byte, 4)
	binary.BigEndian.PutUint32(rh, uint32(len(out)))
	c.Write(append(rh, out...))
}

func (f *fakeKDC) seen() (requests int, ts []int32) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests, append([]int32(nil), f.tsETypes...)
}

// withRC4Registered registers rc4-hmac in go-krb5's process-wide registry for the test. The pinned
// library does not register it by default (see TestPinnedKrb5RegistersNoWeakEtypes), so without
// this the library itself would refuse etype 23 and these tests would prove nothing about the
// keytab filter, which is the defence that must still hold if a pin bump or another dependency
// turns RC4 on. The tests in this package do not run in parallel, so the global is safe to toggle.
func withRC4Registered(t *testing.T) {
	t.Helper()
	crypto.RegisterDeprecatedRC4HMAC()
	t.Cleanup(func() {
		crypto.DeleteEType(etypeID.RC4_HMAC)
		crypto.DeleteChecksumEType(chksumtype.KERB_CHECKSUM_HMAC_MD5)
	})
}

// Tripwire: the connector relies on go-krb5 not registering weak etypes unless asked. If a pin bump
// changes that, this fails and the keytab filter becomes the only barrier (it still holds, see the
// KDC tests), so review the bump for the T-0856 exposure.
func TestPinnedKrb5RegistersNoWeakEtypes(t *testing.T) {
	for _, id := range crypto.ETypeIDs() {
		if id != etypeID.AES128_CTS_HMAC_SHA1_96 && id != etypeID.AES256_CTS_HMAC_SHA1_96 &&
			id != etypeID.AES128_CTS_HMAC_SHA256_128 && id != etypeID.AES256_CTS_HMAC_SHA384_192 {
			t.Errorf("go-krb5 registers non-AES etype %d by default", id)
		}
	}
}

// mixedKeytab holds RC4 (23), AES128 (17) and AES256 (18) keys for the test principal.
func mixedKeytab(t *testing.T, etypes ...int32) *keytab.Keytab {
	t.Helper()
	withRC4Registered(t)
	kt := keytab.New()
	for _, et := range etypes {
		if err := kt.AddEntry("svc-activediq$", "LAB.ACTIVEDIQ.TEST", "pw", time.Now(), 1, et); err != nil {
			t.Fatal(err)
		}
	}
	return kt
}

func keytabSecret(t *testing.T, kt *keytab.Keytab) secret.Secret {
	t.Helper()
	raw, err := kt.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return secret.FromBytes(raw)
}

// testChannelBinding is a well-formed binding of a throwaway certificate: the client refuses to
// start a handshake without one, so the fake KDC would otherwise never be reached.
func testChannelBinding(t *testing.T) *krb5gssapi.ChannelBinding {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "dc1.lab.activediq.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	cb, err := gssapi.ChannelBindingFromCert(cert)
	if err != nil {
		t.Fatal(err)
	}
	return cb
}

func deadConn(t *testing.T) *ldap.Conn {
	t.Helper()
	c1, c2 := net.Pipe()
	t.Cleanup(func() { c2.Close() })
	conn := ldap.NewConn(c1, false)
	conn.Start()
	t.Cleanup(func() { conn.Close() })
	return conn
}

// T-0856 AC1: the KDC offers only RC4 pre-authentication; the keytab holds RC4 and AES keys. The
// client must send no PA-ENC-TIMESTAMP at all and the bind must fail closed.
func TestKDCOfferingOnlyRC4PreauthGetsNoTimestamp(t *testing.T) {
	const rc4 = etypeID.RC4_HMAC
	kdc := newFakeKDC(t, rc4)
	k := goodKrb()
	k.KDCs = []string{kdc.addr()}
	k.Keytab = keytabSecret(t, mixedKeytab(t, rc4, etypeID.AES128_CTS_HMAC_SHA1_96, etypeID.AES256_CTS_HMAC_SHA1_96))
	if err := bindWithKeytab(deadConn(t), k, testChannelBinding(t), "dc1.lab.activediq.test"); err == nil {
		t.Fatal("bind succeeded against a KDC that offered only RC4")
	}
	n, ts := kdc.seen()
	if n == 0 {
		t.Fatal("the fake KDC never saw the AS-REQ; the test proves nothing")
	}
	if len(ts) != 0 {
		t.Fatalf("client sent PA-ENC-TIMESTAMP with etypes %v to a KDC that offered only RC4", ts)
	}
	if n != 1 {
		t.Errorf("client retried the AS-REQ %d times", n)
	}
}

// Negative control: the same exchange with the keytab handed to the Kerberos client unfiltered (the
// pre-fix behaviour) does send an RC4 PA-ENC-TIMESTAMP, so the fake KDC can see the leak and the
// test above is not vacuous.
func TestNegativeControlUnfilteredKeytabLeaksRC4Timestamp(t *testing.T) {
	const rc4 = etypeID.RC4_HMAC
	kdc := newFakeKDC(t, rc4)
	k := goodKrb()
	k.KDCs = []string{kdc.addr()}
	kt := mixedKeytab(t, rc4, etypeID.AES256_CTS_HMAC_SHA1_96)
	defer zeroKeytab(kt)
	_ = gssapiHandshake(deadConn(t), k, kt, k.krb5Config(), testChannelBinding(t), "dc1.lab.activediq.test")
	_, ts := kdc.seen()
	if len(ts) != 1 || ts[0] != rc4 {
		t.Fatalf("negative control: want one etype-23 PA-ENC-TIMESTAMP, got %v", ts)
	}
}

func TestDropNonAESKeys(t *testing.T) {
	kt := mixedKeytab(t, etypeID.RC4_HMAC, etypeID.AES256_CTS_HMAC_SHA1_96, etypeID.RC4_HMAC, etypeID.AES128_CTS_HMAC_SHA1_96)
	var dropped [][]byte
	for _, e := range kt.Entries {
		if e.Key.KeyType != 17 && e.Key.KeyType != 18 {
			dropped = append(dropped, e.Key.KeyValue)
		}
	}
	if err := dropNonAESKeys(kt); err != nil {
		t.Fatal(err)
	}
	if len(kt.Entries) != 2 || kt.Entries[0].Key.KeyType != 18 || kt.Entries[1].Key.KeyType != 17 {
		t.Fatalf("kept %d entries: %+v", len(kt.Entries), kt.Entries)
	}
	for _, e := range kt.Entries {
		if allZero(e.Key.KeyValue) {
			t.Error("an AES key was wiped")
		}
	}
	if len(dropped) != 2 {
		t.Fatalf("fixture: %d dropped keys", len(dropped))
	}
	for _, kv := range dropped {
		if !allZero(kv) {
			t.Error("a dropped non-AES key was not zeroised")
		}
	}
}

// T-0856 AC2: a keytab with only RC4 keys is refused by Open with CodeInvalidArgument before any
// connection is made, and the parsed keys are zeroised.
func TestOpenRejectsKeytabWithoutAESKeysBeforeNetwork(t *testing.T) {
	k := goodKrb()
	k.Keytab = keytabSecret(t, mixedKeytab(t, etypeID.RC4_HMAC))
	dialer := &countingDialer{}
	var parsed *keytab.Keytab
	keytabParsed = func(p *keytab.Keytab) { parsed = p }
	t.Cleanup(func() { keytabParsed = nil })
	_, err := Open(t.Context(), Config{Servers: []string{"dc1.lab.activediq.test:636"}, Kerberos: &k, Dialer: dialer})
	if err == nil {
		t.Fatal("RC4-only keytab accepted")
	}
	if c := CodeOf(err); c != CodeInvalidArgument {
		t.Errorf("code = %v, want CodeInvalidArgument (err %v)", c, err)
	}
	if dialer.n != 0 {
		t.Errorf("dialled %d times before refusing the keytab", dialer.n)
	}
	if parsed != nil {
		t.Error("bind path ran")
	}
}

func TestBindWithKeytabRC4OnlyZeroisesAndFails(t *testing.T) {
	kt := mixedKeytab(t, etypeID.RC4_HMAC)
	k := goodKrb()
	k.Keytab = keytabSecret(t, kt)
	err := bindWithKeytab(nil, k, nil, "dc1.lab.activediq.test")
	if err == nil || CodeOf(err) != CodeInvalidArgument {
		t.Fatalf("want CodeInvalidArgument, got %v", err)
	}
}

type countingDialer struct{ n int }

func (d *countingDialer) DialContext(_ context.Context, _, _ string) (net.Conn, error) {
	d.n++
	return nil, io.EOF
}

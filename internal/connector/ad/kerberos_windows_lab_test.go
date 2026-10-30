//go:build lab && windowslab

package ad

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/go-krb5/krb5/client"
	krb5gssapi "github.com/go-krb5/krb5/gssapi"
	"github.com/go-krb5/krb5/iana/etypeID"
	"github.com/go-krb5/krb5/keytab"
	"github.com/go-ldap/ldap/v3"

	"github.com/skenzeriq/activediq/internal/connector/ad/gssapi"
	"github.com/skenzeriq/activediq/internal/platform/secret"
)

// T-0566: the equivalents of kerberos_lab_test.go against the Windows lab DC. Precondition (runbook
// windows-lab.md section 11): guest/gssapi-ready.ps1 ran on dc1 (LDAPServerIntegrity=2,
// LdapEnforceChannelBindingTokens=2, dc1 rebooted) and its output sits beside the lab env file.
// Like the rest of the Windows lab tests nothing is skipped: a missing lab or keytab fails loudly.
// Two deliberately untested-until-first-run assumptions are marked [UNVERIFIED] below.
const (
	winKrbRealm   = "WIN.ACTIVEDIQ.TEST"
	winKrbAccount = "svc-t0566-gssapi"
)

// winKrbFile returns a file named by envVar or the default beside lab/windows.
func winKrbFile(envVar, def string) string { return winLabPath(envVar, def) }

func winKDC() string {
	h := os.Getenv("WIN_LAB_DC_ADDR")
	if h == "" {
		h = "192.168.77.10"
	}
	return h + ":88"
}

// aesOnly drops every non-AES entry so a test cannot pass on RC4/DES.
func aesOnly(t *testing.T, kt *keytab.Keytab) {
	t.Helper()
	kept := kt.Entries[:0]
	for _, e := range kt.Entries {
		if e.Key.KeyType == etypeID.AES128_CTS_HMAC_SHA1_96 || e.Key.KeyType == etypeID.AES256_CTS_HMAC_SHA1_96 {
			kept = append(kept, e)
		}
	}
	if len(kept) == 0 {
		t.Fatal("no AES entries in keytab")
	}
	kt.Entries = kept
}

func winKeytabIdentity(t *testing.T) Kerberos {
	t.Helper()
	p := winKrbFile("WIN_LAB_GSSAPI_KEYTAB", ".win-lab-gssapi.keytab")
	kt, err := keytab.Load(p)
	if err != nil {
		t.Fatalf("service keytab %s (run guest/gssapi-ready.ps1 and copy svc.keytab): %v", p, err)
	}
	aesOnly(t, kt)
	b, err := kt.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return Kerberos{Principal: winKrbAccount, Realm: winKrbRealm, Keytab: secret.FromBytes(b), KDCs: []string{winKDC()}}
}

// gmsaCurrentPassword parses MSDS-MANAGEDPASSWORD_BLOB (MS-ADTS 2.2.19) and returns CurrentPassword
// as UTF-16 code units.
func gmsaCurrentPassword(blob []byte) ([]uint16, error) {
	if len(blob) < 16 {
		return nil, errors.New("short managed password blob")
	}
	off := int(binary.LittleEndian.Uint16(blob[8:10]))
	if off >= len(blob) {
		return nil, errors.New("bad CurrentPasswordOffset")
	}
	var u []uint16
	for i := off; i+1 < len(blob); i += 2 {
		c := binary.LittleEndian.Uint16(blob[i:])
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return u, nil
}

// winGMSAIdentity derives the AES keytab for the gMSA from its managed password. [UNVERIFIED]
// assumption 1: the string-to-key password is the UTF-16 password re-encoded to UTF-8 (invalid
// surrogates become U+FFFD, which is what utf16.Decode does) with the host-style salt
// REALM+"host"+<name without $>+"."+<dns domain>; the entry is then filed under "name$".
func winGMSAIdentity(t *testing.T) Kerberos {
	t.Helper()
	p := winKrbFile("WIN_LAB_GMSA", ".win-lab-gmsa.json")
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("gMSA export %s (run guest/gssapi-ready.ps1 and copy gmsa.json): %v", p, err)
	}
	var g struct {
		Principal, Realm, DNSHostName string
		Kvno                          int
		Blob                          string
	}
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatal(err)
	}
	blob, err := base64.StdEncoding.DecodeString(g.Blob)
	if err != nil {
		t.Fatal(err)
	}
	u, err := gmsaCurrentPassword(blob)
	if err != nil {
		t.Fatal(err)
	}
	pw := string(utf16.Decode(u))
	kt := keytab.New()
	for _, et := range []int32{etypeID.AES256_CTS_HMAC_SHA1_96, etypeID.AES128_CTS_HMAC_SHA1_96} {
		if err := kt.AddEntry("host/"+strings.ToLower(g.DNSHostName), g.Realm, pw, time.Now(), uint8(g.Kvno), et); err != nil {
			t.Fatal(err)
		}
	}
	for i := range kt.Entries {
		kt.Entries[i].Principal.Components = []string{g.Principal}
		kt.Entries[i].Principal.NumComponents = 1
		kt.Entries[i].Principal.NameType = 1 // KRB_NT_PRINCIPAL
	}
	b, err := kt.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return Kerberos{Principal: g.Principal, Realm: g.Realm, Keytab: secret.FromBytes(b), KDCs: []string{winKDC()}}
}

func winKrbConfig(t *testing.T, k Kerberos) Config {
	t.Helper()
	cfg := winConfig(t, "", true)
	cfg.Credential = Credential{}
	cfg.Kerberos = &k
	cfg.Timeout = 30 * time.Second
	return cfg
}

// BUG T-0846 (filed by this ticket): the product bind path (gssapiHandshake -> client.NewWithKeytab) cannot
// log in to a Windows Server 2025 KDC: go-krb5 sends PA-REQ-ENC-PA-REP, the KDC sets the EncPARep flag, and
// the client then rejects the AS-REP ("KDC did not respond appropriately to FAST negotiation", as_xchange /
// kdc_rep.go requires PA-FX-FAST in the encrypted pa-data). Samba does not set the flag, so T-0560 never saw it.
// The Open-based tests below therefore stay RED until the connector builds its client with
// client.DisablePAFXFAST(true) (or the library check is fixed); like TestWinLabTM26GCOpens they are red on
// purpose. Every other test in this file drives the same handshake with PA-FX-FAST disabled (winHandshake)
// so the DC-side behaviour (channel binding, SPN, keys, gMSA derivation) is pinned independently of that bug.

// winDialBound dials the DC over verified LDAPS (the product dial path) and returns the connection and the
// RFC 5929 binding of the certificate it presented.
func winDialBound(t *testing.T, k Kerberos) (*ldap.Conn, *krb5gssapi.ChannelBinding) {
	t.Helper()
	cfg := winKrbConfig(t, k)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	host, port := splitHostPort(cfg.Servers[0])
	conn, err := dial(ctx, cfg, host, port)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	state, ok := conn.TLSConnectionState()
	cb, err := gssapi.ChannelBindingFromTLS(state, ok)
	if err != nil {
		t.Fatal(err)
	}
	return conn, cb
}

// winHandshake runs the SASL GSSAPI bind on conn with PA-FX-FAST disabled (see the bug note above), SPN
// ldap/<spnHost> and the given binding (nil = absent). It returns the unwrapped error so a test can assert the
// LDAP result code.
func winHandshake(t *testing.T, conn *ldap.Conn, k Kerberos, cb *krb5gssapi.ChannelBinding, spnHost string) error {
	t.Helper()
	kt := keytab.New()
	var perr error
	k.Keytab.Expose(func(b []byte) { perr = kt.Unmarshal(b) })
	if perr != nil {
		t.Fatal(perr)
	}
	krb := client.NewWithKeytab(k.Principal, k.Realm, kt, k.krb5Config(), client.DisablePAFXFAST(true))
	defer krb.Destroy()
	return conn.GSSAPIBind(gssapi.New(krb, cb), "ldap/"+strings.ToLower(strings.TrimSuffix(spnHost, ".")), "")
}

// requireBind binds with the DC's own channel binding and checks whoami and rootDSE over the session.
func requireBind(t *testing.T, k Kerberos, want string) {
	t.Helper()
	conn, cb := winDialBound(t, k)
	if err := winHandshake(t, conn, k, cb, winTLSName()); err != nil {
		t.Fatalf("GSSAPI bind: %v", err)
	}
	who, err := conn.WhoAmI(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ToLower(who.AuthzID), want) {
		t.Errorf("whoami = %q, want it to name %q", who.AuthzID, want)
	}
	res, err := conn.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 30, false,
		"(objectClass=*)", []string{"defaultNamingContext"}, nil))
	if err != nil {
		t.Fatalf("rootDSE over the GSSAPI-bound session: %v", err)
	}
	if len(res.Entries) != 1 || !strings.EqualFold(res.Entries[0].GetAttributeValue("defaultNamingContext"), winBase) {
		t.Errorf("rootDSE = %+v", res.Entries)
	}
}

// requireOpenBinds is the product path: ad.Open with a Kerberos identity.
func requireOpenBinds(t *testing.T, k Kerberos, want string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	s, err := Open(ctx, winKrbConfig(t, k))
	if err != nil {
		t.Fatalf("ad.Open with a keytab identity (known bug T-0846, WS2025 PA-REQ-ENC-PA-REP): %v", err)
	}
	defer s.Close()
	who, err := s.conn.WhoAmI(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ToLower(who.AuthzID), want) {
		t.Errorf("whoami = %q, want it to name %q", who.AuthzID, want)
	}
	r, err := s.RootDSE(ctx)
	if err != nil || !strings.EqualFold(r.DefaultNamingContext, winBase) {
		t.Errorf("rootDSE over the GSSAPI-bound session: %v %+v", err, r)
	}
}

// AC1, correct binding: keytab identity, SPN ldap/<fqdn>, layer none, DC enforcing CBT=Always + signing required.
func TestWindowsLabKerberosKeytabBindWithChannelBinding(t *testing.T) {
	requireBind(t, winKeytabIdentity(t), winKrbAccount)
}

// AC1, gMSA-derived keytab.
func TestWindowsLabKerberosGMSAKeytabBind(t *testing.T) {
	requireBind(t, winGMSAIdentity(t), "gmsa-t0566")
}

// RED until bug T-0846 is fixed: the same two binds through ad.Open (the code customers run).
func TestWindowsLabKerberosOpenKeytabBind(t *testing.T) {
	requireOpenBinds(t, winKeytabIdentity(t), winKrbAccount)
}
func TestWindowsLabKerberosOpenGMSABind(t *testing.T) {
	requireOpenBinds(t, winGMSAIdentity(t), "gmsa-t0566")
}

// AC1, wrong binding: a well-formed binding of a certificate the DC did not present (the lab CA's)
// must be rejected by a DC with LdapEnforceChannelBindingTokens=2, with ldap result 49.
func TestWindowsLabKerberosWrongChannelBindingRejected(t *testing.T) {
	k := winKeytabIdentity(t)
	// control first: the DC's own certificate binds, so the failure below is the DC's CBT check, not the KDC or the key.
	conn, good := winDialBound(t, k)
	if err := winHandshake(t, conn, k, good, winTLSName()); err != nil {
		t.Fatalf("control (correct binding) failed, the wrong-binding result below proves nothing: %v", err)
	}

	caPEM, err := os.ReadFile(winLabPath("WIN_LAB_CA", ".win-lab-ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(caPEM)
	if blk == nil {
		t.Fatal("bad lab CA")
	}
	other, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := gssapi.ChannelBindingFromCert(other)
	if err != nil {
		t.Fatal(err)
	}
	conn2, _ := winDialBound(t, k)
	err = winHandshake(t, conn2, k, wrong, winTLSName())
	if err == nil {
		t.Fatal("DC accepted a bind with the wrong channel binding")
	}
	if !ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
		t.Errorf("want ldap result 49 (invalid credentials), got: %v", err)
	}
}

// Absent binding: the client library refuses to bind without one, so no request ever reaches the DC.
func TestWindowsLabKerberosMissingChannelBindingRefusedClientSide(t *testing.T) {
	k := winKeytabIdentity(t)
	conn, _ := winDialBound(t, k)
	if err := winHandshake(t, conn, k, nil, winTLSName()); err == nil {
		t.Fatal("bind without channel binding succeeded")
	}
}

// SPN ldap/<fqdn>: a different host name in the SPN must not bind (the KDC has no such service).
func TestWindowsLabKerberosWrongSPNFails(t *testing.T) {
	k := winKeytabIdentity(t)
	conn, cb := winDialBound(t, k)
	if err := winHandshake(t, conn, k, cb, winTLSName()); err != nil {
		t.Fatalf("control (ldap/%s) failed: %v", winTLSName(), err)
	}
	conn2, cb2 := winDialBound(t, k)
	if err := winHandshake(t, conn2, k, cb2, "nosuchhost.win.activediq.test"); err == nil {
		t.Fatal("bind with an SPN for another host succeeded")
	}
}

// A different key for the same principal is refused by the KDC (the control proves the principal is otherwise good).
func TestWindowsLabKerberosBadKeytabFailsBind(t *testing.T) {
	k := winKeytabIdentity(t)
	conn, cb := winDialBound(t, k)
	if err := winHandshake(t, conn, k, cb, winTLSName()); err != nil {
		t.Fatalf("control (real keytab) failed: %v", err)
	}
	bad := k
	bad.Keytab = secret.FromBytes(mustBadKeytab(t, k))
	conn2, cb2 := winDialBound(t, bad)
	if err := winHandshake(t, conn2, bad, cb2, winTLSName()); err == nil {
		t.Fatal("bind with a foreign key succeeded")
	}
}

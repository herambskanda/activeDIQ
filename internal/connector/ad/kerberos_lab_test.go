//go:build lab

package ad

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	krb5gssapi "github.com/go-krb5/krb5/gssapi"
	"github.com/go-krb5/krb5/iana/etypeID"
	"github.com/go-krb5/krb5/keytab"

	"github.com/skenzeriq/activediq/internal/connector/ad/gssapi"
	"github.com/skenzeriq/activediq/internal/platform/secret"
)

// T-0560 acceptance: against the Samba lab (ldap server require strong auth = yes) a keytab
// identity binds with SASL GSSAPI over LDAPS with channel binding, and a wrong or missing binding
// is rejected. Samba proves the LDAP/Kerberos wire behaviour only; Windows Server is T-0133.
const (
	krbAccount = "svc-t0560-gssapi"
	krbRealm   = "LAB.ACTIVEDIQ.TEST"
	krbHost    = "dc1.lab.activediq.test"
)

// aesKeytab creates (or resets) the lab account and returns its keytab with RC4 entries removed,
// so the test cannot pass on RC4.
func aesKeytab(t *testing.T, env map[string]string) []byte {
	t.Helper()
	c := env["LAB_CONTAINER"]
	script := `set -eu
P="$(head -c 24 /dev/urandom | base64 | tr -d "=+/")Aa1!"
samba-tool user delete ` + krbAccount + ` >/dev/null 2>&1 || true
samba-tool user create ` + krbAccount + ` "$P" >/dev/null 2>&1
ldbmodify -H /var/lib/samba/private/sam.ldb >/dev/null <<LDIF
dn: CN=` + krbAccount + `,CN=Users,DC=lab,DC=activediq,DC=test
changetype: modify
replace: msDS-SupportedEncryptionTypes
msDS-SupportedEncryptionTypes: 24
LDIF
samba-tool user setpassword ` + krbAccount + ` --newpassword="$P" >/dev/null 2>&1
rm -f /tmp/t0560.keytab
samba-tool domain exportkeytab /tmp/t0560.keytab --principal=` + krbAccount + `@` + krbRealm + ` >/dev/null 2>&1`
	if out, err := exec.Command("docker", "exec", c, "sh", "-c", script).CombinedOutput(); err != nil {
		t.Fatalf("create account: %v\n%s", err, out)
	}
	dir := t.TempDir()
	full := filepath.Join(dir, "full.keytab")
	if out, err := exec.Command("docker", "cp", c+":/tmp/t0560.keytab", full).CombinedOutput(); err != nil {
		t.Fatalf("docker cp: %v\n%s", err, out)
	}
	exec.Command("docker", "exec", c, "rm", "-f", "/tmp/t0560.keytab").Run()
	kt, err := keytab.Load(full)
	if err != nil {
		t.Fatal(err)
	}
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
	b, err := kt.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func krbConfig(t *testing.T) (Config, Kerberos, *x509.CertPool, []byte) {
	t.Helper()
	env := labEnv(t)
	caPEM, err := os.ReadFile(filepath.Join("..", "..", "..", "lab", ".lab-ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("bad lab CA")
	}
	kt := aesKeytab(t, env)
	k := Kerberos{Principal: krbAccount, Realm: krbRealm, Keytab: secret.FromBytes(kt), KDCs: []string{"localhost:" + env["LAB_KRB_PORT"]}}
	cfg := Config{Servers: []string{"localhost:" + env["LAB_LDAPS_PORT"]}, ServerName: krbHost, RootCAs: pool, Kerberos: &k, Timeout: 20 * time.Second}
	return cfg, k, pool, caPEM
}

func TestKerberosBindWithChannelBinding(t *testing.T) {
	cfg, _, _, _ := krbConfig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	s, err := Open(ctx, cfg)
	if err != nil {
		t.Fatalf("GSSAPI open: %v", err)
	}
	defer s.Close()
	who, err := s.conn.WhoAmI(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(who.AuthzID, "u:LAB\\"+krbAccount) && !strings.Contains(strings.ToLower(who.AuthzID), krbAccount) {
		t.Errorf("whoami = %q", who.AuthzID)
	}
	// The session is a normal session: rootDSE and search work over the GSSAPI-bound connection.
	if _, err := s.RootDSE(ctx); err != nil {
		t.Errorf("rootDSE: %v", err)
	}
}

// bindWith dials the lab and attempts the GSSAPI handshake with the given channel binding.
func bindWith(t *testing.T, mode string) error {
	t.Helper()
	cfg, k, _, caPEM := krbConfig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	host, port := splitHostPort(cfg.Servers[0])
	conn, err := dial(ctx, cfg, host, port)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conf := k.krb5Config()
	kt := keytab.New()
	k.Keytab.Expose(func(b []byte) { err = kt.Unmarshal(b) })
	if err != nil {
		t.Fatal(err)
	}
	var cb *krb5gssapi.ChannelBinding
	switch mode {
	case "wrong": // a well-formed binding of a certificate the DC did not present (the CA's)
		blk, _ := pem.Decode(caPEM)
		other, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		if cb, err = gssapi.ChannelBindingFromCert(other); err != nil {
			t.Fatal(err)
		}
	case "none":
	}
	return gssapiHandshake(conn, k, kt, conf, cb, krbHost)
}

func TestKerberosWrongChannelBindingRejected(t *testing.T) {
	err := bindWith(t, "wrong")
	if err == nil {
		t.Fatal("DC accepted a bind with the wrong channel binding")
	}
	t.Logf("wrong binding rejected: %v", err)
}

func TestKerberosMissingChannelBindingRefusedClientSide(t *testing.T) {
	err := bindWith(t, "none")
	if err == nil {
		t.Fatal("bind without channel binding succeeded")
	}
}

func TestKerberosBadKeytabFailsBind(t *testing.T) {
	cfg, k, _, _ := krbConfig(t)
	k.Keytab = secret.FromBytes(mustBadKeytab(t, k))
	cfg.Kerberos = &k
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	_, err := Open(ctx, cfg)
	if err == nil {
		t.Fatal("bind with a different key succeeded")
	}
	var ae *Error
	if !errors.As(err, &ae) || ae.Code != CodeBindFailed && ae.Code != CodeInvalidArgument {
		t.Errorf("error = %v", err)
	}
}

// mustBadKeytab is a keytab for the same principal with a random key: the KDC must refuse it.
func mustBadKeytab(t *testing.T, k Kerberos) []byte {
	t.Helper()
	kt := keytab.New()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	if err := kt.AddEntry(k.Principal, k.Realm, string(key), time.Now(), 3, etypeID.AES256_CTS_HMAC_SHA1_96); err != nil {
		t.Fatal(err)
	}
	b, err := kt.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

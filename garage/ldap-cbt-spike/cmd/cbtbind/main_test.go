package main

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-krb5/krb5/iana/etypeID"
	"github.com/go-krb5/krb5/keytab"
)

// Integration tests against the T-0012 Samba lab (ldap server require strong auth = yes). They need the lab, so
// they are skipped unless SPIKE_CA and SPIKE_KEYTAB are set — scripts/run-spike.sh sets them.
func labArgs(t *testing.T) (ca, kt, ldaps, ldap, kdc string) {
	t.Helper()
	ca, kt = os.Getenv("SPIKE_CA"), os.Getenv("SPIKE_KEYTAB")
	if ca == "" || kt == "" {
		t.Skip("SPIKE_CA/SPIKE_KEYTAB not set: run scripts/run-spike.sh against the lab")
	}
	get := func(k, d string) string {
		if v := os.Getenv(k); v != "" {
			return v
		}
		return d
	}
	return ca, kt, get("SPIKE_LDAPS_ADDR", "127.0.0.1:1636"), get("SPIKE_LDAP_ADDR", "127.0.0.1:1389"), get("SPIKE_KDC", "127.0.0.1:1088")
}

func TestKeytabIsAESOnly(t *testing.T) {
	_, ktPath, _, _, _ := labArgs(t)
	kt, err := keytab.Load(ktPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(kt.Entries) == 0 {
		t.Fatal("empty keytab")
	}
	for _, e := range kt.Entries {
		if e.Key.KeyType != etypeID.AES128_CTS_HMAC_SHA1_96 && e.Key.KeyType != etypeID.AES256_CTS_HMAC_SHA1_96 {
			t.Fatalf("keytab holds a non-AES key (etype %d)", e.Key.KeyType)
		}
	}
}

func TestBindMatrixAgainstStrongAuthLab(t *testing.T) {
	ca, kt, ldaps, ldap, kdc := labArgs(t)
	const sn, user, realm = "dc1.lab.activediq.test", "svc-cbt-spike", "LAB.ACTIVEDIQ.TEST"
	for _, tc := range []struct {
		mode, addr, cbt string
		wantErr         string // "" = must succeed
	}{
		{"ldaps", ldaps, "server-end-point", ""},
		{"starttls", ldap, "server-end-point", ""},
		{"ldaps", ldaps, "none", "80090346"}, // SEC_E_BAD_BINDINGS
		{"starttls", ldap, "none", "80090346"},
		{"ldaps", ldaps, "wrong", "80090346"}, // a binding over a different certificate
		{"starttls", ldap, "wrong", "80090346"},
	} {
		t.Run(tc.mode+"/cbt="+tc.cbt, func(t *testing.T) {
			err := run(tc.mode, tc.addr, sn, ca, kt, user, realm, kdc, tc.cbt, 20*time.Second)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("bind must succeed: %v", err)
			case tc.wantErr != "" && err == nil:
				t.Fatalf("bind without a correct channel binding was ACCEPTED")
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Fatalf("rejected for the wrong reason: %v", err)
			}
		})
	}
}

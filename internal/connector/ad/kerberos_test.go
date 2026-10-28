package ad

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/go-krb5/krb5/keytab"
	"github.com/go-ldap/ldap/v3"

	"github.com/skenzeriq/activediq/internal/platform/secret"
)

func goodKrb() Kerberos {
	return Kerberos{Principal: "svc-activediq$", Realm: "LAB.ACTIVEDIQ.TEST", Keytab: secret.FromBytes([]byte{5, 2}), KDCs: []string{"dc1.lab.activediq.test", "10.0.0.5:88"}}
}

func TestKerberosValidate(t *testing.T) {
	if err := goodKrb().validate(); err != nil {
		t.Fatalf("good identity rejected: %v", err)
	}
	bad := map[string]func(*Kerberos){
		"empty keytab":      func(k *Kerberos) { k.Keytab = secret.Secret{} },
		"realm newline":     func(k *Kerberos) { k.Realm = "A.B\n[realms]" },
		"realm brace":       func(k *Kerberos) { k.Realm = "A.B{" },
		"principal space":   func(k *Kerberos) { k.Principal = "a b" },
		"kdc injection":     func(k *Kerberos) { k.KDCs = []string{"x\n admin_server = evil"} },
		"kdc bad port":      func(k *Kerberos) { k.KDCs = []string{"dc1.lab:99999"} },
		"kdc eq":            func(k *Kerberos) { k.KDCs = []string{"a=b"} },
		"principal missing": func(k *Kerberos) { k.Principal = "" },
	}
	for name, mut := range bad {
		k := goodKrb()
		mut(&k)
		if err := k.validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestKerberosConfigTypedAESOnly(t *testing.T) {
	c := goodKrb().krb5Config()
	if c.LibDefaults.DefaultRealm != "LAB.ACTIVEDIQ.TEST" || c.LibDefaults.DNSLookupKDC {
		t.Errorf("libdefaults: %+v", c.LibDefaults)
	}
	if len(c.Realms) != 1 || c.Realms[0].Realm != "LAB.ACTIVEDIQ.TEST" {
		t.Fatalf("realms: %+v", c.Realms)
	}
	want := []string{"dc1.lab.activediq.test:88", "10.0.0.5:88"}
	if got := c.Realms[0].KDC; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("kdc = %v, want %v", got, want)
	}
	for _, ids := range [][]int32{c.LibDefaults.DefaultTktEnctypeIDs, c.LibDefaults.DefaultTGSEnctypeIDs, c.LibDefaults.PermittedEnctypeIDs} {
		if len(ids) != 2 || ids[0] != 18 || ids[1] != 17 {
			t.Errorf("enctype IDs not AES-only: %v", ids)
		}
	}
	for _, names := range [][]string{c.LibDefaults.DefaultTktEnctypes, c.LibDefaults.DefaultTGSEnctypes, c.LibDefaults.PermittedEnctypes} {
		for _, n := range names {
			if !strings.HasPrefix(n, "aes") {
				t.Errorf("weak enctype %q", n)
			}
		}
	}
	k := goodKrb()
	k.KDCs = nil
	nc := k.krb5Config()
	if !nc.LibDefaults.DNSLookupKDC || len(nc.Realms) != 0 {
		t.Error("no KDCs should enable SRV discovery and define no realm")
	}
}

func TestZeroKeytabWipesEveryKey(t *testing.T) {
	kt := keytab.New()
	for i := 0; i < 3; i++ {
		if err := kt.AddEntry("svc", "LAB.ACTIVEDIQ.TEST", "pw", time.Now(), 1, 18); err != nil {
			t.Fatal(err)
		}
	}
	keys := make([][]byte, len(kt.Entries))
	for i, e := range kt.Entries {
		if allZero(e.Key.KeyValue) {
			t.Fatal("fixture key already zero")
		}
		keys[i] = e.Key.KeyValue
	}
	zeroKeytab(kt)
	zeroKeytab(nil)
	for i, kv := range keys {
		if !allZero(kv) {
			t.Errorf("entry %d key not zeroised", i)
		}
	}
}

// Success or failure, the parsed keytab is all-zero once the bind returns. Here the peer hangs up,
// so the handshake fails after the keytab was parsed.
func TestBindWithKeytabZeroisesParsedKeytab(t *testing.T) {
	kt := keytab.New()
	if err := kt.AddEntry("svc", "LAB.ACTIVEDIQ.TEST", "pw", time.Now(), 1, 18); err != nil {
		t.Fatal(err)
	}
	raw, err := kt.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	k := goodKrb()
	k.Keytab = secret.FromBytes(raw)
	var parsed *keytab.Keytab
	keytabParsed = func(p *keytab.Keytab) {
		parsed = p
		if allZero(p.Entries[0].Key.KeyValue) {
			t.Error("keytab parsed as zero")
		}
	}
	t.Cleanup(func() { keytabParsed = nil })
	c1, c2 := net.Pipe()
	c2.Close()
	conn := ldap.NewConn(c1, false)
	conn.Start()
	defer conn.Close()
	if err := bindWithKeytab(conn, k, nil, "dc1.lab.activediq.test"); err == nil {
		t.Fatal("bind against a closed peer succeeded")
	}
	if parsed == nil {
		t.Fatal("seam never saw the keytab")
	}
	for i, e := range parsed.Entries {
		if !allZero(e.Key.KeyValue) {
			t.Errorf("entry %d key not zeroised after bind", i)
		}
	}
}

// A keytab that fails to parse is rejected without reaching the handshake.
func TestBindWithKeytabUnreadable(t *testing.T) {
	if err := bindWithKeytab(nil, goodKrb(), nil, "dc1.lab.activediq.test"); err == nil {
		t.Fatal("garbage keytab accepted")
	}
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return len(b) > 0
}

func TestKerberosRedacted(t *testing.T) {
	if s := goodKrb().String(); strings.Contains(s, "svc") {
		t.Errorf("String leaks: %s", s)
	}
}

func TestOpenRejectsBothOrNeitherIdentity(t *testing.T) {
	ctx := context.Background()
	k := goodKrb()
	both := Config{Servers: []string{"dc1:636"}, Kerberos: &k, Credential: Credential{BindName: "u", Password: secret.FromBytes([]byte("p"))}}
	if _, err := open(ctx, both, false); err == nil || !strings.Contains(err.Error(), "either") {
		t.Errorf("both set: %v", err)
	}
	if _, err := open(ctx, Config{Servers: []string{"dc1:636"}}, false); err == nil {
		t.Error("neither set accepted")
	}
}

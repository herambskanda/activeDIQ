package ad

import (
	"context"
	"strings"
	"testing"

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

func TestKerberosConfAESOnlyAndShape(t *testing.T) {
	c := goodKrb().krb5Conf()
	for _, want := range []string{"default_realm = LAB.ACTIVEDIQ.TEST", "dns_lookup_kdc = false", "kdc = dc1.lab.activediq.test:88", "kdc = 10.0.0.5:88"} {
		if !strings.Contains(c, want) {
			t.Errorf("conf lacks %q:\n%s", want, c)
		}
	}
	if strings.Contains(strings.ToLower(c), "rc4") || strings.Contains(c, "des") {
		t.Errorf("conf offers a weak enctype:\n%s", c)
	}
	k := goodKrb()
	k.KDCs = nil
	if !strings.Contains(k.krb5Conf(), "dns_lookup_kdc = true") {
		t.Error("no KDCs should enable SRV discovery")
	}
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

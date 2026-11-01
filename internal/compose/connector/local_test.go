package connector

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
)

const goodLocal = `{"connection_id":"conn-1","enrollment_dir":"/var/lib/diq/enroll","data_dir":"/var/lib/diq/data",
"servers":["dc1.lab.test"],"ca_file":"/etc/diq/ca.pem","kerberos":{"principal":"svc-diq$","realm":"LAB.TEST","keytab_file":"/etc/diq/svc.keytab"}}`

func TestParseLocalStrict(t *testing.T) {
	l, err := ParseLocal([]byte(goodLocal))
	if err != nil || l.ConnectionID != "conn-1" || l.Kerberos.Principal != "svc-diq$" {
		t.Fatalf("good document: %+v %v", l, err)
	}
	bad := map[string]string{
		"unknown key":     strings.Replace(goodLocal, `"servers"`, `"password":"x","servers"`, 1),
		"trailing doc":    goodLocal + goodLocal,
		"no connection":   strings.Replace(goodLocal, `"conn-1"`, `""`, 1),
		"odd connection":  strings.Replace(goodLocal, `"conn-1"`, `"a b\"c"`, 1),
		"relative dir":    strings.Replace(goodLocal, `/var/lib/diq/data`, `data`, 1),
		"no servers":      strings.Replace(goodLocal, `["dc1.lab.test"]`, `[]`, 1),
		"no kerberos":     strings.Replace(goodLocal, `"principal":"svc-diq$"`, `"principal":""`, 1),
		"relative keytab": strings.Replace(goodLocal, `/etc/diq/svc.keytab`, `svc.keytab`, 1),
		"empty":           ``,
		"oversize":        `{"connection_id":"` + strings.Repeat("a", maxLocalBytes) + `"}`,
	}
	for name, doc := range bad {
		if _, err := ParseLocal([]byte(doc)); !errors.Is(err, ErrLocal) {
			t.Errorf("%s: err = %v, want ErrLocal", name, err)
		}
	}
	if _, err := LoadLocal(""); !errors.Is(err, ErrNoConfig) {
		t.Errorf("no path: %v", err)
	}
}

// AC3: the session is Kerberos (SASL GSSAPI over LDAPS with channel binding), never a password, and
// trusts the customer CA only.
func TestADConfigIsKerberosOnly(t *testing.T) {
	d := t.TempDir()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageCertSign}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, k.Public(), k)
	pemb := []byte("-----BEGIN CERTIFICATE-----\n" + b64(der) + "\n-----END CERTIFICATE-----\n")
	loc := Local{ConnectionID: "c", Servers: []string{"dc1.lab.test"}, ServerName: "dc1.lab.test",
		CAFile: filepath.Join(d, "ca.pem"), Kerberos: LocalKerberos{Principal: "svc$", Realm: "LAB.TEST", KeytabFile: filepath.Join(d, "kt"), KDCs: []string{"kdc.lab.test"}}}
	if err := os.WriteFile(loc.CAFile, pemb, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(loc.Kerberos.KeytabFile, []byte("keytab-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := adConfig(loc)
	if err != nil {
		t.Fatal(err)
	}
	if c.Kerberos == nil || c.Kerberos.Principal != "svc$" || c.Kerberos.Keytab.IsEmpty() {
		t.Fatal("no kerberos identity")
	}
	if c.Credential.BindName != "" || !c.Credential.Password.IsEmpty() {
		t.Fatal("a password credential rode along with kerberos")
	}
	if c.RootCAs == nil {
		t.Fatal("the customer CA pool is not set (system roots would be trusted)")
	}
	if strings.Contains(c.Kerberos.String()+" "+slogText(c.Kerberos), "keytab-bytes") {
		t.Fatal("keytab printed")
	}
	// A bad CA file and a missing keytab refuse; neither error names the path content.
	loc.CAFile = loc.Kerberos.KeytabFile
	if _, err := adConfig(loc); err == nil {
		t.Fatal("non-PEM CA accepted")
	}
	loc.CAFile = filepath.Join(d, "ca.pem")
	loc.Kerberos.KeytabFile = filepath.Join(d, "nope")
	if _, err := adConfig(loc); err == nil {
		t.Fatal("missing keytab accepted")
	}
}

func slogText(v any) string {
	var b strings.Builder
	slog.New(slog.NewTextHandler(&b, nil)).Info("x", "k", v)
	return b.String()
}

func b64(b []byte) string {
	const t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var sb strings.Builder
	for i := 0; i < len(b); i += 3 {
		var n uint32
		m := 0
		for j := 0; j < 3; j++ {
			n <<= 8
			if i+j < len(b) {
				n |= uint32(b[i+j])
				m++
			}
		}
		for j := 0; j < 4; j++ {
			if j <= m {
				sb.WriteByte(t[n>>(18-6*uint(j))&63])
			} else {
				sb.WriteByte('=')
			}
		}
		if (i/3+1)%16 == 0 {
			sb.WriteByte('\n')
		}
	}
	return sb.String()
}

// AC4 (pins part): the C13 pins are durable, only grow, and a new instance on the same file reloads them.
func TestFilePinsSurviveRestartAndOnlyGrow(t *testing.T) {
	p := filepath.Join(t.TempDir(), pinsFile)
	a, b := guid.GUID{1}, guid.GUID{2}
	first := &filePins{path: p}
	if got, err := first.PinnedC13(context.Background()); err != nil || len(got) != 0 {
		t.Fatalf("fresh: %v %v", got, err)
	}
	if err := first.PinC13(context.Background(), []guid.GUID{a}); err != nil {
		t.Fatal(err)
	}
	second := &filePins{path: p} // a restart
	if err := second.PinC13(context.Background(), []guid.GUID{a, b}); err != nil {
		t.Fatal(err)
	}
	got, err := (&filePins{path: p}).PinnedC13(context.Background())
	if err != nil || len(got) != 2 {
		t.Fatalf("after restart: %v %v", got, err)
	}
	if err := os.WriteFile(p, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (&filePins{path: p}).PinnedC13(context.Background()); err == nil {
		t.Fatal("a corrupt pin file read as an empty set")
	}
	if err := (&filePins{path: p}).PinC13(context.Background(), []guid.GUID{a}); err == nil {
		t.Fatal("a corrupt pin file was overwritten")
	}
}

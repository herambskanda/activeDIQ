//go:build lab

package connector_test

import (
	"context"
	"crypto/x509"
	"encoding/json/v2"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-krb5/krb5/iana/etypeID"
	"github.com/go-krb5/krb5/keytab"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/skenzeriq/activediq/internal/compose/config"
	"github.com/skenzeriq/activediq/internal/compose/connector"
	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/write"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/platform/fleet"
	"github.com/skenzeriq/activediq/internal/platform/fleet/dial"
	"github.com/skenzeriq/activediq/internal/platform/fleet/tunnelclient"
	"github.com/skenzeriq/activediq/internal/platform/secret"
	v1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
	"github.com/skenzeriq/activediq/internal/testlab"
)

// T-0703 (M1 demo criterion 2): connector.Run, booted against the Samba lab with a Kerberos keytab
// identity, serves VerifyConnection and Read over the tunnel. Samba proves the LDAP/Kerberos wire path
// and the handler assembly only; Windows Kerberos/CBT and service-account privilege are T-0790.
const (
	labAccount = "svc-t0703-conn"
	labRealm   = "LAB.ACTIVEDIQ.TEST"
	labHost    = "dc1.lab.activediq.test"
)

func labKeytab(t *testing.T, ctr string) []byte {
	t.Helper()
	script := `set -eu
P="$(head -c 24 /dev/urandom | base64 | tr -d "=+/")Aa1!"
samba-tool user delete ` + labAccount + ` >/dev/null 2>&1 || true
samba-tool user create ` + labAccount + ` "$P" >/dev/null 2>&1
ldbmodify -H /var/lib/samba/private/sam.ldb >/dev/null <<LDIF
dn: CN=` + labAccount + `,CN=Users,DC=lab,DC=activediq,DC=test
changetype: modify
replace: msDS-SupportedEncryptionTypes
msDS-SupportedEncryptionTypes: 24
LDIF
samba-tool user setpassword ` + labAccount + ` --newpassword="$P" >/dev/null 2>&1
rm -f /tmp/t0703.keytab
samba-tool domain exportkeytab /tmp/t0703.keytab --principal=` + labAccount + `@` + labRealm + ` >/dev/null 2>&1`
	if out, err := exec.Command("docker", "exec", ctr, "sh", "-c", script).CombinedOutput(); err != nil {
		t.Fatalf("create account: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "exec", ctr, "samba-tool", "user", "delete", labAccount).Run() })
	full := filepath.Join(t.TempDir(), "full.keytab")
	if out, err := exec.Command("docker", "cp", ctr+":/tmp/t0703.keytab", full).CombinedOutput(); err != nil {
		t.Fatalf("docker cp: %v\n%s", err, out)
	}
	_ = exec.Command("docker", "exec", ctr, "rm", "-f", "/tmp/t0703.keytab").Run()
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
	kt.Entries = kept
	b, err := kt.Marshal()
	if err != nil || len(kept) == 0 {
		t.Fatalf("keytab: %v (%d AES entries)", err, len(kept))
	}
	return b
}

func TestLabRunServesVerifyAndReadOverTunnel(t *testing.T) {
	env := testlab.Load(t)
	dir := t.TempDir()
	caPEM, err := os.ReadFile(filepath.Join("..", "..", "..", "lab", ".lab-ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	caFile, ktFile := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "svc.keytab")
	ktBytes := labKeytab(t, env.Container)
	for p, b := range map[string][]byte{caFile: caPEM, ktFile: ktBytes} {
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	krbPort := os.Getenv("LAB_KRB_PORT")
	if krbPort == "" {
		t.Fatal("LAB_KRB_PORT not set (source lab/.lab.env)")
	}
	conf := map[string]any{"connection_id": "lab-conn-1", "enrollment_dir": filepath.Join(dir, "enroll"), "data_dir": filepath.Join(dir, "data"),
		"servers": []string{"localhost:" + env.Port}, "server_name": labHost, "ca_file": caFile,
		"kerberos": map[string]any{"principal": labAccount, "realm": labRealm, "keytab_file": ktFile, "kdcs": []string{"localhost:" + krbPort}}}
	cb, _ := json.Marshal(conf)
	cfgPath := filepath.Join(dir, "connector.json")
	if err := os.WriteFile(cfgPath, cb, 0o600); err != nil {
		t.Fatal(err)
	}

	// The lab-side truth the server would hold: forest identity and an object to read.
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	probe, err := ad.Open(ctx, ad.Config{Servers: []string{"localhost:" + env.Port}, ServerName: labHost, RootCAs: pool, PageSize: 500,
		Kerberos: &ad.Kerberos{Principal: labAccount, Realm: labRealm, Keytab: secret.FromBytes(ktBytes), KDCs: []string{"localhost:" + krbPort}}})
	if err != nil {
		t.Fatalf("probe session: %v", err)
	}
	defer probe.Close()
	rd, err := probe.RootDSE(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rootRef, _ := dn.ParseObjectRef(rd.RootDomainNamingContext)
	head, err := probe.Read(ctx, rootRef, []string{"objectGUID"}, ad.ReadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	rg, err := head.GUID()
	if err != nil {
		t.Fatal(err)
	}
	ident := &v1.DirectoryIdentity{Identity: &v1.DirectoryIdentity_AdForest{AdForest: &v1.AdForestIdentity{ForestRootNcGuid: write.GUIDToWire(rg)}}}
	conn := &v1.ConnectionRef{ConnectionId: "lab-conn-1", DirectoryIdentity: ident}

	// Boot through the real run path: only the enrolment load and the dial-out are substituted; the AD
	// session, handlers and TunnelBinding are the production assembly.
	exercise := func(c tunnelclient.Config) { labExercise(t, c, conn, ident, rg) }
	var served bool
	err = connector.RunWith(ctx, config.Config{ConnectorConfigPath: cfgPath},
		func(string) (*dial.State, error) { return leafState(t, fleet.KindConnector), nil },
		func(ctx context.Context, loc connector.Local, log *slog.Logger) (*connector.Backend, error) {
			return connector.OpenBackend(ctx, loc, log)
		},
		func(_ context.Context, c tunnelclient.Config) { served = true; exercise(c) })
	if err != nil || !served {
		t.Fatalf("Run: served=%v err=%v", served, err)
	}
}

func labExercise(t *testing.T, got tunnelclient.Config, conn *v1.ConnectionRef, ident *v1.DirectoryIdentity, rg guid.GUID) {
	t.Helper()
	tn, tctx := tunnelFor(t, got.Binding, 60*time.Second)
	c := v1.NewConnectorClient(tn.srv.Conn())

	// Verify over the tunnel: a verdict arrives and the stream ends `completed`.
	vs, err := c.VerifyConnection(tctx, &v1.VerifyConnectionRequest{Connection: conn,
		RunKind: v1.VerificationRunKind_VERIFICATION_RUN_KIND_ONBOARDING, VerificationId: &v1.Guid{Value: []byte("0123456789abcdef")}})
	if err != nil {
		t.Fatal(err)
	}
	var completed, tier0 bool
	for {
		m, err := vs.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("VerifyConnection: %v", err)
		}
		completed = completed || m.GetCompleted() != nil
		tier0 = tier0 || m.GetTier0Set() != nil
	}
	if !completed || !tier0 {
		t.Fatalf("verify stream: completed=%v tier0set=%v", completed, tier0)
	}

	// Read over the tunnel returns the forest root with the tier-0 verdict of the connector's classifier.
	rs, err := c.Read(tctx, &v1.ReadRequest{Connection: conn, Guid: write.GUIDToWire(rg), Attributes: []string{"distinguishedName"}, IncludeTier0: true})
	if err != nil {
		t.Fatal(err)
	}
	var hdr *v1.ReadHeader
	for {
		m, err := rs.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
		if h := m.GetHeader(); h != nil {
			hdr = h
		}
	}
	if hdr == nil || hdr.GetEntry() == nil || hdr.GetTier0() == nil {
		t.Fatalf("read header = %+v, want an entry with a tier0 verdict", hdr)
	}

	// A request for another connection is refused before any directory work.
	bad := &v1.ConnectionRef{ConnectionId: "other", DirectoryIdentity: ident}
	vs, err = c.VerifyConnection(tctx, &v1.VerifyConnectionRequest{Connection: bad,
		RunKind: v1.VerificationRunKind_VERIFICATION_RUN_KIND_ONBOARDING, VerificationId: &v1.Guid{Value: []byte("0123456789abcdef")}})
	if err == nil {
		_, err = vs.Recv()
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("foreign connection_id: %v, want InvalidArgument", err)
	}
}

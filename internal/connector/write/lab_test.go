//go:build lab

package write

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/tier0"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/platform/secret"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// AC2 on Samba: `make lab-up && go test -tags lab ./internal/connector/write -run TestLab`.
// Samba proves the LDAP semantics (in-chain membership, tokenGroups, GUID reads). Windows-only
// behaviour (live DACL defaults, GPO links on a real DC, RODC) stays a Windows-lab ticket.

const labDom = "DC=lab,DC=activediq,DC=test"

func labEnv(t *testing.T) map[string]string {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "..", "..", "lab", ".lab.env"))
	if err != nil {
		t.Fatalf("lab not up (make lab-up): %v", err)
	}
	defer f.Close()
	env := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(sc.Text()), "export "))
		if k, v, ok := strings.Cut(l, "="); ok && !strings.HasPrefix(l, "#") {
			env[k] = strings.Trim(v, `"'`)
		}
	}
	return env
}

func TestLabAddedToDomainAdminsAfterLastSyncIsRefused(t *testing.T) {
	env := labEnv(t)
	pem, err := os.ReadFile(filepath.Join("..", "..", "..", "lab", ".lab-ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	port := env["LAB_LDAPS_PORT"]
	if port == "" {
		port = "636"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()
	sess, err := ad.Open(ctx, ad.Config{
		Servers: []string{"localhost:" + port}, RootCAs: pool, PageSize: 500,
		Credential: ad.Credential{BindName: "svc-activediq@lab.activediq.test", Password: secret.FromBytes([]byte(env["LAB_SVC_PASSWORD"]))},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	admin, err := ldap.DialURL("ldaps://localhost:"+port, ldap.DialWithTLSConfig(&tls.Config{RootCAs: pool, ServerName: "localhost"}))
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if err := admin.Bind("Administrator@lab.activediq.test", env["LAB_ADMIN_PASSWORD"]); err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("t0098-%d", time.Now().UnixNano()%1_000_000)
	userDN := "CN=" + name + ",CN=Users," + labDom
	add := ldap.NewAddRequest(userDN, nil)
	add.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "user"})
	add.Attribute("sAMAccountName", []string{name})
	if err := admin.Add(add); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Del(ldap.NewDelRequest(userDN, nil)) })

	ref, err := dn.ParseObjectRef(userDN)
	if err != nil {
		t.Fatal(err)
	}
	dir := tier0.SessionDirectory{S: sess}
	e, err := dir.Get(ctx, ref, []string{"objectGUID"})
	if err != nil {
		t.Fatal(err)
	}
	id, err := e.GUID()
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	run := passRun(nil) // the connector's last VerifyConnection knows nothing of this user
	run.CompletedAt = now
	book, _ := NewGateBook(&memBaseline{}, time.Now)
	book.Complete(connID, run)
	h, err := New(&ADProvider{Dir: dir, ID: adIdentity()}, book, WithRecorder(&memRecorder{}))
	if err != nil {
		t.Fatal(err)
	}
	fresh := func() *connectorv1.Tier0Context {
		return &connectorv1.Tier0Context{Tier0Revision: 1, Statements: []*connectorv1.CorrelationStatement{noLink(id, now)}}
	}
	// Before: an ordinary user reaches the kind check.
	_, err = h.Plan(ctx, planReq(id, fresh()))
	if connErr(t, err).GetCode() != connectorv1.ErrorCode_ERROR_CODE_CAPABILITY_UNSUPPORTED {
		t.Fatalf("before: %v", err)
	}
	mod := ldap.NewModifyRequest("CN=Domain Admins,CN=Users,"+labDom, nil)
	mod.Add("member", []string{userDN})
	if err := admin.Modify(mod); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		m := ldap.NewModifyRequest("CN=Domain Admins,CN=Users,"+labDom, nil)
		m.Delete("member", []string{userDN})
		_ = admin.Modify(m)
	})
	// After: the live re-read finds C2 although the connector's set and the context do not.
	_, err = h.Plan(ctx, planReq(id, fresh()))
	d := wantTier0(t, err, connectorv1.Tier0RefusalStage_TIER0_REFUSAL_STAGE_LIVE_REREAD)
	if len(d.GetBasis()) == 0 || d.GetBasis()[0] != tier0.C2 {
		t.Fatalf("basis %v", d.GetBasis())
	}
	_, err = h.Apply(ctx, applyReq(id, fresh()))
	wantTier0(t, err, connectorv1.Tier0RefusalStage_TIER0_REFUSAL_STAGE_LIVE_REREAD)
}

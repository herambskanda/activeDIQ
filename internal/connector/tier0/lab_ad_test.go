//go:build lab

package tier0

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
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/platform/secret"
)

// Lab test (Samba AD): `make lab-up && go test -tags lab ./internal/connector/tier0 -run TestLabAD`.
// Samba proves the LDAP semantics only (paging, in-chain, primaryGroupID, wellKnownObjects, SD
// bytes). Windows-only facts (live DACL defaults, RODC corroboration, KDS keys) stay Windows-lab.

const labDom = "DC=lab,DC=activediq,DC=test"

func labEnvAD(t *testing.T) map[string]string {
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

// AC1 on the lab: add a fresh user to Domain Admins after a first classification; the next call
// sees it via C2 although adminCount is not set on the user yet.
func TestLabADMembershipAfterClassification(t *testing.T) {
	env := labEnvAD(t)
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
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
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
	name := fmt.Sprintf("t0093-%d", time.Now().UnixNano()%1_000_000)
	userDN := "CN=" + name + ",CN=Users," + labDom
	add := ldap.NewAddRequest(userDN, nil)
	add.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "user"})
	add.Attribute("sAMAccountName", []string{name})
	if err := admin.Add(add); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Del(ldap.NewDelRequest(userDN, nil)) })

	c := NewAD(SessionDirectory{S: sess})
	target, err := dn.ParseObjectRef(userDN)
	if err != nil {
		t.Fatal(err)
	}
	r, err := c.Classify(ctx, target, ADInput{CorrelationKnown: true})
	if err != nil || r.Tier0 {
		t.Fatalf("before: %+v %v", r, err)
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
	r, err = c.Classify(ctx, target, ADInput{CorrelationKnown: true})
	if err != nil || !r.Tier0 || !has(r, C2) {
		t.Fatalf("after: %+v %v", r, err)
	}
}

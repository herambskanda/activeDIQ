//go:build lab

package read_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/read"
	"github.com/skenzeriq/activediq/internal/connector/write"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/platform/secret"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// T-1586 (CC-READ-10) on Samba: `make lab-up && go test -tags lab ./internal/connector/read -run TestLabChildCount`.
// An OU with 0 and with 3 children, and one with 1,200 children counted up to the cap of 1,000.
func TestLabChildCount(t *testing.T) {
	env := labEnv(t)
	pem, err := os.ReadFile(filepath.Join("..", "..", "..", "lab", ".lab-ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	port := env["LAB_LDAPS_PORT"]
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()
	sess, err := ad.Open(ctx, ad.Config{Servers: []string{"localhost:" + port}, RootCAs: pool, PageSize: 500,
		Credential: ad.Credential{BindName: "svc-activediq@lab.activediq.test", Password: secret.FromBytes([]byte(env["LAB_SVC_PASSWORD"]))}})
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
	guidOf := func(dn string) guid.GUID {
		r, err := admin.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"objectGUID"}, nil))
		if err != nil || len(r.Entries) != 1 {
			t.Fatalf("guid of %s: %v", dn, err)
		}
		g, err := guid.FromBytes(r.Entries[0].GetRawAttributeValue("objectGUID"))
		if err != nil {
			t.Fatal(err)
		}
		return g
	}
	add := func(dn string, class []string) {
		t.Helper()
		a := ldap.NewAddRequest(dn, nil)
		a.Attribute("objectClass", class)
		if err := admin.Add(a); err != nil {
			t.Fatalf("add %s: %v", dn, err)
		}
	}
	base := fmt.Sprintf("OU=cc%d,%s", time.Now().UnixNano()%1_000_000_000, labDom)
	add(base, []string{"top", "organizationalUnit"})
	t.Cleanup(func() {
		res, err := admin.Search(ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"dn"}, nil))
		if err != nil {
			return
		}
		for i := len(res.Entries) - 1; i >= 0; i-- { // deepest first (search order is parent before child)
			_ = admin.Del(ldap.NewDelRequest(res.Entries[i].DN, nil))
		}
	})
	empty, three, big := "OU=empty,"+base, "OU=three,"+base, "OU=big,"+base
	for _, d := range []string{empty, three, big} {
		add(d, []string{"top", "organizationalUnit"})
	}
	// Children of every kind count, and a grandchild does not (one level only).
	add("CN=c\\, Ünï,"+three, []string{"top", "contact"})
	add("OU=sub,"+three, []string{"top", "organizationalUnit"})
	add("CN=g,"+three, []string{"top", "group"})
	add("CN=deep,OU=sub,"+three, []string{"top", "contact"})
	for i := 0; i < 1200; i++ {
		add(fmt.Sprintf("CN=k%04d,%s", i, big), []string{"top", "contact"})
	}

	ident := &connectorv1.DirectoryIdentity{Identity: &connectorv1.DirectoryIdentity_AdForest{AdForest: &connectorv1.AdForestIdentity{
		ForestRootNcGuid: write.GUIDToWire(guidOf(labDom))}}}
	prov := write.NewADProvider(sess, nil, ident, &memPins{})
	src, err := read.NewADSource(sess, prov)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prov.BoundDC(ctx); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, dn string
		limit    int
		n        int
		capped   bool
	}{
		{"empty", empty, read.ChildCountCap, 0, false},
		{"three", three, read.ChildCountCap, 3, false},
		{"big capped", big, read.ChildCountCap, read.ChildCountCap, true},
		{"big under a larger limit", big, 5000, 1200, false},
	} {
		n, capped, err := src.CountChildren(ctx, guidOf(c.dn), c.limit)
		if err != nil || n != c.n || capped != c.capped {
			t.Errorf("%s: n=%d capped=%v err=%v, want %d %v", c.name, n, capped, err, c.n, c.capped)
		}
	}
}

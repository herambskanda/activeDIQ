//go:build lab && windowslab

package read_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/read"
	"github.com/skenzeriq/activediq/internal/connector/write"
	"github.com/skenzeriq/activediq/internal/directory/inventory"
	dirsync "github.com/skenzeriq/activediq/internal/directory/sync"
	"github.com/skenzeriq/activediq/internal/platform/secret"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// T-1787 (split from T-1205): accountExpires 0 / MAX (9223372036854775807) / a future value and
// lastLogonTimestamp present / absent, requested through the real ScopedSearch handler against the Windows
// lab DC (dc1) with the widened sync attribute list. With SYNC_CAPTURE_DIR set the entries are written as
// protojson, the fixtures internal/directory/sync/windows_golden_test.go reads. Seeding is plain LDAPS adds
// by the lab Administrator in a throw-away OU; the whole run holds the dc1 lock (runbook section 10):
//
//	lab/windows/bin/with-dc1-lock -- env SYNC_CAPTURE_DIR=$PWD/internal/directory/sync/testdata/windows \
//	  go test -tags 'lab windowslab' ./internal/connector/read -run TestWindowsLabSyncCapture
func TestWindowsLabSyncCapture(t *testing.T) {
	const fqdn, dom = "win.activediq.test", "DC=win,DC=activediq,DC=test"
	if os.Getenv("DIQ_DC1_LOCK_HELD") == "" {
		t.Fatal("run under lab/windows/bin/with-dc1-lock (runbook section 10)")
	}
	lf := func(env, def string) string {
		if p := os.Getenv(env); p != "" {
			return p
		}
		return filepath.Join("..", "..", "..", "lab", "windows", def)
	}
	f, err := os.Open(lf("WIN_LAB_ENV", ".win-lab.env"))
	if err != nil {
		t.Fatalf("windows lab credentials: %v", err)
	}
	env := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "="); ok && !strings.HasPrefix(k, "#") {
			env[k] = strings.Trim(v, `"'`)
		}
	}
	f.Close()
	host := os.Getenv("WIN_LAB_DC_ADDR")
	if host == "" {
		host = env["WIN_LAB_DC_ADDR"]
	}
	if host == "" {
		t.Fatal("WIN_LAB_DC_ADDR is not set")
	}
	tlsName := os.Getenv("WIN_LAB_TLS_NAME")
	if tlsName == "" {
		tlsName = "dc1." + fqdn
	}
	pem, err := os.ReadFile(lf("WIN_LAB_CA", ".win-lab-ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("bad windows lab CA")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	sess, err := ad.Open(ctx, ad.Config{Servers: []string{host + ":636"}, ServerName: tlsName, RootCAs: pool, PageSize: searchPage,
		Schema:     ad.DefaultSchema(),
		Credential: ad.Credential{BindName: "svc-activediq@" + fqdn, Password: secret.FromBytes([]byte(env["WIN_LAB_SVC_PASSWORD"]))}})
	if err != nil {
		t.Fatalf("service bind: %v", err)
	}
	t.Cleanup(func() { sess.Close() })
	adm, err := ldap.DialURL("ldaps://"+host+":636", ldap.DialWithTLSConfig(&tls.Config{RootCAs: pool, ServerName: tlsName, MinVersion: tls.VersionTLS12}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { adm.Close() })
	if err := adm.Bind("Administrator@"+fqdn, env["WIN_LAB_ADMIN_PASSWORD"]); err != nil {
		t.Fatalf("admin bind: %v", err)
	}
	l := &searchLab{adm: adm, stamp: time.Now().UTC().Format("150405")}
	l.ident = &connectorv1.DirectoryIdentity{Identity: &connectorv1.DirectoryIdentity_AdForest{AdForest: &connectorv1.AdForestIdentity{ForestRootNcGuid: l.guid(t, dom)}}}
	src, err := read.NewADSource(sess, write.NewADProvider(sess, nil, l.ident, &memPins{}))
	if err != nil {
		t.Fatal(err)
	}
	l.client = start(t, src)

	ou := "OU=t1787-" + l.stamp + "," + dom
	l.delTree(ou)
	l.add(t, ou, map[string][]string{"objectClass": {"organizationalUnit"}, "description": {"T-1787 sync capture; removed by the test"}})
	t.Cleanup(func() { l.delTree(ou) })
	mk := func(name, expires string) string {
		a := map[string][]string{"objectClass": {"user"}, "sAMAccountName": {name + l.stamp}}
		if expires != "" {
			a["accountExpires"] = []string{expires}
		}
		l.add(t, "CN="+name+l.stamp+","+ou, a)
		return name + l.stamp
	}
	// 159335808000000000 ticks = a far-future FILETIME (year 2105); the never-logged-on user has no logon at all on this fresh account.
	cases := []struct{ file, cn, root string }{
		{"user-expires-zero", mk("exp0-", "0"), ou},
		{"user-expires-max", mk("expmax-", "9223372036854775807"), ou},
		{"user-expires-future", mk("expfut-", "159335808000000000"), ou},
		{"user-never-logged-on", mk("nologon-", ""), ou},
		// Administrator has logged on to dc1: a real lastLogonTimestamp, not one we wrote (it is system-only).
		{"user-lastlogon-present", "Administrator", "CN=Users," + dom},
	}
	m, err := dirsync.NewMapper(dirsync.Config{NC: inventory.GUID(guidText(t, l.guid(t, dom)))})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			got, _, err := rpc(t, l.client, l.request(l.guid(t, c.root), connectorv1.SearchDepth_SEARCH_DEPTH_ONE_LEVEL, "user", m.Attributes()...))
			if err != nil {
				t.Fatalf("ScopedSearch: %v", err)
			}
			var hit *connectorv1.DirectoryEntry
			for _, e := range got {
				if strings.HasPrefix(strings.ToLower(e.GetDn().GetDisplayDn()), "cn="+strings.ToLower(c.cn)+",") {
					hit = e
				}
			}
			if hit == nil {
				t.Fatalf("no entry for %s", c.cn)
			}
			if _, err := m.Map(hit); err != nil {
				t.Fatalf("Map: %v", err)
			}
			if dir := os.Getenv("SYNC_CAPTURE_DIR"); dir != "" {
				b, err := protojson.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(hit)
				if err != nil || os.MkdirAll(dir, 0o755) != nil || os.WriteFile(filepath.Join(dir, c.file+".json"), append(b, '\n'), 0o644) != nil {
					t.Fatalf("capture: %v", err)
				}
			}
		})
	}
	// The domain head is the NC the golden test maps against.
	if dir := os.Getenv("SYNC_CAPTURE_DIR"); dir != "" {
		got, _, err := rpc(t, l.client, l.request(l.guid(t, dom), connectorv1.SearchDepth_SEARCH_DEPTH_SUBTREE, "domainDNS", m.Attributes()...))
		if err != nil || len(got) != 1 {
			t.Fatalf("domain head: %v (%d)", err, len(got))
		}
		for _, e := range got {
			b, _ := protojson.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(e)
			if err := os.WriteFile(filepath.Join(dir, "domain.json"), append(b, '\n'), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
}

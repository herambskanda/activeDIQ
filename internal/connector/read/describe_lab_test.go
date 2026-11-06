//go:build lab

package read_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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

// T-1258 AC1 on Samba: Describe's naming contexts and page-size limit equal a direct LDAP read of the
// partitions (crossRef objects, the heads' objectGUIDs, lDAPAdminLimits). The Windows-only part (a
// child domain's crossRef, an RODC, a changed MaxPageSize policy) is a Windows-lab ticket.
func TestLabDescribeEqualsDirectPartitionRead(t *testing.T) {
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
	base := func(dn, filter string, scope int, attrs ...string) *ldap.SearchResult {
		t.Helper()
		r, err := admin.Search(ldap.NewSearchRequest(dn, scope, ldap.NeverDerefAliases, 0, 0, false, filter, attrs, nil))
		if err != nil {
			t.Fatalf("direct read of %q: %v", dn, err)
		}
		return r
	}
	guidOf := func(dn string) *connectorv1.Guid {
		r := base(dn, "(objectClass=*)", ldap.ScopeBaseObject, "objectGUID")
		if len(r.Entries) != 1 {
			t.Fatalf("%s: %d entries", dn, len(r.Entries))
		}
		g, err := guid.FromBytes(r.Entries[0].GetRawAttributeValue("objectGUID"))
		if err != nil {
			t.Fatal(err)
		}
		return write.GUIDToWire(g)
	}

	ident := &connectorv1.DirectoryIdentity{Identity: &connectorv1.DirectoryIdentity_AdForest{AdForest: &connectorv1.AdForestIdentity{
		ForestRootNcGuid: guidOf(labDom)}}}
	prov := write.NewADProvider(sess, nil, ident, &memPins{})
	src, err := read.NewADSource(sess, prov)
	if err != nil {
		t.Fatal(err)
	}
	h, err := read.New(src)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := h.Describe(ctx, &connectorv1.DescribeRequest{Connection: &connectorv1.ConnectionRef{ConnectionId: "c1", DirectoryIdentity: ident}})
	if err != nil {
		t.Fatal(err)
	}

	// Expected, by an independent route: every enabled crossRef's nCName, its head's objectGUID read
	// by the admin, and the kind from the DN (the lab has one domain, one configuration, one schema).
	cfg := "CN=Configuration," + labDom
	want := map[string]connectorv1.NamingContextKind{} // wire GUID -> kind
	for _, e := range base("CN=Partitions,"+cfg, "(objectClass=crossRef)", ldap.ScopeSingleLevel, "nCName", "enabled").Entries {
		if strings.EqualFold(e.GetAttributeValue("enabled"), "FALSE") {
			continue
		}
		nc := e.GetAttributeValue("nCName")
		k := connectorv1.NamingContextKind_NAMING_CONTEXT_KIND_APPLICATION
		switch {
		case strings.EqualFold(nc, labDom):
			k = connectorv1.NamingContextKind_NAMING_CONTEXT_KIND_DOMAIN
		case strings.EqualFold(nc, cfg):
			k = connectorv1.NamingContextKind_NAMING_CONTEXT_KIND_CONFIGURATION
		case strings.EqualFold(nc, "CN=Schema,"+cfg):
			k = connectorv1.NamingContextKind_NAMING_CONTEXT_KIND_SCHEMA
		}
		want[string(guidOf(nc).GetValue())] = k
	}
	kinds := map[connectorv1.NamingContextKind]int{}
	for _, k := range want {
		kinds[k]++
	}
	for _, k := range []connectorv1.NamingContextKind{connectorv1.NamingContextKind_NAMING_CONTEXT_KIND_DOMAIN,
		connectorv1.NamingContextKind_NAMING_CONTEXT_KIND_CONFIGURATION, connectorv1.NamingContextKind_NAMING_CONTEXT_KIND_SCHEMA} {
		if kinds[k] != 1 {
			t.Fatalf("direct read found %d %v naming contexts, want 1 (kinds %v)", kinds[k], k, kinds)
		}
	}
	if len(resp.GetNamingContexts()) != len(want) {
		t.Fatalf("Describe lists %d naming contexts, the directory has %d", len(resp.GetNamingContexts()), len(want))
	}
	for _, nc := range resp.GetNamingContexts() {
		k, ok := want[string(nc.GetNcGuid().GetValue())]
		if !ok || k != nc.GetKind() {
			t.Errorf("naming context %q: kind %v, directory says %v (listed in directory: %v)", nc.GetHead().GetDisplayDn(), nc.GetKind(), k, ok)
		}
		if string(nc.GetHead().GetGuid().GetValue()) != string(nc.GetNcGuid().GetValue()) {
			t.Errorf("%q: head GUID differs from nc_guid", nc.GetHead().GetDisplayDn())
		}
		if nc.GetKind() == connectorv1.NamingContextKind_NAMING_CONTEXT_KIND_DOMAIN {
			if nc.GetDomainSid() == nil || nc.GetDnsName() == "" || nc.GetNetbiosName() == "" || nc.FunctionalLevel == nil {
				t.Errorf("domain nc is missing its facts: %v", nc)
			}
			r := base(labDom, "(objectClass=*)", ldap.ScopeBaseObject, "objectSid", "msDS-Behavior-Version")
			if got := string(nc.GetDomainSid().GetValue()); got != string(r.Entries[0].GetRawAttributeValue("objectSid")) {
				t.Errorf("domain SID differs from the head's objectSid")
			}
			if lvl, _ := strconv.Atoi(r.Entries[0].GetAttributeValue("msDS-Behavior-Version")); uint32(lvl) != nc.GetFunctionalLevel() {
				t.Errorf("functional level %d, head says %d", nc.GetFunctionalLevel(), lvl)
			}
		}
	}

	// Limits: the DC's lDAPAdminLimits, capped at the session's page ceiling, never zero.
	wantPage := uint32(1000)
	for _, pol := range []string{"CN=Default Query Policy,CN=Query-Policies,CN=Directory Service,CN=Windows NT,CN=Services," + cfg} {
		r, err := admin.Search(ldap.NewSearchRequest(pol, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"lDAPAdminLimits"}, nil))
		if err != nil {
			t.Logf("no Default Query Policy on this DC (%v): the documented default applies", err)
			continue
		}
		t.Logf("Default Query Policy lDAPAdminLimits = %v", r.Entries[0].GetAttributeValues("lDAPAdminLimits"))
		for _, v := range r.Entries[0].GetAttributeValues("lDAPAdminLimits") {
			if k, val, ok := strings.Cut(v, "="); ok && strings.EqualFold(k, "MaxPageSize") {
				n, _ := strconv.Atoi(val)
				wantPage = uint32(n)
			}
		}
	}
	wantPage = min(wantPage, ad.MaxPageSize)
	if got := resp.GetLimits().GetMaxPageSize(); got != wantPage || got == 0 {
		t.Errorf("max_page_size = %d, direct read says %d", got, wantPage)
	}
	if resp.GetLimits().GetMaxValueRange() == 0 {
		t.Error("max_value_range is zero")
	}
	t.Logf("lab Describe: %d naming contexts %v, limits %v", len(resp.GetNamingContexts()), kinds, resp.GetLimits())
}

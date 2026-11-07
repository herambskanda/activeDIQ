//go:build lab

package server

import (
	"context"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/connector/labadmin"
	"github.com/skenzeriq/activediq/internal/connector/write"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
	"github.com/skenzeriq/activediq/internal/testlab"
)

// T-1258 AC1: the lab connector's Describe lists the domain NC (DOMAIN, with its objectGUID), the
// configuration and schema NCs with their kinds and limits.max_page_size; the count and the GUIDs
// equal a direct LDAP read of the partitions (an administrator's own connection, not the connector's).
func TestLabDescribeNamingContextsEqualDirectRead(t *testing.T) {
	le := testlab.Load(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	specs, err := labSpecs(envOf(map[string]string{"LAB_LDAPS_PORT": le.Port, "LAB_SVC_PASSWORD": le.Values["LAB_SVC_PASSWORD"], "LAB_CA": le.CAPath}))
	if err != nil || len(specs) != 1 {
		t.Fatalf("lab specs = %d, %v", len(specs), err)
	}
	lab, closeLab, err := openLabServer(ctx, specs[0])
	if err != nil {
		t.Fatalf("open lab connector: %v", err)
	}
	t.Cleanup(closeLab)

	// The identity the connector serves is the forest root's GUID; Describe must be asked with it.
	adm := labadmin.Dial(t, le.Port, le.Pool, "Administrator@lab.activediq.test", le.Values["LAB_ADMIN_PASSWORD"])
	parts := adm.ReadPartitions()
	wireOf := func(dnStr string) string {
		t.Helper()
		return string(write.GUIDToWire(mustGUID(t, adm.ObjectGUID(dnStr))).GetValue())
	}
	domainDN, cfgDN, schemaDN := parts.DomainDN, parts.ConfigDN, parts.SchemaDN
	ident := &connectorv1.DirectoryIdentity{Identity: &connectorv1.DirectoryIdentity_AdForest{AdForest: &connectorv1.AdForestIdentity{
		ForestRootNcGuid: write.GUIDToWire(mustGUID(t, parts.RootDomainGUID))}}}

	resp, err := lab.Describe(ctx, &connectorv1.DescribeRequest{Connection: &connectorv1.ConnectionRef{ConnectionId: "lab", DirectoryIdentity: ident}})
	if err != nil {
		t.Fatalf("Describe: %v", err)
	}

	// Direct read of the partitions: every enabled crossRef in CN=Partitions is one naming context.
	xrefs := parts.Heads
	if len(resp.GetNamingContexts()) != len(xrefs) {
		t.Fatalf("Describe lists %d naming contexts, the directory has %d crossRefs", len(resp.GetNamingContexts()), len(xrefs))
	}
	got := map[string]connectorv1.NamingContextKind{}
	for _, nc := range resp.GetNamingContexts() {
		got[string(nc.GetNcGuid().GetValue())] = nc.GetKind()
		if string(nc.GetHead().GetGuid().GetValue()) != string(nc.GetNcGuid().GetValue()) {
			t.Errorf("head GUID differs from nc_guid for %s", nc.GetHead().GetDisplayDn())
		}
	}
	if len(got) != len(xrefs) {
		t.Errorf("duplicate nc_guid in the answer: %d distinct of %d", len(got), len(xrefs))
	}
	for _, x := range xrefs {
		// nCName is the head's DN; its objectGUID is read from the head itself.
		if k, ok := got[wireOf(x)]; !ok || k == connectorv1.NamingContextKind_NAMING_CONTEXT_KIND_UNSPECIFIED {
			t.Errorf("crossRef %s: head GUID missing from Describe or kind unset", x)
		}
	}
	for name, c := range map[string]struct {
		dn   string
		kind connectorv1.NamingContextKind
	}{
		"domain":        {domainDN, connectorv1.NamingContextKind_NAMING_CONTEXT_KIND_DOMAIN},
		"configuration": {cfgDN, connectorv1.NamingContextKind_NAMING_CONTEXT_KIND_CONFIGURATION},
		"schema":        {schemaDN, connectorv1.NamingContextKind_NAMING_CONTEXT_KIND_SCHEMA},
	} {
		if k, ok := got[wireOf(c.dn)]; !ok || k != c.kind {
			t.Errorf("%s NC %s: kind = %v (listed %v), want %v", name, c.dn, k, ok, c.kind)
		}
	}
	for _, nc := range resp.GetNamingContexts() {
		if nc.GetKind() == connectorv1.NamingContextKind_NAMING_CONTEXT_KIND_DOMAIN && len(nc.GetDomainSid().GetValue()) == 0 {
			t.Errorf("domain NC %s has no SID", nc.GetHead().GetDisplayDn())
		}
	}

	// limits.max_page_size: positive and never above the page the session itself asks for.
	if n := resp.GetLimits().GetMaxPageSize(); n == 0 || n > 1000 {
		t.Errorf("limits.max_page_size = %d", n)
	}
	if resp.GetLimits().GetMaxValueRange() == 0 {
		t.Error("limits.max_value_range = 0")
	}
	t.Logf("Describe: %d naming contexts, max_page_size %d, max_value_range %d", len(resp.GetNamingContexts()), resp.GetLimits().GetMaxPageSize(), resp.GetLimits().GetMaxValueRange())
}

func mustGUID(t *testing.T, b []byte) guid.GUID {
	t.Helper()
	g, err := guid.FromBytes(b)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

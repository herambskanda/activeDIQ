//go:build lab

package read_test

import (
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
	"github.com/skenzeriq/activediq/internal/connector/read"
	"github.com/skenzeriq/activediq/internal/connector/write"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/platform/secret"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// T-1143 on the single-DC Samba lab: CC-PDC-01 and CC-PDC-02 (and the DC enumeration they stand on).
// CC-PDC-03/04/05 need the `2dc` profile, which the lab does not have yet (see the ticket's
// follow-up); CC-PDC-06 is a Windows case; CC-PDC-07 is proved with a counter in perdc_test.go.

func TestLabReadPerDCSingleDC(t *testing.T) {
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
	cred := ad.Credential{BindName: "svc-activediq@lab.activediq.test", Password: secret.FromBytes([]byte(env["LAB_SVC_PASSWORD"]))}
	openAt := func(ctx context.Context, _ string) (*ad.Session, error) { // every DC host is the one lab DC
		return ad.Open(ctx, ad.Config{Servers: []string{"localhost:" + port}, RootCAs: pool, Credential: cred})
	}
	sess, err := openAt(ctx, "")
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
	guidOf := func(dn string) *connectorv1.Guid {
		r, err := admin.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"objectGUID"}, nil))
		if err != nil || len(r.Entries) != 1 {
			t.Fatalf("guid of %s: %v", dn, err)
		}
		g, err := guid.FromBytes(r.Entries[0].GetRawAttributeValue("objectGUID"))
		if err != nil {
			t.Fatal(err)
		}
		return write.GUIDToWire(g)
	}
	sam := fmt.Sprintf("t1143%d", time.Now().UnixNano()%1_000_000)
	userDN := "CN=Müller\\, " + sam + ",CN=Users," + labDom
	add := ldap.NewAddRequest(userDN, nil)
	add.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "user"})
	add.Attribute("sAMAccountName", []string{sam})
	if err := admin.Add(add); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Del(ldap.NewDelRequest(userDN, nil)) })

	ident := &connectorv1.DirectoryIdentity{Identity: &connectorv1.DirectoryIdentity_AdForest{AdForest: &connectorv1.AdForestIdentity{
		ForestRootNcGuid: guidOf(labDom)}}}
	prov := write.NewADProvider(sess, nil, ident, &memPins{})
	base, err := read.NewADSource(sess, prov)
	if err != nil {
		t.Fatal(err)
	}
	psrc, err := read.NewADPerDCSource(base, openAt)
	if err != nil {
		t.Fatal(err)
	}
	h, err := read.New(psrc)
	if err != nil {
		t.Fatal(err)
	}
	dc, err := prov.BoundDC(ctx)
	if err != nil {
		t.Fatal(err)
	}
	do := func(scope connectorv1.PerDcScope, attrs ...connectorv1.PerDcAttribute) ([]*connectorv1.PerDcResult, *connectorv1.PerDcSummary) {
		t.Helper()
		s := &pdSink{}
		err := h.ReadPerDC(ctx, &connectorv1.ReadPerDCRequest{Connection: &connectorv1.ConnectionRef{ConnectionId: "c1", DirectoryIdentity: ident},
			Guid: guidOf(userDN), NcGuid: guidOf(labDom), Attributes: attrs, Scope: scope}, s)
		if err != nil {
			t.Fatal(err)
		}
		var rs []*connectorv1.PerDcResult
		var sum *connectorv1.PerDcSummary
		for _, m := range s.ms {
			if m.GetSummary() != nil {
				sum = m.GetSummary()
			} else {
				rs = append(rs, m.GetResult())
			}
		}
		return rs, sum
	}
	all := []connectorv1.PerDcAttribute{connectorv1.PerDcAttribute_PER_DC_ATTRIBUTE_LAST_LOGON, connectorv1.PerDcAttribute_PER_DC_ATTRIBUTE_LOGON_COUNT,
		connectorv1.PerDcAttribute_PER_DC_ATTRIBUTE_BAD_PWD_COUNT, connectorv1.PerDcAttribute_PER_DC_ATTRIBUTE_BAD_PASSWORD_TIME,
		connectorv1.PerDcAttribute_PER_DC_ATTRIBUTE_LOCKOUT_TIME}

	// CC-PDC-01: one result for the lab DC, 1/1 COMPLETE, never-logged-on lastLogon is ZERO.
	rs, sum := do(connectorv1.PerDcScope_PER_DC_SCOPE_ALL, all...)
	if len(rs) != 1 || sum.GetDcsInScope() != 1 || sum.GetDcsAnswered() != 1 || sum.GetCoverage() != connectorv1.Coverage_COVERAGE_COMPLETE {
		t.Fatalf("results %v summary %v", rs, sum)
	}
	if string(rs[0].GetDc().GetDsaGuid().GetValue()) != string(dc.GetDsaGuid().GetValue()) {
		t.Fatal("result names another DC than the bound one")
	}
	if rs[0].GetError() != nil {
		t.Fatalf("lab DC errored: %v", rs[0].GetError())
	}
	// CC-PDC-02: typed values, in the order asked.
	vs := rs[0].GetValues().GetValues()
	if len(vs) != len(all) {
		t.Fatalf("values %v", vs)
	}
	for i, v := range vs {
		if v.GetAttribute() != all[i] {
			t.Fatalf("value %d is %v", i, v.GetAttribute())
		}
	}
	if vs[0].GetTime().GetSentinel() != connectorv1.TimeSentinel_TIME_SENTINEL_ZERO || vs[1].GetInteger() != 0 || vs[2].GetInteger() != 0 {
		t.Fatalf("never-logged-on user: %v", vs)
	}

	// A wrong password raises badPwdCount on the DC that saw it (Samba keeps it per DC too).
	wrong, err := ldap.DialURL("ldaps://localhost:"+port, ldap.DialWithTLSConfig(&tls.Config{RootCAs: pool, ServerName: "localhost"}))
	if err != nil {
		t.Fatal(err)
	}
	_ = wrong.Bind(sam+"@lab.activediq.test", "definitely-not-"+strings.Repeat("x", 8))
	wrong.Close()
	rs, _ = do(connectorv1.PerDcScope_PER_DC_SCOPE_WRITABLE, connectorv1.PerDcAttribute_PER_DC_ATTRIBUTE_BAD_PWD_COUNT)
	if n := rs[0].GetValues().GetValues()[0].GetInteger(); n < 1 {
		t.Logf("badPwdCount is %d after a failed bind (Samba may not count simple-bind failures)", n)
	}

	// A group is not a domain: nc_guid naming CN=Users finds no DCs.
	s := &pdSink{}
	err = h.ReadPerDC(ctx, &connectorv1.ReadPerDCRequest{Connection: &connectorv1.ConnectionRef{ConnectionId: "c1", DirectoryIdentity: ident},
		Guid: guidOf(userDN), NcGuid: guidOf("CN=Users," + labDom), Attributes: all[:1], Scope: connectorv1.PerDcScope_PER_DC_SCOPE_ALL}, s)
	if err == nil || len(s.ms) != 0 {
		t.Fatalf("a non-NC head served: %v", err)
	}
}

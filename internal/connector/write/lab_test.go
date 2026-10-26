//go:build lab

package write

import (
	"bufio"
	"bytes"
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
	prov := NewADProvider(sess, nil, adIdentity(), &memPins{})
	dc, err := prov.BoundDC(ctx) // rule 5: the requests pin the DC the session is bound to
	if err != nil {
		t.Fatal(err)
	}
	h, err := New(prov, book, WithRecorder(&memRecorder{}))
	if err != nil {
		t.Fatal(err)
	}
	plan := func(c *connectorv1.Tier0Context) *connectorv1.PlanRequest {
		r := planReq(id, c)
		r.Dc = &connectorv1.DcSelection{PinnedDsaGuid: dc.GetDsaGuid()}
		return r
	}
	apply := func(c *connectorv1.Tier0Context) *connectorv1.ApplyRequest {
		r := applyReq(id, c)
		r.Precondition.Dc = dc
		return r
	}
	fresh := func() *connectorv1.Tier0Context {
		return &connectorv1.Tier0Context{Tier0Revision: 1, Statements: []*connectorv1.CorrelationStatement{noLink(id, now)}}
	}
	// Before: an ordinary user reaches the kind check.
	_, err = h.Plan(ctx, plan(fresh()))
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
	_, err = h.Plan(ctx, plan(fresh()))
	d := wantTier0(t, err, connectorv1.Tier0RefusalStage_TIER0_REFUSAL_STAGE_LIVE_REREAD)
	if len(d.GetBasis()) == 0 || d.GetBasis()[0] != tier0.C2 {
		t.Fatalf("basis %v", d.GetBasis())
	}
	_, err = h.Apply(ctx, apply(fresh()))
	wantTier0(t, err, connectorv1.Tier0RefusalStage_TIER0_REFUSAL_STAGE_LIVE_REREAD)
}

// T-0401 AC1: Session.DCIdentity against a real DC. The DSA GUID is compared with the NTDS Settings
// objectGUID read independently over a plain go-ldap connection, and the wire bytes the client pins
// are compared with the RFC 4122 order derived by hand from the mixed-endian directory bytes.
// Samba only: the Windows DC run is the Windows-lab ticket (see the advance note).
func TestLabSessionDCIdentityMatchesNTDSSettings(t *testing.T) {
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

	raw, err := ldap.DialURL("ldaps://localhost:"+port, ldap.DialWithTLSConfig(&tls.Config{RootCAs: pool, ServerName: "localhost"}))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if err := raw.Bind("Administrator@lab.activediq.test", env["LAB_ADMIN_PASSWORD"]); err != nil {
		t.Fatal(err)
	}
	rd, err := raw.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"dsServiceName", "dnsHostName"}, nil))
	if err != nil || len(rd.Entries) != 1 {
		t.Fatalf("rootDSE: %v", err)
	}
	ntds := rd.Entries[0].GetAttributeValue("dsServiceName")
	ne, err := raw.Search(ldap.NewSearchRequest(ntds, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"objectGUID", "invocationId"}, nil))
	if err != nil || len(ne.Entries) != 1 {
		t.Fatalf("NTDS Settings: %v", err)
	}
	dsaRaw := ne.Entries[0].GetRawAttributeValue("objectGUID")
	invRaw := ne.Entries[0].GetRawAttributeValue("invocationId")
	if len(dsaRaw) != 16 || len(invRaw) != 16 {
		t.Fatalf("guid lengths %d %d", len(dsaRaw), len(invRaw))
	}

	id, err := sess.DCIdentity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Directory bytes are mixed-endian (first three fields little-endian); RFC 4122 text order is
	// the same bytes with those fields swapped.
	text := func(b []byte) string {
		return fmt.Sprintf("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
			b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
	}
	if got, want := id.DSAGUID.String(), text(dsaRaw); !strings.EqualFold(got, want) {
		t.Fatalf("DSAGUID %s, NTDS Settings objectGUID %s", got, want)
	}
	if got, want := id.InvocationID.String(), text(invRaw); !strings.EqualFold(got, want) {
		t.Fatalf("InvocationID %s, want %s", got, want)
	}
	if id.DSAGUID == id.InvocationID {
		t.Fatal("DSA GUID equals invocationId") // legitimate only after a restore; a fresh lab is never restored
	}
	wire := func(b []byte) []byte { // RFC 4122 order bytes
		return []byte{b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]}
	}
	bound, err := SessionDC{S: sess}.BoundDC(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bound.GetDsaGuid().GetValue(), wire(dsaRaw)) || !bytes.Equal(bound.GetInvocationId().GetValue(), wire(invRaw)) {
		t.Fatalf("wire bytes %x / %x, want %x / %x", bound.GetDsaGuid().GetValue(), bound.GetInvocationId().GetValue(), wire(dsaRaw), wire(invRaw))
	}
	if !strings.EqualFold(id.DNSHostName, rd.Entries[0].GetAttributeValue("dnsHostName")) || id.Site == "" {
		t.Fatalf("host %q site %q", id.DNSHostName, id.Site)
	}
	// The same identity is stable across calls on the one session.
	again, err := sess.DCIdentity(ctx)
	if err != nil || again != id {
		t.Fatalf("second read %+v %v", again, err)
	}
}

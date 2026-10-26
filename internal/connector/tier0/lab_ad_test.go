//go:build lab

package tier0

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/platform/secret"
	"github.com/skenzeriq/activediq/internal/testlab"
)

// Lab test (Samba AD): `make lab-up && go test -tags lab ./internal/connector/tier0 -run TestLabAD`.
// Samba proves the LDAP semantics only (paging, in-chain, primaryGroupID, wellKnownObjects, SD
// bytes). Windows-only facts (live DACL defaults, RODC corroboration, KDS keys) stay Windows-lab.

const labDom = "DC=lab,DC=activediq,DC=test"

func labEnvAD(t *testing.T) map[string]string {
	t.Helper()
	return testlab.Load(t).Values
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

// Spot checks on the seeded lab: protected groups, krbtgt, the Domain Controllers OU and the domain head.
func TestLabADSeededObjects(t *testing.T) {
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
	c := NewAD(SessionDirectory{S: sess})
	for _, x := range []struct {
		dn   string
		want Basis
	}{
		{"CN=Domain Admins,CN=Users," + labDom, C1},
		{labDom, C7},
		{"CN=Administrator,CN=Users," + labDom, C1},
		{"CN=krbtgt,CN=Users," + labDom, C4},
		{"OU=Domain Controllers," + labDom, C6},
	} {
		ref, err := dn.ParseObjectRef(x.dn)
		if err != nil {
			t.Fatal(err)
		}
		r, err := c.Classify(ctx, ref, ADInput{CorrelationKnown: true})
		if err != nil || !r.Tier0 || !has(r, x.want) {
			t.Errorf("%s: %+v %v", x.dn, r, err)
		}
	}
}

// T-0380 / TM-D27 rule 4: Authenticated Users (S-1-5-11) holding WP member on Domain Admins must fail
// the snapshot closed. The lab holds CN=S-1-5-11,CN=ForeignSecurityPrincipals; resolving the trustee to
// that FSP and marking only it used to let the snapshot succeed with nobody newly tier0.
func TestLabADBroadSIDWithFSPFailsClosed(t *testing.T) {
	e := testlab.Load(t)
	if out, err := exec.Command("docker", "exec", e.Container, "true").CombinedOutput(); err != nil {
		t.Fatalf("lab container %s not available (run `make lab-up`): %v %s", e.Container, err, out)
	}
	env := e.Values
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	sess, err := ad.Open(ctx, ad.Config{
		Servers: []string{"localhost:" + e.Port}, RootCAs: e.Pool, PageSize: 500,
		Credential: ad.Credential{BindName: "svc-activediq@lab.activediq.test", Password: secret.FromBytes([]byte(env["LAB_SVC_PASSWORD"]))},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	// Precondition: the lab holds the default FSP. Samba cannot resolve it by <SID=S-1-5-11> (the SID
	// base search reports "Duplicate base-DN matches" across partitions, mapped to not-found), so on
	// Samba the classifier already fails closed by accident; the FSP-resolves-to-placeholder path that
	// real AD takes is covered by the unit fake (default FSPs) and needs a Windows-lab test.
	fspDN, err := dn.ParseObjectRef("CN=S-1-5-11,CN=ForeignSecurityPrincipals," + labDom)
	if err != nil {
		t.Fatal(err)
	}
	fsp, err := sess.Read(ctx, fspDN, []string{"objectClass"}, ad.ReadOptions{})
	if err != nil || !hasClass(fsp, "foreignSecurityPrincipal") {
		t.Fatalf("lab has no FSP for S-1-5-11: %v %v", fsp, err)
	}

	daDN := "CN=Domain Admins,CN=Users," + labDom
	sddl := "(OA;;WP;bf9679c0-0de6-11d0-b285-00c04fb9698d;;AU)" // WP member for Authenticated Users
	if out, err := exec.Command("docker", "exec", e.Container, "samba-tool", "dsacl", "set", "--objectdn="+daDN, "--sddl="+sddl).CombinedOutput(); err != nil {
		t.Fatalf("dsacl set: %v %s", err, out)
	}
	t.Cleanup(func() {
		_, _ = exec.Command("docker", "exec", e.Container, "samba-tool", "dsacl", "delete", "--objectdn="+daDN, "--sddl="+sddl).CombinedOutput()
	})

	target, err := dn.ParseObjectRef("CN=Administrator,CN=Users," + labDom)
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewAD(SessionDirectory{S: sess}).Classify(ctx, target, ADInput{CorrelationKnown: true})
	if err == nil || !strings.Contains(err.Error(), "S-1-5-11") {
		t.Fatalf("Authenticated Users WP member on Domain Admins did not fail closed: %+v %v", r, err)
	}
}

// T-0382: BUILTIN\Pre-Windows 2000 Compatible Access (S-1-5-32-554) has Authenticated Users as a
// member, so a rule-2 right granted to it is held by every authenticated bind, though tokenGroups never
// lists the group. The classifier must not succeed.
func TestLabADNestedBroadFSPInTrusteeFailsClosed(t *testing.T) {
	e := testlab.Load(t)
	if out, err := exec.Command("docker", "exec", e.Container, "true").CombinedOutput(); err != nil {
		t.Fatalf("lab container %s not available (run `make lab-up`): %v %s", e.Container, err, out)
	}
	env := e.Values
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	sess, err := ad.Open(ctx, ad.Config{
		Servers: []string{"localhost:" + e.Port}, RootCAs: e.Pool, PageSize: 500,
		Credential: ad.Credential{BindName: "svc-activediq@lab.activediq.test", Password: secret.FromBytes([]byte(env["LAB_SVC_PASSWORD"]))},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	daDN := "CN=Domain Admins,CN=Users," + labDom
	sddl := "(OA;;WP;bf9679c0-0de6-11d0-b285-00c04fb9698d;;RU)" // WP member for BUILTIN\Pre-Windows 2000 Compatible Access (S-1-5-32-554; SDDL alias RU)
	if out, err := exec.Command("docker", "exec", e.Container, "samba-tool", "dsacl", "set", "--objectdn="+daDN, "--sddl="+sddl).CombinedOutput(); err != nil {
		t.Fatalf("dsacl set: %v %s", err, out)
	}
	t.Cleanup(func() {
		_, _ = exec.Command("docker", "exec", e.Container, "samba-tool", "dsacl", "delete", "--objectdn="+daDN, "--sddl="+sddl).CombinedOutput()
	})
	target, err := dn.ParseObjectRef("CN=Administrator,CN=Users," + labDom)
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewAD(SessionDirectory{S: sess}).Classify(ctx, target, ADInput{CorrelationKnown: true})
	if err == nil || !strings.Contains(err.Error(), "S-1-5-11") {
		t.Fatalf("Pre-Windows 2000 Compatible Access WP member on Domain Admins did not fail closed naming S-1-5-11: %+v %v", r, err)
	}
	t.Logf("failed closed: %v", err)
}

// T-0397: a member of a tier0 group that the connector cannot read (deny-read ACE) must not drop
// out of the walk: the snapshot fails closed naming the group that lists it.
func TestLabADUnreadableNestedMemberFailsClosed(t *testing.T) {
	e := testlab.Load(t)
	dock := func(args ...string) string {
		t.Helper()
		out, err := exec.Command("docker", append([]string{"exec", e.Container}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %v %s", args, err, out)
		}
		return string(out)
	}
	env := e.Values
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	sess, err := ad.Open(ctx, ad.Config{
		Servers: []string{"localhost:" + e.Port}, RootCAs: e.Pool, PageSize: 500,
		Credential: ad.Credential{BindName: "svc-activediq@lab.activediq.test", Password: secret.FromBytes([]byte(env["LAB_SVC_PASSWORD"]))},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	const grp = "t0397-hidden"
	grpDN := "CN=" + grp + ",CN=Users," + labDom
	dock("samba-tool", "group", "add", grp)
	t.Cleanup(func() {
		_, _ = exec.Command("docker", "exec", e.Container, "samba-tool", "group", "delete", grp).CombinedOutput()
	})
	dock("samba-tool", "group", "addmembers", "Domain Admins", grp)
	t.Cleanup(func() {
		_, _ = exec.Command("docker", "exec", e.Container, "samba-tool", "group", "removemembers", "Domain Admins", grp).CombinedOutput()
	})
	out := dock("samba-tool", "user", "show", "svc-activediq", "--attributes=objectSid")
	var svcSID string
	for _, f := range strings.Fields(out) {
		if strings.HasPrefix(f, "S-1-5-21-") {
			svcSID = f
		}
	}
	if svcSID == "" {
		t.Fatalf("svc SID not found in %q", out)
	}
	sddl := "(D;;LCRPLO;;;" + svcSID + ")"
	dock("samba-tool", "dsacl", "set", "--objectdn="+grpDN, "--sddl="+sddl)

	target, err := dn.ParseObjectRef("CN=Administrator,CN=Users," + labDom)
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewAD(SessionDirectory{S: sess}).Classify(ctx, target, ADInput{CorrelationKnown: true})
	// Samba answers a deny-read Read with the entry minus its identity attributes (objectGUID), a
	// Windows DC with no-such-object (the unit test pins that path); both must fail the snapshot.
	if err == nil || !r.Unknown {
		t.Fatalf("hidden nested group did not fail the snapshot closed: %+v %v", r, err)
	}
	t.Logf("failed closed: %v", err)
}

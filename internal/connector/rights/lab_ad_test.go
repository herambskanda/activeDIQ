//go:build lab

package rights

import (
	"context"
	"crypto/x509"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	adguid "github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/platform/secret"
	v1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// Lab tests (Samba AD): `make lab-up && go test -tags lab ./internal/connector/rights -run TestLabAD`.
// Fixtures are made with samba-tool inside the lab DC container (the lab's admin tool); the check
// itself runs as a freshly made non-admin user over LDAPS. Samba proves LDAP semantics and its own
// ACL module only: the SDProp path (CC-VER-06), exact Windows ACE semantics, a second domain and
// tokenGroupsGlobalAndUniversal readability are Windows-lab cases.

const (
	labDom       = "DC=lab,DC=activediq,DC=test"
	labUPNSuffix = "lab.activediq.test"
	labPassword  = "Lab-Pa55w0rd!x9"
	attrMember   = "bf9679c0-0de6-11d0-a285-00aa003049e2"
	classUser    = "bf967aba-0de6-11d0-a285-00aa003049e2"
)

type lab struct {
	t    *testing.T
	ctr  string
	pool *x509.CertPool
	port string
}

func newLab(t *testing.T) *lab {
	t.Helper()
	ctr := os.Getenv("LAB_CONTAINER")
	if ctr == "" {
		ctr = "activediq-lab-dc-1"
	}
	if out, err := exec.Command("docker", "exec", ctr, "true").CombinedOutput(); err != nil {
		t.Skipf("lab container not available: %v %s", err, out)
	}
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	if out, err := exec.Command("docker", "cp", ctr+":/var/lib/samba/lab-tls/ca.pem", ca).CombinedOutput(); err != nil {
		t.Fatalf("copy CA: %v %s", err, out)
	}
	pem, err := os.ReadFile(ca)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	port := os.Getenv("LAB_LDAPS_PORT")
	if port == "" {
		port = "636"
	}
	return &lab{t: t, ctr: ctr, pool: pool, port: port}
}

func (l *lab) tool(args ...string) string {
	l.t.Helper()
	out, err := exec.Command("docker", append([]string{"exec", l.ctr}, args...)...).CombinedOutput()
	if err != nil {
		l.t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func (l *lab) try(args ...string) {
	_, _ = exec.Command("docker", append([]string{"exec", l.ctr}, args...)...).CombinedOutput()
}

var labSeq = time.Now().UnixNano() % 1_000_000

func (l *lab) user() (name, userDN, sidText string) {
	l.t.Helper()
	labSeq++
	name = fmt.Sprintf("t96u%d", labSeq)
	l.tool("samba-tool", "user", "create", name, labPassword)
	l.t.Cleanup(func() { l.try("samba-tool", "user", "delete", name) })
	out := l.tool("samba-tool", "user", "show", name, "--attributes=objectSid,distinguishedName")
	for _, ln := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(ln, "objectSid: "); ok {
			sidText = strings.TrimSpace(v)
		}
		if v, ok := strings.CutPrefix(ln, "dn: "); ok {
			userDN = strings.TrimSpace(v)
		}
	}
	if sidText == "" || userDN == "" {
		l.t.Fatalf("user fixture: %q", out)
	}
	return
}

func (l *lab) ou() (ouDN string) {
	labSeq++
	name := fmt.Sprintf("t96ou%d", labSeq)
	ouDN = "OU=" + name + "," + labDom
	l.tool("samba-tool", "ou", "create", ouDN)
	l.t.Cleanup(func() { l.try("samba-tool", "ou", "delete", ouDN) })
	return
}

// ace adds an SDDL ACE to an object and removes it at cleanup.
func (l *lab) ace(objectDN, sddl string) {
	l.t.Helper()
	l.tool("samba-tool", "dsacl", "set", "--objectdn="+objectDN, "--sddl="+sddl)
	l.t.Cleanup(func() { l.try("samba-tool", "dsacl", "delete", "--objectdn="+objectDN, "--sddl="+sddl) })
}

func (l *lab) open(ctx context.Context, name string) *ad.Session {
	l.t.Helper()
	s, err := ad.Open(ctx, ad.Config{Servers: []string{"localhost:" + l.port}, RootCAs: l.pool, PageSize: 500,
		Credential: ad.Credential{BindName: name + "@" + labUPNSuffix, Password: secret.FromBytes([]byte(labPassword))}})
	if err != nil {
		l.t.Fatal(err)
	}
	l.t.Cleanup(func() { s.Close() })
	return s
}

func guidOf(t *testing.T, ctx context.Context, s *ad.Session, dnText string) adguid.GUID {
	t.Helper()
	ref, err := dn.ParseObjectRef(dnText)
	if err != nil {
		t.Fatal(err)
	}
	e, err := s.Read(ctx, ref, []string{"objectGUID"}, ad.ReadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	g, err := e.GUID()
	if err != nil {
		t.Fatal(err)
	}
	return g
}

type labRun struct {
	res  *ADResult
	sess *ad.Session
}

func (l *lab) verify(ctx context.Context, name, userDN string, in ADInput) labRun {
	l.t.Helper()
	s := l.open(ctx, name)
	ref, err := dn.ParseObjectRef(userDN)
	if err != nil {
		l.t.Fatal(err)
	}
	in.Identity = ref
	res, err := VerifyAD(ctx, NewSessionDirectory(s), in)
	if err != nil {
		l.t.Fatal(err)
	}
	return labRun{res, s}
}

func (r labRun) find(code string) []Finding {
	var out []Finding
	for _, f := range r.res.Findings {
		if f.Code == code {
			out = append(out, f)
		}
	}
	return out
}

func (r labRun) refused(t *testing.T) {
	t.Helper()
	if r.res.Verdict != v1.VerificationVerdict_VERIFICATION_VERDICT_REFUSED {
		t.Fatalf("verdict %v, want REFUSED; findings %s", r.res.Verdict, dump(r.res))
	}
	if r.res.WriteGateOpenable {
		t.Fatal("refused run opens the gate")
	}
}

func dump(r *ADResult) string {
	var b strings.Builder
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "\n  %v %v %s q=%s", f.Check, f.Severity, f.Code, f.Qualifier)
	}
	return b.String()
}

func labCtx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 280*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// AC2 and AC3: a correctly delegated identity passes; an extra right and a missing one are both listed.
func TestLabADDelegatedIdentity(t *testing.T) {
	l := newLab(t)
	ctx := labCtx(t)
	name, userDN, sidText := l.user()
	ouDN := l.ou()
	l.ace(ouDN, fmt.Sprintf("(OA;CI;CCDC;%s;;%s)(OA;CI;CR;00299570-246d-11d0-a768-00aa006e0529;%s;%s)", classUser, sidText, classUser, sidText))
	sess := l.open(ctx, name)
	in := ADInput{
		EnabledFamilies: []v1.RightsFamily{v1.RightsFamily_RIGHTS_FAMILY_AD_R3_USER_LIFECYCLE, v1.RightsFamily_RIGHTS_FAMILY_AD_R5_PASSWORD_RESET},
		ManagedDomains:  []adguid.GUID{guidOf(t, ctx, sess, labDom)},
		ManagedRoots:    []adguid.GUID{guidOf(t, ctx, sess, ouDN)},
	}
	r := l.verify(ctx, name, userDN, in)
	if r.res.Verdict != v1.VerificationVerdict_VERIFICATION_VERDICT_PASS || !r.res.WriteGateOpenable {
		t.Fatalf("delegated identity not passed: %v%s", r.res.Verdict, dump(r.res))
	}
	for _, f := range r.res.Findings {
		if f.Kind == v1.FindingKind_FINDING_KIND_EXCESSIVE_RIGHT || f.Kind == v1.FindingKind_FINDING_KIND_MISSING_RIGHT {
			t.Errorf("unexpected finding %s q=%s", f.Code, f.Qualifier)
		}
	}
	if len(r.res.Tier0Set) == 0 {
		t.Error("tier0 set not reported")
	}

	// AC3: one extra right (WRITE_DAC on the OU) and one missing (R6 groups enabled, never granted).
	l.ace(ouDN, fmt.Sprintf("(A;CI;WD;;;%s)", sidText))
	in.EnabledFamilies = append(in.EnabledFamilies, v1.RightsFamily_RIGHTS_FAMILY_AD_R6_GROUPS)
	r = l.verify(ctx, name, userDN, in)
	if r.res.Verdict != v1.VerificationVerdict_VERIFICATION_VERDICT_PASS {
		t.Fatalf("warnings must not change the verdict: %v%s", r.res.Verdict, dump(r.res))
	}
	if got := r.find(CodeExcessOU + "write_dacl"); len(got) != 1 || got[0].Object == nil {
		t.Fatalf("excess WRITE_DAC not reported once with its object:%s", dump(r.res))
	}
	if len(r.find(CodeMissingFamily)) == 0 {
		t.Fatalf("missing R6 right not reported:%s", dump(r.res))
	}
}

// AC1: each over-privileged identity is refused.
func TestLabADRefusals(t *testing.T) {
	l := newLab(t)
	ctx := labCtx(t)
	dcOU := "OU=Domain Controllers," + labDom
	for _, tc := range []struct {
		name  string
		setup func(name, userDN, sid string)
		code  string
	}{
		{"domain admins direct", func(n, _, _ string) {
			l.tool("samba-tool", "group", "addmembers", "Domain Admins", n)
			l.t.Cleanup(func() { l.try("samba-tool", "group", "removemembers", "Domain Admins", n) })
		}, CodeTier0Group},
		{"nested group", func(n, _, _ string) {
			g := fmt.Sprintf("t96g%d", time.Now().UnixNano()%1_000_000)
			l.tool("samba-tool", "group", "add", g)
			l.t.Cleanup(func() { l.try("samba-tool", "group", "delete", g) })
			l.tool("samba-tool", "group", "addmembers", g, n)
			l.tool("samba-tool", "group", "addmembers", "Domain Admins", g)
			l.t.Cleanup(func() { l.try("samba-tool", "group", "removemembers", "Domain Admins", g) })
		}, CodeTier0Group},
		{"account operators", func(n, _, _ string) {
			l.tool("samba-tool", "group", "addmembers", "Account Operators", n)
			l.t.Cleanup(func() { l.try("samba-tool", "group", "removemembers", "Account Operators", n) })
		}, CodeTier0Group},
		{"genericall on DC OU", func(_, _, s string) { l.ace(dcOU, fmt.Sprintf("(A;CI;GA;;;%s)", s)) }, CodeTier0GenericAll},
		{"write member on C1 group", func(_, _, s string) {
			l.ace("CN=Print Operators,CN=Builtin,"+labDom, fmt.Sprintf("(OA;;WP;%s;;%s)", attrMember, s))
		}, CodeTier0Write},
		{"reset password on tier0 user", func(_, _, s string) {
			l.ace("CN=Administrator,CN=Users,"+labDom, fmt.Sprintf("(OA;;CR;00299570-246d-11d0-a768-00aa006e0529;;%s)", s))
		}, CodeTier0Control},
		{"constrained delegation", func(n, _, _ string) {
			l.tool("samba-tool", "delegation", "add-service", n, "ldap/dc1.lab.activediq.test")
		}, CodeDelegConstr},
		{"unconstrained delegation", func(n, _, _ string) { l.tool("samba-tool", "delegation", "for-any-service", n, "on") }, CodeDelegUncons},
		{"rbcd on a DC", func(n, _, _ string) {
			l.tool("samba-tool", "delegation", "add-principal", "DC1$", n)
			l.t.Cleanup(func() { l.try("samba-tool", "delegation", "del-principal", "DC1$", n) })
		}, CodeDelegRBCD},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l.t = t
			name, userDN, sidText := l.user()
			tc.setup(name, userDN, sidText)
			sess := l.open(ctx, name)
			r := l.verify(ctx, name, userDN, ADInput{ManagedDomains: []adguid.GUID{guidOf(t, ctx, sess, labDom)}})
			r.refused(t)
			if len(r.find(tc.code)) == 0 {
				t.Fatalf("no %s finding:%s", tc.code, dump(r.res))
			}
		})
	}
}

// T-0237 AC1: Authenticated Users holding Reset-Password on a tier0 object is a WARN exposure
// naming the object, right and trustee; the verdict stays PASS (broad-principal exposure is WARN).
func TestLabADBroadPrincipalExposure(t *testing.T) {
	l := newLab(t)
	ctx := labCtx(t)
	name, userDN, _ := l.user()
	l.ace("CN=Administrator,CN=Users,"+labDom, "(OA;;CR;00299570-246d-11d0-a768-00aa006e0529;;AU)")
	r := l.verify(ctx, name, userDN, ADInput{})
	got := r.find(CodeTier0BroadPrincipal)
	if len(got) != 1 {
		t.Fatalf("want 1 broad-principal finding:%s", dump(r.res))
	}
	if got[0].Object == nil || got[0].Severity != v1.FindingSeverity_FINDING_SEVERITY_WARN {
		t.Fatalf("finding lacks object or is not WARN:%s", dump(r.res))
	}
	if r.res.Verdict != v1.VerificationVerdict_VERIFICATION_VERDICT_PASS {
		t.Fatalf("verdict %v:%s", r.res.Verdict, dump(r.res))
	}
}

//go:build lab

package ad

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/directory/ldapfilter"
)

func labAdmin(t *testing.T) (*ldap.Conn, Config) {
	t.Helper()
	env := labEnv(t)
	port := env["LAB_LDAPS_PORT"]
	if port == "" {
		port = "636"
	}
	cfg, roots := labConfigForProof(t, env, port)
	adm, err := ldap.DialURL("ldaps://localhost:"+port, ldap.DialWithTLSConfig(&tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS12}))
	if err != nil {
		t.Fatalf("admin dial: %v", err)
	}
	t.Cleanup(func() { adm.Close() })
	if err := adm.Bind("Administrator@lab.activediq.test", env["LAB_ADMIN_PASSWORD"]); err != nil {
		t.Fatalf("admin bind: %v", err)
	}
	return adm, cfg
}

func labOpen(t *testing.T, cfg Config) *Session {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	s, err := Open(ctx, cfg)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func adminAdd(t *testing.T, adm *ldap.Conn, dnStr string, attrs map[string][]string) {
	t.Helper()
	req := ldap.NewAddRequest(dnStr, nil)
	for k, v := range attrs {
		req.Attribute(k, v)
	}
	if err := adm.Add(req); err != nil {
		t.Fatalf("add %s: %v", dnStr, err)
	}
}

func adminGUID(t *testing.T, adm *ldap.Conn, dnStr string) guid.GUID {
	t.Helper()
	res, err := adm.Search(ldap.NewSearchRequest(dnStr, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"objectGUID"}, nil))
	if err != nil || len(res.Entries) != 1 {
		t.Fatalf("guid of %s: %v", dnStr, err)
	}
	g, err := guid.FromBytes(res.Entries[0].GetRawAttributeValue("objectGUID"))
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func userAttrs(sam string) map[string][]string {
	return map[string][]string{"objectClass": {"top", "person", "organizationalPerson", "user"}, "sAMAccountName": {sam}}
}

// LF-31, LF-39 and CC-SRCH-02..05 on the lab: roots by GUID, de-duplication across nested roots,
// post-authorisation counts, a moved root, and a deleted root that does not widen.
func TestLabScopedSearch(t *testing.T) {
	adm, cfg := labAdmin(t)
	s := labOpen(t, cfg)
	stamp := time.Now().Format("150405")
	ouA := "OU=t0115a" + stamp + "," + labBase
	ouB := "OU=nested," + ouA
	ouDest := "OU=t0115dest" + stamp + "," + labBase
	adminAdd(t, adm, ouA, map[string][]string{"objectClass": {"top", "organizationalUnit"}})
	adminAdd(t, adm, ouB, map[string][]string{"objectClass": {"top", "organizationalUnit"}})
	adminAdd(t, adm, ouDest, map[string][]string{"objectClass": {"top", "organizationalUnit"}})
	var cleanup []string
	t.Cleanup(func() {
		for _, d := range cleanup {
			_ = adm.Del(ldap.NewDelRequest(d, nil))
		}
	})
	users := []string{"CN=u1," + ouA, "CN=u2," + ouA, "CN=u3," + ouB}
	for i, u := range users {
		adminAdd(t, adm, u, userAttrs("t0115u"+stamp+strconv.Itoa(i)))
	}
	cleanup = append(cleanup, users[2], users[1], users[0], ouB)
	gA, gB := adminGUID(t, adm, ouA), adminGUID(t, adm, ouB)

	cls, _ := ldapfilter.ParseAttrName("objectClass", s.schema)
	f := ldapfilter.Eq(cls, ldapfilter.String("user"))
	collect := func(req ScopedRequest) (map[string]int, ScopedResult, error) {
		got := map[string]int{}
		req.Filter, req.Attributes = f, []string{"distinguishedName"}
		res, err := s.ScopedSearch(context.Background(), req, func(e *Entry) error { got[e.DN]++; return nil })
		return got, res, err
	}
	// Nested roots: each object once (CC-SRCH-03), bounded to the subtree (CC-SRCH-02).
	got, res, err := collect(ScopedRequest{Roots: []dn.ObjectRef{dn.GUIDRef(gA), dn.GUIDRef(gB)}, Depth: ScopeSubtree, PageSize: 2})
	if err != nil || len(got) != 3 || res.Returned != 3 || res.RootsCompleted != 2 {
		t.Fatalf("subtree: %v %v %+v", err, got, res)
	}
	for _, n := range got {
		if n != 1 {
			t.Errorf("duplicate entry: %v", got)
		}
	}
	got, _, err = collect(ScopedRequest{Roots: []dn.ObjectRef{dn.GUIDRef(gA)}, Depth: ScopeOneLevel})
	if err != nil || len(got) != 2 {
		t.Errorf("one level: %v %v", err, got)
	}
	// LF-39: a denied object is withheld and the count is the post-authorisation count.
	deny := func(e *Entry) (bool, error) { return !strings.HasPrefix(e.DN, "CN=u2,"), nil }
	got, res, err = collect(ScopedRequest{Roots: []dn.ObjectRef{dn.GUIDRef(gA)}, Depth: ScopeSubtree, PageSize: 1, Authorize: deny})
	if err != nil || len(got) != 2 || res.Returned != 2 || res.Denied != 1 {
		t.Errorf("authorise: %v %v %+v", err, got, res)
	}
	// Moved root: the GUID follows the object (CC-SRCH-05).
	if err := adm.ModifyDN(ldap.NewModifyDNRequest(ouB, "OU=nested", true, ouDest)); err != nil {
		t.Fatalf("move: %v", err)
	}
	movedB := "OU=nested," + ouDest
	cleanup = []string{users[1], users[0], "CN=u3," + movedB, movedB, ouA, ouDest}
	got, _, err = collect(ScopedRequest{Roots: []dn.ObjectRef{dn.GUIDRef(gB)}, Depth: ScopeSubtree})
	if err != nil || len(got) != 1 {
		t.Errorf("moved root: %v %v", err, got)
	}
	// Deleted root: DELEGATION_ROOT_GONE, no entries, no fallback (LF-31, CC-SRCH-04).
	for _, d := range []string{"CN=u3," + movedB, movedB} {
		if err := adm.Del(ldap.NewDelRequest(d, nil)); err != nil {
			t.Fatalf("delete %s: %v", d, err)
		}
	}
	got, res, err = collect(ScopedRequest{Roots: []dn.ObjectRef{dn.GUIDRef(gB)}, Depth: ScopeSubtree})
	if CodeOf(err) != CodeDelegationRootGone || len(got) != 0 || res.Returned != 0 {
		t.Errorf("deleted root: %v %v %+v", err, got, res)
	}
}

// LF-32 (referral) is not provable on Samba: no referral objectClass, no injectable transport (T-0309).

// LF-33 on the wire: a GC port is refused before any connection.
func TestLabGlobalCatalogRefused(t *testing.T) {
	_, cfg := labAdmin(t)
	for _, p := range []string{"3268", "3269"} {
		cfg.Servers = []string{"localhost:" + p}
		if _, err := Open(context.Background(), cfg); CodeOf(err) != CodeGlobalCatalog {
			t.Errorf("port %s: %v", p, err)
		}
	}
}

// LF-37, LF-38, LF-35 and CC-SCH-02, schema-driven: the oracle is a plain admin query of every
// attributeSchema with a secret searchFlags bit, so a newly flagged attribute is covered with no code
// change. A custom attribute flagged 0x200 only is added to the schema first when the lab allows it.
func TestLabSchemaDrivenSecretAttrs(t *testing.T) {
	adm, cfg := labAdmin(t)
	env := labEnv(t)
	_ = env
	schemaNC := "CN=Schema,CN=Configuration," + labBase
	custom := "t0115RodcOnly" + time.Now().Format("150405")
	oid := "1.2.840.113556.1.8000.2554.99999.4." + strconv.FormatInt(time.Now().Unix(), 10)
	ad := ldap.NewAddRequest("CN="+custom+","+schemaNC, nil)
	for k, v := range map[string][]string{
		"objectClass": {"top", "attributeSchema"}, "lDAPDisplayName": {custom}, "attributeID": {oid},
		"attributeSyntax": {"2.5.5.12"}, "oMSyntax": {"64"}, "isSingleValued": {"TRUE"}, "searchFlags": {"512"},
	} {
		ad.Attribute(k, v)
	}
	addErr := adm.Add(ad)
	seeded := addErr == nil
	if !seeded {
		t.Logf("lab refused the custom 0x200-only attribute (CC-SCH-02 custom case needs a seed addition): %v", addErr)
	}

	oracle, err := adm.SearchWithPaging(ldap.NewSearchRequest(schemaNC, ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=attributeSchema)", []string{"lDAPDisplayName", "searchFlags"}, nil), 500)
	if err != nil {
		t.Fatal(err)
	}
	s := labOpen(t, cfg)
	flagged, sawCustom := 0, false
	for _, e := range oracle.Entries {
		name := e.GetAttributeValue("lDAPDisplayName")
		fl, _ := strconv.Atoi(e.GetAttributeValue("searchFlags"))
		if name == custom {
			sawCustom = true
		}
		if fl&(0x80|0x200|0x1000) == 0 {
			continue
		}
		flagged++
		if !s.schema.IsSecret(name) {
			t.Errorf("%s (searchFlags %#x) is not in SecretAttrs", name, fl)
			continue
		}
		if _, err := s.checkAttrs([]string{"cn", name}, false); CodeOf(err) != CodeSecretAttribute {
			t.Errorf("attrs %s: %v", name, err)
		}
		a, _ := ldapfilter.ParseAttrName(name, s.schema)
		if _, err := ldapfilter.Render(ldapfilter.Present(a), s.schema); ldapfilter.Code(err) != ldapfilter.SecretAttribute {
			t.Errorf("filter %s: %v", name, err)
		}
		if _, err := ldapfilter.ParseSortKey(name, s.schema); ldapfilter.Code(err) != ldapfilter.ForbiddenSortKey {
			t.Errorf("sort %s: %v", name, err)
		}
	}
	t.Logf("%d schema-flagged attributes checked (oracle: %d attributeSchema objects)", flagged, len(oracle.Entries))
	if flagged == 0 {
		t.Error("vacuous: the lab schema flags no attribute 0x80/0x200/0x1000 — Windows lab required (safe-primitives gotcha)")
	}
	if seeded && !sawCustom {
		t.Logf("custom attribute not visible to the oracle yet (schema cache); retry after schemaUpdateNow")
	}
	if seeded && sawCustom && !s.schema.IsSecret(custom) {
		t.Errorf("custom 0x200-only attribute %s is not secret", custom)
	}
	// The static list is refused on a real session too (LF-37).
	for _, n := range []string{"unicodePwd", "msDS-ManagedPassword", "ms-Mcs-AdmPwd"} {
		if !s.schema.IsSecret(n) {
			t.Errorf("static %s not secret", n)
		}
	}
}

// ReadSecret on the lab: userPassword is on the static list and Samba stores it readably for an
// administrator. The connector identity may not be allowed to read it; both outcomes must be an
// audited, typed result with no value in the audit event.
func TestLabReadSecret(t *testing.T) {
	adm, cfg := labAdmin(t)
	var events []SecretReadEvent
	cfg.SecretAudit = func(e SecretReadEvent) error { events = append(events, e); return nil }
	s := labOpen(t, cfg)
	sam := "t0115sec" + time.Now().Format("150405")
	u := "CN=" + sam + ",CN=Users," + labBase
	attrs := userAttrs(sam)
	attrs["userPassword"] = []string{"lab-only-secret-value"}
	adminAdd(t, adm, u, attrs)
	t.Cleanup(func() { _ = adm.Del(ldap.NewDelRequest(u, nil)) })
	g := adminGUID(t, adm, u)

	attr, err := s.SecretAttr("userPassword")
	if err != nil {
		t.Fatal(err)
	}
	grant, err := MintSecretReadGrant("lab-actor", g, attr, "T-0115 lab test")
	if err != nil {
		t.Fatal(err)
	}
	sec, err := s.ReadSecret(context.Background(), dn.GUIDRef(g), attr, grant)
	switch {
	case err == nil:
		var v string
		sec.Expose(func(b []byte) { v = string(b) })
		if v != "lab-only-secret-value" {
			t.Errorf("secret value mismatch")
		}
		if strings.Contains(sec.LogValue().String()+strings.TrimSpace(fmtSprint(sec)), "lab-only") {
			t.Errorf("secret printed")
		}
	case CodeOf(err) == CodeSecretNotSet:
		t.Logf("connector identity cannot read userPassword on Samba (SECRET_NOT_SET): refusal path proved")
	default:
		t.Fatalf("ReadSecret: %v", err)
	}
	if len(events) != 1 || events[0].Target != g || events[0].Attribute != "userPassword" || events[0].Actor != "lab-actor" {
		t.Errorf("audit: %+v", events)
	}
	// unicodePwd is write-only: it never comes back.
	up, err := s.SecretAttr("unicodePwd")
	if err != nil {
		t.Fatal(err)
	}
	g2, _ := MintSecretReadGrant("lab-actor", g, up, "T-0115 lab test")
	if _, err := s.ReadSecret(context.Background(), dn.GUIDRef(g), up, g2); CodeOf(err) != CodeSecretNotSet {
		t.Errorf("unicodePwd: %v", err)
	}
	if len(events) != 2 || events[1].Outcome != string(CodeSecretNotSet) {
		t.Errorf("audit of refusal: %+v", events)
	}
	// An object that does not exist.
	ghost, _ := MintSecretReadGrant("lab-actor", guid.GUID{0xde, 0xad}, attr, "T-0115 lab test")
	if _, err := s.ReadSecret(context.Background(), dn.GUIDRef(guid.GUID{0xde, 0xad}), attr, ghost); CodeOf(err) != CodeObjectNotFound {
		t.Errorf("missing object: %v", err)
	}
}

func fmtSprint(v any) string {
	return strings.Join([]string{sprintf("%v", v), sprintf("%+v", v), sprintf("%#v", v)}, " ")
}

var sprintf = fmt.Sprintf

// T-0313 (1): a secret read that succeeded must not outlive a failing audit sink. The value is
// destroyed and the caller gets an error and a zero Secret.
func TestLabReadSecretAuditFailureDestroysValue(t *testing.T) {
	adm, cfg := labAdmin(t)
	sinkErr := fmt.Errorf("audit sink down")
	fail := false
	var events int
	cfg.SecretAudit = func(SecretReadEvent) error {
		events++
		if fail {
			return sinkErr
		}
		return nil
	}
	s := labOpen(t, cfg)
	sam := "t0313aud" + time.Now().Format("150405")
	u := "CN=" + sam + ",CN=Users," + labBase
	attrs := userAttrs(sam)
	attrs["userPassword"] = []string{"lab-only-audit-value"}
	adminAdd(t, adm, u, attrs)
	t.Cleanup(func() { _ = adm.Del(ldap.NewDelRequest(u, nil)) })
	g := adminGUID(t, adm, u)
	attr, err := s.SecretAttr("userPassword")
	if err != nil {
		t.Fatal(err)
	}
	grant, err := MintSecretReadGrant("lab-actor", g, attr, "T-0313 lab test")
	if err != nil {
		t.Fatal(err)
	}
	// Precondition: with a working sink the value is really readable by this identity, otherwise the
	// failing-sink assertion below would be vacuous.
	ok, err := s.ReadSecret(context.Background(), dn.GUIDRef(g), attr, grant)
	if err != nil {
		t.Fatalf("precondition: the lab identity must read userPassword (else this test proves nothing): %v", err)
	}
	ok.Destroy()

	fail = true
	sec, err := s.ReadSecret(context.Background(), dn.GUIDRef(g), attr, grant)
	if err == nil {
		t.Fatal("ReadSecret succeeded although the audit sink failed")
	}
	if CodeOf(err) != CodeProtocol || !errors.Is(err, sinkErr) {
		t.Errorf("error should be the audit failure carrying the sink error: %v", err)
	}
	sec.Expose(func(b []byte) {
		if len(b) != 0 {
			t.Errorf("a value survived the audit failure")
		}
	})
	if strings.Contains(err.Error(), "lab-only") {
		t.Error("value in error text")
	}
	if events != 2 {
		t.Errorf("audit attempts = %d, want 2", events)
	}
}

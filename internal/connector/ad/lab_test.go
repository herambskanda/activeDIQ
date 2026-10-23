//go:build lab

// Lab tests run against the Samba AD lab: `make lab-up && make lab-test-connector`. They read the
// per-run credentials from lab/.lab.env and the CA from lab/.lab-ca.pem; nothing is skipped when
// the lab is missing, so a CI job that selects the tag fails loudly.
package ad

import (
	"bufio"
	"context"
	"crypto/x509"
	"github.com/skenzeriq/activediq/internal/platform/secret"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/directory/ldapfilter"
)

const labBase = "DC=lab,DC=activediq,DC=test"

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

func labSession(t *testing.T) *Session {
	t.Helper()
	env := labEnv(t)
	pem, err := os.ReadFile(filepath.Join("..", "..", "..", "lab", ".lab-ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("bad lab CA")
	}
	port := env["LAB_LDAPS_PORT"]
	if port == "" {
		port = "636"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, err := Open(ctx, Config{
		Servers:    []string{"localhost:" + port},
		RootCAs:    pool,
		Credential: Credential{BindName: "svc-activediq@lab.activediq.test", Password: secret.FromBytes([]byte(env["LAB_SVC_PASSWORD"]))},
		PageSize:   500,
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func findOne(t *testing.T, s *Session, attr, value string) *Entry {
	t.Helper()
	a, err := ldapfilter.ParseAttrName(attr, s.schema)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := dn.Parse(labBase, dn.Strict)
	var got []*Entry
	err = s.Search(context.Background(), SearchRequest{
		Base: dn.DNRef(root), Scope: ScopeSubtree,
		Filter:     ldapfilter.Eq(a, ldapfilter.String(value)),
		Attributes: []string{"objectGUID", "distinguishedName"},
	}, func(e *Entry) error { got = append(got, e); return nil })
	if err != nil {
		t.Fatalf("search %s=%q: %v", attr, value, err)
	}
	if len(got) != 1 {
		t.Fatalf("search %s=%q: %d entries", attr, value, len(got))
	}
	return got[0]
}

func TestLabBindRejectsWrongPasswordAndUntrustedCert(t *testing.T) {
	env := labEnv(t)
	port := env["LAB_LDAPS_PORT"]
	if port == "" {
		port = "636"
	}
	pem, _ := os.ReadFile(filepath.Join("..", "..", "..", "lab", ".lab-ca.pem"))
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	ctx := context.Background()
	_, err := Open(ctx, Config{Servers: []string{"localhost:" + port}, RootCAs: pool, Credential: Credential{BindName: "svc-activediq@lab.activediq.test", Password: secret.FromBytes([]byte("wrong-password"))}})
	if CodeOf(err) != CodeBindFailed {
		t.Errorf("wrong password: %v", err)
	}
	// System roots do not trust the lab CA: the connection must fail, never fall back.
	_, err = Open(ctx, Config{Servers: []string{"localhost:" + port}, Credential: Credential{BindName: "svc-activediq@lab.activediq.test", Password: secret.FromBytes([]byte(env["LAB_SVC_PASSWORD"]))}})
	if CodeOf(err) != CodeUnreachable {
		t.Errorf("untrusted CA: %v", err)
	}
}

func TestLabRootDSE(t *testing.T) {
	s := labSession(t)
	r, err := s.RootDSE(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(r.DefaultNamingContext, labBase) {
		t.Errorf("defaultNamingContext = %q", r.DefaultNamingContext)
	}
	for _, oid := range []string{"1.2.840.113556.1.4.319", "1.2.840.113556.1.4.801"} {
		if !r.SupportsControl(oid) {
			t.Errorf("DC does not advertise control %s", oid)
		}
	}
}

// AC1: tokenGroups of the connector's own object.
func TestLabReadOwnTokenGroups(t *testing.T) {
	s := labSession(t)
	self := findOne(t, s, "sAMAccountName", "svc-activediq")
	g, err := self.GUID()
	if err != nil {
		t.Fatal(err)
	}
	e, err := s.Read(context.Background(), dn.GUIDRef(g), []string{"objectSid", "tokenGroups"}, ReadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	toks, err := e.SIDs("tokenGroups")
	if err != nil || len(toks) == 0 {
		t.Fatalf("tokenGroups = %v, %v", toks, err)
	}
	me, _ := e.SIDs("objectSid")
	dom, _ := me[0].DomainSID()
	var domainUsers bool
	for _, x := range toks {
		if rid, ok := x.RID(); ok && rid == 513 {
			if d, _ := x.DomainSID(); d == dom {
				domainUsers = true
			}
		}
	}
	if !domainUsers {
		t.Errorf("Domain Users (RID 513) missing from %d token groups", len(toks))
	}
	// The same read by DN gives the same answer.
	d, _ := dn.Parse(self.DN, dn.Strict)
	e2, err := s.Read(context.Background(), dn.DNRef(d), []string{"tokenGroups"}, ReadOptions{})
	if err != nil || len(e2.Raw("tokenGroups")) != len(toks) {
		t.Errorf("read by DN: %v, %d values", err, len(e2.Raw("tokenGroups")))
	}
	// A search cannot ask for it.
	root, _ := dn.Parse(labBase, dn.Strict)
	cn, _ := ldapfilter.ParseAttrName("cn", s.schema)
	err = s.Search(context.Background(), SearchRequest{Base: dn.DNRef(root), Scope: ScopeBase, Filter: ldapfilter.Present(cn), Attributes: []string{"tokenGroups"}}, func(*Entry) error { return nil })
	if CodeOf(err) != CodeAttributeNotAllowed {
		t.Errorf("search for tokenGroups: %v", err)
	}
}

// AC2: effective-rights attributes of a target object, as the connector identity sees them.
func TestLabReadEffectiveRights(t *testing.T) {
	s := labSession(t)
	ctx := context.Background()
	cases := []struct {
		attr, value string
		wantWrite   bool
	}{
		{"sAMAccountName", "svc-activediq", false}, // own object: delegated rights only on OU=Managed
	}
	_ = cases
	// A user inside the delegated OU vs the domain root, which the identity can only read.
	managed := findOne(t, s, "ou", "Managed")
	mg, _ := managed.GUID()
	m, err := s.Read(ctx, dn.GUIDRef(mg), []string{"allowedAttributesEffective", "allowedChildClassesEffective", "sDRightsEffective"}, ReadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Managed: %d writable attrs, child classes %v, sDRightsEffective present=%v", len(m.Strings("allowedAttributesEffective")), m.Strings("allowedChildClassesEffective"), m.Has("sDRightsEffective"))
	root, _ := dn.Parse(labBase, dn.Strict)
	r, err := s.Read(ctx, dn.DNRef(root), []string{"allowedAttributesEffective", "allowedChildClassesEffective", "sDRightsEffective"}, ReadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if n := len(r.Strings("allowedChildClassesEffective")); n != 0 {
		t.Errorf("connector identity can create %d child classes at the domain root; it must not", n)
	}
	if len(m.Strings("allowedChildClassesEffective")) == 0 {
		t.Error("connector identity sees no creatable child class in OU=Managed, where it is delegated")
	}
	if v, ok, err := m.Int32("sDRightsEffective"); err != nil || !ok || v&8 != 0 {
		t.Errorf("sDRightsEffective = %d ok=%v err=%v; the SACL bit must not be granted", v, ok, err)
	}
}

func TestLabReadSecurityDescriptor(t *testing.T) {
	s := labSession(t)
	managed := findOne(t, s, "ou", "Managed")
	g, _ := managed.GUID()
	e, err := s.Read(context.Background(), dn.GUIDRef(g), []string{"nTSecurityDescriptor"}, ReadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	sd := e.Raw("nTSecurityDescriptor")
	if len(sd) != 1 || len(sd[0]) < 20 {
		t.Fatalf("nTSecurityDescriptor = %d values", len(sd))
	}
	// Self-relative SD header: revision 1, control word; offsetSacl (bytes 12..15) must be 0.
	if sd[0][0] != 1 || sd[0][12]|sd[0][13]|sd[0][14]|sd[0][15] != 0 {
		t.Errorf("descriptor header % x: SACL present or malformed", sd[0][:20])
	}
}

// Ranged attributes: GG-Big has 3000 members; all of them come back, nothing is duplicated.
func TestLabReadRangedMembers(t *testing.T) {
	s := labSession(t)
	big := findOne(t, s, "sAMAccountName", "GG-Big")
	g, _ := big.GUID()
	e, err := s.Read(context.Background(), dn.GUIDRef(g), []string{"member"}, ReadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	m := e.Strings("member")
	seen := map[string]struct{}{}
	for _, v := range m {
		seen[strings.ToLower(v)] = struct{}{}
	}
	if len(m) != 3000 || len(seen) != 3000 {
		t.Errorf("member values = %d, distinct = %d, want 3000", len(m), len(seen))
	}
	capped, err := s.Read(context.Background(), dn.GUIDRef(g), []string{"member"}, ReadOptions{MaxValues: 1600})
	if err != nil {
		t.Fatal(err)
	}
	if len(capped.Raw("member")) != 1600 || len(capped.Truncated) != 1 {
		t.Errorf("capped read: %d values, truncated %v", len(capped.Raw("member")), capped.Truncated)
	}
}

// Paging: a subtree search over the whole Managed OU streams every user in several pages.
func TestLabPagedSearchStreams(t *testing.T) {
	s := labSession(t)
	managed := findOne(t, s, "ou", "Managed")
	d, _ := dn.Parse(managed.DN, dn.Strict)
	cls, _ := ldapfilter.ParseAttrName("objectClass", s.schema)
	n := 0
	seen := map[guid.GUID]struct{}{}
	err := s.Search(context.Background(), SearchRequest{
		Base: dn.DNRef(d), Scope: ScopeSubtree, PageSize: 500,
		Filter:     ldapfilter.Eq(cls, ldapfilter.String("user")),
		Attributes: []string{"objectGUID"},
	}, func(e *Entry) error {
		g, err := e.GUID()
		if err != nil {
			return err
		}
		seen[g] = struct{}{}
		n++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n < 5000 || len(seen) != n {
		t.Errorf("entries = %d, distinct = %d, want >= 5000 and no duplicates", n, len(seen))
	}
	// Stopping from the callback stops the search cleanly and the session stays usable.
	stop := context.Canceled
	cnt := 0
	err = s.Search(context.Background(), SearchRequest{Base: dn.DNRef(d), Scope: ScopeSubtree, PageSize: 100, Filter: ldapfilter.Eq(cls, ldapfilter.String("user")), Attributes: []string{"objectGUID"}},
		func(*Entry) error {
			cnt++
			if cnt == 150 {
				return stop
			}
			return nil
		})
	if err != stop || cnt != 150 {
		t.Errorf("early stop: err=%v cnt=%d", err, cnt)
	}
	if _, err := s.RootDSE(context.Background()); err != nil {
		t.Errorf("session unusable after early stop: %v", err)
	}
}

// AC4 on the wire: hostile values are data. Edge-case users are found by exact value; injection
// attempts match nothing and never widen the result.
func TestLabHostileValuesOnTheWire(t *testing.T) {
	s := labSession(t)
	cn, _ := ldapfilter.ParseAttrName("cn", s.schema)
	root, _ := dn.Parse(labBase, dn.Strict)
	count := func(v string) int {
		n := 0
		err := s.Search(context.Background(), SearchRequest{Base: dn.DNRef(root), Scope: ScopeSubtree, Filter: ldapfilter.Eq(cn, ldapfilter.String(v)), Attributes: []string{"cn"}}, func(*Entry) error { n++; return nil })
		if err != nil {
			t.Fatalf("%q: %v", v, err)
		}
		return n
	}
	for _, v := range []string{"*", "*)(objectClass=*", "a*", `\2a`, "x)(cn=*", "admin*)(|(cn=*"} {
		if n := count(v); n != 0 {
			t.Errorf("hostile value %q matched %d entries", v, n)
		}
	}
	// An edge-case user with a comma/plus/quote in the CN is found exactly, and read back by its DN.
	var edgeDN string
	err := s.Search(context.Background(), SearchRequest{Base: dn.DNRef(root), Scope: ScopeSubtree, Filter: ldapfilter.Contains(cn, ","), Attributes: []string{"cn"}},
		func(e *Entry) error {
			if edgeDN == "" && strings.Contains(e.DN, "EdgeCases") {
				edgeDN = e.DN
			}
			return nil
		})
	if err != nil || edgeDN == "" {
		t.Fatalf("no edge-case user with a comma: %v", err)
	}
	d, err := dn.Parse(edgeDN, dn.Strict)
	if err != nil {
		t.Fatalf("DC's own DN does not round-trip the strict parser: %v", err)
	}
	if _, err := s.Read(context.Background(), dn.DNRef(d), []string{"cn"}, ReadOptions{}); err != nil {
		t.Errorf("read by edge-case DN: %v", err)
	}
}

func TestLabNotFound(t *testing.T) {
	s := labSession(t)
	var g guid.GUID
	g[0] = 1
	if _, err := s.Read(context.Background(), dn.GUIDRef(g), []string{"cn"}, ReadOptions{}); CodeOf(err) != CodeObjectNotFound {
		t.Errorf("missing GUID: %v", err)
	}
}

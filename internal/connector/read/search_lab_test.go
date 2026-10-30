//go:build lab

package read_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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

// T-0695: the ScopedSearch RPC (read.Handler over read.NewADSource over a real Samba session, served
// on a bufconn gRPC server) against an admin LDAP query of the same tree.
// `make lab-up && go test -tags lab ./internal/connector/read -run TestLabScopedSearch`.
// Samba does not range `member` (MaxValRange is a Windows behaviour): here the handler's own 1500
// cap produces complete=false; the DC-side ranging is a Windows-lab ticket.

const (
	bulkUsers  = 1600 // > 1000 (default MaxPageSize) and > 1500 (the first-range cap)
	searchPage = 400
	memberCap  = 1500
)

type searchLab struct {
	adm    *ldap.Conn
	client connectorv1.ConnectorClient
	ident  *connectorv1.DirectoryIdentity
	stamp  string
}

func newSearchLab(t *testing.T) *searchLab {
	t.Helper()
	env := labEnv(t)
	pem, err := os.ReadFile(filepath.Join("..", "..", "..", "lab", ".lab-ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	port := env["LAB_LDAPS_PORT"]
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	sess, err := ad.Open(ctx, ad.Config{Servers: []string{"localhost:" + port}, RootCAs: pool, PageSize: searchPage,
		Credential: ad.Credential{BindName: "svc-activediq@lab.activediq.test", Password: secret.FromBytes([]byte(env["LAB_SVC_PASSWORD"]))}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sess.Close() })
	adm, err := ldap.DialURL("ldaps://localhost:"+port, ldap.DialWithTLSConfig(&tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS12}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { adm.Close() })
	if err := adm.Bind("Administrator@lab.activediq.test", env["LAB_ADMIN_PASSWORD"]); err != nil {
		t.Fatal(err)
	}
	l := &searchLab{adm: adm, stamp: fmt.Sprint(time.Now().UnixNano() % 100_000_000)}
	l.ident = &connectorv1.DirectoryIdentity{Identity: &connectorv1.DirectoryIdentity_AdForest{AdForest: &connectorv1.AdForestIdentity{
		ForestRootNcGuid: l.guid(t, labDom)}}}
	prov := write.NewADProvider(sess, nil, l.ident, &memPins{})
	src, err := read.NewADSource(sess, prov)
	if err != nil {
		t.Fatal(err)
	}
	l.client = start(t, src)
	return l
}

func (l *searchLab) guid(t *testing.T, dn string) *connectorv1.Guid {
	t.Helper()
	r, err := l.adm.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"objectGUID"}, nil))
	if err != nil || len(r.Entries) != 1 {
		t.Fatalf("guid of %s: %v", dn, err)
	}
	g, err := guid.FromBytes(r.Entries[0].GetRawAttributeValue("objectGUID"))
	if err != nil {
		t.Fatal(err)
	}
	return write.GUIDToWire(g)
}

func (l *searchLab) add(t *testing.T, dn string, attrs map[string][]string) {
	t.Helper()
	a := ldap.NewAddRequest(dn, nil)
	for k, v := range attrs {
		a.Attribute(k, v)
	}
	if err := l.adm.Add(a); err != nil {
		t.Fatalf("add %s: %v", dn, err)
	}
}

// delTree removes dn and everything below it, deepest first, ignoring failures (cleanup only).
func (l *searchLab) delTree(dn string) {
	r, err := l.adm.Search(ldap.NewSearchRequest(dn, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"1.1"}, nil))
	if err != nil {
		return
	}
	dns := make([]string, 0, len(r.Entries))
	for _, e := range r.Entries {
		dns = append(dns, e.DN)
	}
	sort.Slice(dns, func(i, j int) bool { return len(dns[i]) > len(dns[j]) })
	for _, d := range dns {
		_ = l.adm.Del(ldap.NewDelRequest(d, nil))
	}
}

func (l *searchLab) request(root *connectorv1.Guid, depth connectorv1.SearchDepth, class string, attrs ...string) *connectorv1.ScopedSearchRequest {
	return &connectorv1.ScopedSearchRequest{
		Connection: &connectorv1.ConnectionRef{ConnectionId: "c1", DirectoryIdentity: l.ident},
		Roots:      []*connectorv1.SearchRoot{{Guid: root}},
		Depth:      depth,
		Filter: &connectorv1.Filter{Node: &connectorv1.Filter_Equal{Equal: &connectorv1.Comparison{Attribute: "objectClass",
			Value: &connectorv1.FilterValue{Value: &connectorv1.FilterValue_Text{Text: class}}}}},
		Attributes: attrs,
		PageSize:   searchPage,
	}
}

// rpc runs the RPC and returns the entries by objectGUID plus whether the stream ended in SearchCompleted.
func rpc(t *testing.T, c connectorv1.ConnectorClient, r *connectorv1.ScopedSearchRequest) (map[string]*connectorv1.DirectoryEntry, bool, error) {
	t.Helper()
	ms, err := searchAll(c, r)
	got := map[string]*connectorv1.DirectoryEntry{}
	done := false
	for _, m := range ms {
		for _, e := range m.GetBatch().GetEntries() {
			k := string(e.GetObjectGuid().GetValue())
			if got[k] != nil {
				t.Errorf("entry %s delivered twice", e.GetDn().GetDisplayDn())
			}
			got[k] = e
		}
		if m.GetCompleted() != nil {
			done = true
		}
	}
	return got, done, err
}

// adminGUIDs is the reference answer: the same search through a separate admin LDAP connection.
func (l *searchLab) adminGUIDs(t *testing.T, base string, scope int, class string) map[string]string {
	t.Helper()
	r, err := l.adm.SearchWithPaging(ldap.NewSearchRequest(base, scope, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass="+class+")", []string{"objectGUID"}, nil), 500)
	if err != nil {
		t.Fatalf("admin search: %v", err)
	}
	out := map[string]string{}
	for _, e := range r.Entries {
		g, err := guid.FromBytes(e.GetRawAttributeValue("objectGUID"))
		if err != nil {
			t.Fatal(err)
		}
		out[string(write.GUIDToWire(g).GetValue())] = e.DN
	}
	return out
}

func sameSet(t *testing.T, what string, got map[string]*connectorv1.DirectoryEntry, want map[string]string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s: rpc returned %d entries, admin LDAP %d", what, len(got), len(want))
	}
	missing := 0
	for k, dn := range want {
		e := got[k]
		if e == nil {
			if missing++; missing <= 3 {
				t.Errorf("%s: missing %s", what, dn)
			}
			continue
		}
		if !strings.EqualFold(e.GetDn().GetDisplayDn(), dn) {
			t.Errorf("%s: dn %q != admin %q", what, e.GetDn().GetDisplayDn(), dn)
		}
	}
	for k, e := range got {
		if _, ok := want[k]; !ok {
			t.Errorf("%s: extra %s", what, e.GetDn().GetDisplayDn())
		}
	}
}

func TestLabScopedSearchNestedAndOneLevelEqualAdminLDAP(t *testing.T) {
	l := newSearchLab(t)
	ouA := "OU=t0695a" + l.stamp + "," + labDom
	ouB := "OU=nested," + ouA
	t.Cleanup(func() { l.delTree(ouA) })
	ou := map[string][]string{"objectClass": {"top", "organizationalUnit"}}
	l.add(t, ouA, ou)
	l.add(t, ouB, ou)
	// Commas, '+', '#', a quote and non-ASCII letters in the RDN: DN text must survive the RPC.
	names := []string{`Müller\, Ann`, `a\+b`, `\#hash`, `q\"uote`, `plain`}
	for i, n := range names {
		l.add(t, "CN="+n+","+ouA, map[string][]string{"objectClass": {"top", "person", "organizationalPerson", "user"},
			"sAMAccountName": {fmt.Sprintf("t0695a%s%d", l.stamp, i)}})
	}
	l.add(t, "CN=deep,"+ouB, map[string][]string{"objectClass": {"top", "person", "organizationalPerson", "user"},
		"sAMAccountName": {"t0695d" + l.stamp}})

	gA, gB := l.guid(t, ouA), l.guid(t, ouB)

	got, done, err := rpc(t, l.client, l.request(gA, connectorv1.SearchDepth_SEARCH_DEPTH_SUBTREE, "user", "cn", "sAMAccountName"))
	if err != nil || !done {
		t.Fatalf("subtree: done=%v err=%v", done, err)
	}
	want := l.adminGUIDs(t, ouA, ldap.ScopeWholeSubtree, "user")
	if len(want) != len(names)+1 {
		t.Fatalf("seed: admin sees %d users", len(want))
	}
	sameSet(t, "subtree", got, want)

	got, done, err = rpc(t, l.client, l.request(gA, connectorv1.SearchDepth_SEARCH_DEPTH_ONE_LEVEL, "user", "cn"))
	if err != nil || !done {
		t.Fatalf("one level: done=%v err=%v", done, err)
	}
	one := l.adminGUIDs(t, ouA, ldap.ScopeSingleLevel, "user")
	if len(one) != len(names) {
		t.Fatalf("one-level reference has %d", len(one))
	}
	sameSet(t, "one level", got, one)

	// Parents: the OU for direct children, the nested OU for the deep user.
	sub, _, _ := rpc(t, l.client, l.request(gA, connectorv1.SearchDepth_SEARCH_DEPTH_SUBTREE, "user", "cn"))
	for _, e := range sub {
		wantParent := gA
		if strings.HasPrefix(strings.ToLower(e.GetDn().GetDisplayDn()), "cn=deep,") {
			wantParent = gB
		}
		if string(e.GetParentGuid().GetValue()) != string(wantParent.GetValue()) {
			t.Errorf("%s: wrong parent_guid", e.GetDn().GetDisplayDn())
		}
	}

	// Nested roots (OU and the OU inside it): every object once, none from outside.
	r := l.request(gA, connectorv1.SearchDepth_SEARCH_DEPTH_SUBTREE, "user", "cn")
	r.Roots = append(r.Roots, &connectorv1.SearchRoot{Guid: gB})
	got, done, err = rpc(t, l.client, r)
	if err != nil || !done {
		t.Fatalf("nested roots: done=%v err=%v", done, err)
	}
	sameSet(t, "nested roots", got, want)
}

func TestLabScopedSearchPagesBeyondOneThousandAndTruncatesBigGroup(t *testing.T) {
	if testing.Short() {
		t.Skip("seeds 1600 users")
	}
	l := newSearchLab(t)
	ou := "OU=t0695p" + l.stamp + "," + labDom
	t.Cleanup(func() { l.delTree(ou) })
	l.add(t, ou, map[string][]string{"objectClass": {"top", "organizationalUnit"}})
	members := make([]string, 0, bulkUsers)
	for i := 0; i < bulkUsers; i++ {
		dn := fmt.Sprintf("CN=bulk%04d,%s", i, ou)
		l.add(t, dn, map[string][]string{"objectClass": {"top", "person", "organizationalPerson", "user"},
			"sAMAccountName": {fmt.Sprintf("b%s%04d", l.stamp, i)}})
		members = append(members, dn)
	}
	grp := "CN=big," + ou
	l.add(t, grp, map[string][]string{"objectClass": {"top", "group"}, "sAMAccountName": {"t0695g" + l.stamp}})
	for i := 0; i < len(members); i += 400 { // member adds in chunks keep each LDAP modify small
		m := ldap.NewModifyRequest(grp, nil)
		m.Add("member", members[i:min(i+400, len(members))])
		if err := l.adm.Modify(m); err != nil {
			t.Fatalf("members %d: %v", i, err)
		}
	}
	gOU := l.guid(t, ou)

	// >1000 entries over several LDAP pages and many gRPC batches equal the admin query.
	got, done, err := rpc(t, l.client, l.request(gOU, connectorv1.SearchDepth_SEARCH_DEPTH_ONE_LEVEL, "user", "cn"))
	if err != nil || !done {
		t.Fatalf("paged: done=%v err=%v", done, err)
	}
	if len(got) != bulkUsers {
		t.Fatalf("paged search returned %d, want %d", len(got), bulkUsers)
	}
	sameSet(t, "paged", got, l.adminGUIDs(t, ou, ldap.ScopeSingleLevel, "user"))

	// The >1500-member group: first range only, complete=false, and the head is what the DC listed first.
	groups, done, err := rpc(t, l.client, l.request(gOU, connectorv1.SearchDepth_SEARCH_DEPTH_ONE_LEVEL, "group", "member", "cn"))
	if err != nil || !done || len(groups) != 1 {
		t.Fatalf("group: done=%v err=%v n=%d", done, err, len(groups))
	}
	for _, e := range groups {
		var member *connectorv1.Attribute
		for _, a := range e.GetAttributes() {
			if strings.EqualFold(a.GetName(), "member") {
				member = a
			}
		}
		if member == nil {
			t.Fatal("member attribute missing")
		}
		if member.GetComplete() || len(member.GetValues()) != memberCap || member.GetRange().GetEnd() != memberCap-1 {
			t.Fatalf("member: complete=%v n=%d range=%v", member.GetComplete(), len(member.GetValues()), member.GetRange())
		}
		have := map[string]bool{}
		for _, v := range member.GetValues() {
			have[strings.ToLower(v.GetDn().GetDisplayDn())] = true
		}
		if len(have) != memberCap {
			t.Errorf("duplicate member values in first range: %d distinct", len(have))
		}
		for d := range have {
			found := false
			for _, m := range members {
				if strings.EqualFold(m, d) {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("first-range member %q is not a member of the group", d)
			}
		}
	}
}

func TestLabScopedSearchDeletedRootIsDelegationRootGone(t *testing.T) {
	l := newSearchLab(t)
	ou := "OU=t0695x" + l.stamp + "," + labDom
	t.Cleanup(func() { l.delTree(ou) })
	l.add(t, ou, map[string][]string{"objectClass": {"top", "organizationalUnit"}})
	l.add(t, "CN=victim,"+ou, map[string][]string{"objectClass": {"top", "person", "organizationalPerson", "user"},
		"sAMAccountName": {"t0695x" + l.stamp}})
	root := l.guid(t, ou)

	// Alive: the user is found (so the failure below is the deletion, not the request).
	if got, done, err := rpc(t, l.client, l.request(root, connectorv1.SearchDepth_SEARCH_DEPTH_SUBTREE, "user", "cn")); err != nil || !done || len(got) != 1 {
		t.Fatalf("before delete: n=%d done=%v err=%v", len(got), done, err)
	}
	l.delTree(ou)

	// A second, live root in the same request must not rescue the search: no fallback, no partial success.
	live := l.guid(t, "CN=Users,"+labDom)
	r := l.request(root, connectorv1.SearchDepth_SEARCH_DEPTH_SUBTREE, "user", "cn")
	r.Roots = append(r.Roots, &connectorv1.SearchRoot{Guid: live})
	for name, req := range map[string]*connectorv1.ScopedSearchRequest{
		"only root":      l.request(root, connectorv1.SearchDepth_SEARCH_DEPTH_SUBTREE, "user", "cn"),
		"with live root": r,
	} {
		_, done, err := rpc(t, l.client, req)
		if c := code(err); c != connectorv1.ErrorCode_ERROR_CODE_DELEGATION_ROOT_GONE {
			t.Errorf("%s: code %v (err %v)", name, c, err)
		}
		if done {
			t.Errorf("%s: stream ended in SearchCompleted after a gone root", name)
		}
	}
}

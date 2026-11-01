//go:build lab

package read_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	dirsync "github.com/skenzeriq/activediq/internal/directory/sync"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// T-1189: the closed attribute list, requested through the real ScopedSearch handler against Samba, maps
// to observations that agree with an administrator's own LDAP read of the same objects. With
// SYNC_CAPTURE_DIR set the entries are written as protojson, the fixtures directory/sync's golden test reads.
//
//	make lab-up && go test -tags lab ./internal/connector/read -run TestLabSyncMapping
//	SYNC_CAPTURE_DIR=$PWD/internal/directory/sync/testdata/lab go test -tags lab ./internal/connector/read -run TestLabSyncMapping
func TestLabSyncMapping(t *testing.T) {
	l := newSearchLab(t)
	ou := "OU=syncmap-" + l.stamp + "," + labDom
	l.add(t, ou, map[string][]string{"objectClass": {"organizationalUnit"}, "description": {"sync mapping lab"}})
	t.Cleanup(func() { l.delTree(ou) })

	userDN := "CN=Ramán\\, Priya " + l.stamp + "," + ou
	l.add(t, userDN, map[string][]string{"objectClass": {"user"}, "sAMAccountName": {"pr" + l.stamp}, "userPrincipalName": {"pr" + l.stamp + "@lab.activediq.test"},
		"displayName": {"Ramán, Priya"}, "mail": {"priya@lab.activediq.test"}, "servicePrincipalName": {"HTTP/syncmap-" + l.stamp}})
	compDN := "CN=SYNCWS" + l.stamp + "," + ou
	l.add(t, compDN, map[string][]string{"objectClass": {"computer"}, "sAMAccountName": {"SYNCWS" + l.stamp + "$"}, "dNSHostName": {"syncws.lab.activediq.test"},
		"operatingSystem": {"Windows 11 Enterprise"}, "userAccountControl": {"4096"}})
	contactDN := "CN=Vendor " + l.stamp + "," + ou
	l.add(t, contactDN, map[string][]string{"objectClass": {"contact"}, "mail": {"v@vendor.test"}, "company": {"Vendor"}})
	groupDN := "CN=Team " + l.stamp + "," + ou
	l.add(t, groupDN, map[string][]string{"objectClass": {"group"}, "sAMAccountName": {"team" + l.stamp}, "groupType": {"-2147483646"},
		"member": {userDN, compDN, contactDN}})

	m, err := dirsync.NewMapper(dirsync.Config{NC: inventory.GUID(guidText(t, l.guid(t, labDom)))})
	if err != nil {
		t.Fatal(err)
	}
	pull := func(root, class string) *connectorv1.DirectoryEntry {
		t.Helper()
		got, _, err := rpc(t, l.client, l.request(l.guid(t, root), connectorv1.SearchDepth_SEARCH_DEPTH_SUBTREE, class, m.Attributes()...))
		if err != nil {
			t.Fatalf("ScopedSearch %s: %v", class, err)
		}
		var hit *connectorv1.DirectoryEntry
		for _, e := range got {
			if class == "domainDNS" || class == "organizationalUnit" || strings.Contains(e.GetDn().GetDisplayDn(), l.stamp) {
				hit = e
			}
		}
		if hit == nil {
			t.Fatalf("no %s entry", class)
		}
		return hit
	}
	cases := []struct {
		name, root, class string
		kind              inventory.Kind
	}{
		{"user", ou, "user", inventory.KindUser}, {"computer", ou, "computer", inventory.KindComputer},
		{"group", ou, "group", inventory.KindGroup}, {"contact", ou, "contact", inventory.KindContact},
		{"ou", ou, "organizationalUnit", inventory.KindOU}, {"domain", labDom, "domainDNS", inventory.KindOther},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := pull(c.root, c.class)
			if dir := os.Getenv("SYNC_CAPTURE_DIR"); dir != "" {
				b, err := protojson.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(e)
				if err != nil || os.MkdirAll(dir, 0o755) != nil || os.WriteFile(filepath.Join(dir, c.name+".json"), append(b, '\n'), 0o644) != nil {
					t.Fatalf("capture: %v", err)
				}
			}
			got, err := m.Map(e)
			if err != nil {
				t.Fatalf("Map: %v", err)
			}
			o := got.Observation
			if o.Kind != c.kind {
				t.Errorf("kind = %s, want %s", o.Kind, c.kind)
			}
			if o.DN != e.GetDn().GetDisplayDn() && !strings.EqualFold(o.DN, e.GetDn().GetDisplayDn()) {
				t.Errorf("dn = %q, DC said %q", o.DN, e.GetDn().GetDisplayDn())
			}
			if c.name == "group" && (len(o.Members) != 3 || !o.MembersComplete) {
				t.Errorf("group members = %d complete=%v", len(o.Members), o.MembersComplete)
			}
			if c.name == "user" {
				if o.SAMAccountName != "pr"+l.stamp || o.DisplayName != "Ramán, Priya" || len(o.SID) == 0 || o.HasSPN == nil || !*o.HasSPN {
					t.Errorf("user = %+v", o)
				}
				if got := o.RDN; got != `CN=Ramán\, Priya `+l.stamp {
					t.Errorf("rdn = %q", got)
				}
			}
			if c.name == "domain" && (o.Parent != "" || string(o.NC) != string(o.Object)) {
				t.Errorf("domain head: parent=%q nc=%q object=%q", o.Parent, o.NC, o.Object)
			}
		})
	}
}

func guidText(t *testing.T, g *connectorv1.Guid) string {
	t.Helper()
	b := g.GetValue()
	if len(b) != 16 {
		t.Fatal("guid")
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

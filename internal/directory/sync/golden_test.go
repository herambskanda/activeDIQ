package sync_test

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

// T-1189 AC1: the entries in testdata/lab are what the connector's ScopedSearch handler streamed for a
// Samba AD, captured by internal/connector/read TestLabSyncMapping (tag lab, SYNC_CAPTURE_DIR). The
// expectations are read off the entries themselves (the DC's own DN, parent_guid, SID), never typed in, so
// a fixture recaptured with a new stamp still passes while a mapper that fabricates or drops a field fails.

func loadLab(t *testing.T, name string) *connectorv1.DirectoryEntry {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "lab", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	e := &connectorv1.DirectoryEntry{}
	if err := protojson.Unmarshal(b, e); err != nil {
		t.Fatal(err)
	}
	return e
}

// rfcText is the canonical text of a connector Guid (RFC 4122 byte order), derived independently of the mapper.
func rfcText(g *connectorv1.Guid) string {
	b := g.GetValue()
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func sidOf(e *connectorv1.DirectoryEntry) []byte {
	for _, a := range e.GetAttributes() {
		if strings.EqualFold(a.GetName(), "objectSid") && len(a.GetValues()) == 1 {
			return a.GetValues()[0].GetSid().GetValue()
		}
	}
	return nil
}

func Test_lab_entries_map_to_observations_that_agree_with_the_dc(t *testing.T) {
	dom := loadLab(t, "domain")
	m, err := dirsync.NewMapper(dirsync.Config{NC: inventory.GUID(rfcText(dom.GetObjectGuid()))})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		kind  inventory.Kind
		class string
	}{
		{"user", inventory.KindUser, "user"},
		{"computer", inventory.KindComputer, "computer"},
		{"group", inventory.KindGroup, "group"},
		{"ou", inventory.KindOU, "organizationalUnit"},
		{"contact", inventory.KindContact, "contact"},
		{"domain", inventory.KindOther, "domainDNS"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := loadLab(t, c.name)
			got, err := m.Map(e)
			if err != nil {
				t.Fatalf("Map: %v", err)
			}
			o := got.Observation
			if o.Kind != c.kind || o.Class != c.class || o.State != inventory.ObjLive {
				t.Errorf("kind/class/state = %s/%s/%s, want %s/%s/live", o.Kind, o.Class, o.State, c.kind, c.class)
			}
			if string(o.Object) != rfcText(e.GetObjectGuid()) || string(o.NC) != string(inventory.GUID(rfcText(dom.GetObjectGuid()))) {
				t.Errorf("identity = %s in %s", o.Object, o.NC)
			}
			if !strings.EqualFold(o.DN, e.GetDn().GetDisplayDn()) {
				t.Errorf("dn = %q, DC said %q", o.DN, e.GetDn().GetDisplayDn())
			}
			if c.name != "domain" && !strings.HasPrefix(o.DN, o.RDN+",") {
				t.Errorf("rdn %q is not the head of %q", o.RDN, o.DN)
			}
			wantParent := ""
			if e.GetParentGuid() != nil {
				wantParent = rfcText(e.GetParentGuid())
			}
			if string(o.Parent) != wantParent {
				t.Errorf("parent = %q, want %q", o.Parent, wantParent)
			}
			if c.name == "domain" && (o.Parent != "" || o.Object != o.NC) {
				t.Errorf("domain head must be its own NC with no parent: %+v", o)
			}
			if sid := sidOf(e); sid != nil && string(o.SID) != string(sid) {
				t.Errorf("sid differs from the DC's")
			}
			// An attribute the entry does not carry is "not read": nothing fabricated, bit clear.
			if o.LastLogonTimestamp.IsZero() && o.InputsRead&inventory.ReadLastLogonTimestamp != 0 {
				t.Errorf("lastLogonTimestamp bit set for an attribute the DC did not return")
			}
			if o.LockoutTime.IsZero() && o.InputsRead&inventory.ReadLockoutTime != 0 {
				t.Errorf("lockoutTime bit set for an attribute the DC did not return")
			}
		})
	}

	t.Run("user fields", func(t *testing.T) {
		o := mustMap(t, m, loadLab(t, "user")).Observation
		if !strings.HasPrefix(o.RDN, `CN=Ramán\, Priya `) || strings.Contains(o.RDN, ",OU=") {
			t.Errorf("rdn = %q: the comma in the CN must stay escaped and the parent out", o.RDN)
		}
		if o.SAMAccountName == "" || !strings.HasSuffix(o.UPN, "@lab.activediq.test") || o.DisplayName != "Ramán, Priya" {
			t.Errorf("names = %q %q %q", o.SAMAccountName, o.UPN, o.DisplayName)
		}
		// Samba stores a password-less LDAP-added user as UAC 546 (ACCOUNTDISABLE set): disabled is the DC's truth.
		if o.UserAccountControl == nil || *o.UserAccountControl != 546 || o.Enabled == nil || *o.Enabled {
			t.Errorf("uac=%v enabled=%v, want 546 and disabled", o.UserAccountControl, o.Enabled)
		}
		if o.HasSPN == nil || !*o.HasSPN {
			t.Errorf("hasSPN = %v", o.HasSPN)
		}
		if o.InputsRead&inventory.ReadPwdLastSet == 0 || o.InputsRead&inventory.ReadAccountExpires == 0 {
			t.Errorf("inputs read = %b", o.InputsRead)
		}
		if o.InputsRead&inventory.ReadLockoutTime != 0 {
			t.Errorf("a never-locked user has no lockoutTime on the wire: it is not read, not zero-and-read")
		}
	})
	t.Run("computer fields", func(t *testing.T) {
		o := mustMap(t, m, loadLab(t, "computer")).Observation
		if !strings.HasSuffix(o.SAMAccountName, "$") || o.Attributes["dNSHostName"] != "syncws.lab.activediq.test" {
			t.Errorf("computer = %q %v", o.SAMAccountName, o.Attributes)
		}
	})
	t.Run("group members without guids are never an edge set", func(t *testing.T) {
		// The connector today sends member DNs without DnValue.guid, so the mapper names none and
		// declares the set incomplete: absence of an edge can then never remove a real one.
		got := mustMap(t, m, loadLab(t, "group"))
		if len(got.Observation.Members) != 0 || got.Observation.MembersComplete || got.MembersUnresolved != 3 {
			t.Errorf("members=%d complete=%v unresolved=%d", len(got.Observation.Members), got.Observation.MembersComplete, got.MembersUnresolved)
		}
	})
}

package sync_test

import (
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	dirsync "github.com/skenzeriq/activediq/internal/directory/sync"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

var (
	created = time.Date(2024, 3, 1, 8, 30, 0, 0, time.UTC)
	logon   = time.Date(2026, 10, 20, 7, 0, 0, 0, time.UTC)
	pwdSet  = time.Date(2026, 9, 1, 7, 0, 0, 0, time.UTC)
)

func eq[T comparable](t *testing.T, what string, got, want T) {
	t.Helper()
	if got != want {
		t.Errorf("%s = %v, want %v", what, got, want)
	}
}

func mustMap(t *testing.T, m *dirsync.Mapper, e *connectorv1.DirectoryEntry) dirsync.Mapped {
	t.Helper()
	got, err := m.Map(e)
	if err != nil {
		t.Fatalf("Map: %v", err)
	}
	return got
}

// AC1: one entry per kind maps to the right Kind, Class, GUID, parent, DN, RDN, names, SID and state.
func Test_map_one_entry_per_kind(t *testing.T) {
	nc := gtext(domainNC)
	tests := []struct {
		name  string
		entry *connectorv1.DirectoryEntry
		want  func(t *testing.T, o inventory.Observation)
	}{
		{"user", entry(10, `CN=Raman\, Priya,OU=Staff,DC=lab,DC=test`, gid(ouGUID),
			attrs(nil).classes("top", "person", "organizationalPerson", "user").
				with("sAMAccountName", txt("praman")).with("userPrincipalName", txt("priya@lab.test")).
				with("displayName", txt("Raman, Priya")).with("mail", txt("priya@lab.test")).
				with("objectSid", sidv(domSID(1105))).with("userAccountControl", i32(0x202)).
				with("primaryGroupID", i32(513)).gentime("whenCreated", created).gentime("whenChanged", logon)),
			func(t *testing.T, o inventory.Observation) {
				eq(t, "kind", o.Kind, inventory.KindUser)
				eq(t, "class", o.Class, "user")
				eq(t, "guid", string(o.Object), gtext(10))
				eq(t, "parent", string(o.Parent), gtext(ouGUID))
				eq(t, "dn", o.DN, `CN=Raman\, Priya,OU=Staff,DC=lab,DC=test`)
				eq(t, "rdn", o.RDN, `CN=Raman\, Priya`)
				eq(t, "sam", o.SAMAccountName, "praman")
				eq(t, "upn", o.UPN, "priya@lab.test")
				eq(t, "display", o.DisplayName, "Raman, Priya")
				eq(t, "sid", string(o.SID), string(sidBytes(1105)))
				eq(t, "nc", string(o.NC), nc)
				eq(t, "state", o.State, inventory.ObjLive)
				eq(t, "mail", o.Attributes["mail"], any("priya@lab.test"))
				if o.Enabled == nil || *o.Enabled { // 0x202 = NORMAL_ACCOUNT | ACCOUNTDISABLE
					t.Errorf("Enabled = %v, want false", o.Enabled)
				}
				if o.UserAccountControl == nil || *o.UserAccountControl != 0x202 || o.PrimaryGroupID == nil || *o.PrimaryGroupID != 513 {
					t.Errorf("uac/primaryGroupID = %v/%v", o.UserAccountControl, o.PrimaryGroupID)
				}
				if !o.WhenCreated.Equal(created) || !o.WhenChanged.Equal(logon) {
					t.Errorf("whenCreated/whenChanged = %v/%v", o.WhenCreated, o.WhenChanged)
				}
				eq(t, "ancestry hops", len(o.Ancestry), 0) // a grandchild's chain needs the parent's: the caller's
			}},
		{"computer", entry(11, "CN=WS-0042,CN=Computers,DC=lab,DC=test", gid(domainNC),
			attrs(nil).classes("top", "person", "organizationalPerson", "user", "computer").
				with("sAMAccountName", txt("WS-0042$")).with("dNSHostName", txt("ws-0042.lab.test")).
				with("operatingSystem", txt("Windows 11 Enterprise")).with("userAccountControl", i32(0x1000)).
				with("msDS-AllowedToDelegateTo", dnv("CN=SQL,DC=lab,DC=test", nil), txt("cifs/files.lab.test")).
				with("objectSid", sidv(domSID(1200)))),
			func(t *testing.T, o inventory.Observation) {
				eq(t, "kind", o.Kind, inventory.KindComputer) // computer inherits user: the more derived class wins
				eq(t, "class", o.Class, "computer")
				eq(t, "rdn", o.RDN, "CN=WS-0042")
				eq(t, "dns", o.Attributes["dNSHostName"], any("ws-0042.lab.test"))
				if o.Enabled == nil || !*o.Enabled {
					t.Errorf("Enabled = %v, want true", o.Enabled)
				}
				if got := o.Attributes["msDS-AllowedToDelegateTo"].([]string); len(got) != 2 {
					t.Errorf("delegation targets = %v", got)
				}
				eq(t, "first hop", len(o.Ancestry), 1) // a child of the NC head: the one chain needing no lookup
				eq(t, "first hop guid", string(o.Ancestry[0]), nc)
			}},
		{"group", entry(12, "CN=Helpdesk,OU=Groups,DC=lab,DC=test", gid(ouGUID),
			attrs(nil).classes("top", "group").with("sAMAccountName", txt("Helpdesk")).
				with("groupType", i32(-2147483646)).with("objectSid", sidv(domSID(1300))).
				with("managedBy", dnv("CN=Raman\\, Priya,OU=Staff,DC=lab,DC=test", gid(10)))),
			func(t *testing.T, o inventory.Observation) {
				eq(t, "kind", o.Kind, inventory.KindGroup)
				eq(t, "class", o.Class, "group")
				if o.Facts.GroupType == nil || *o.Facts.GroupType != -2147483646 { // the sign survives (security group)
					t.Errorf("GroupType = %v", o.Facts.GroupType)
				}
				eq(t, "managedBy", o.Attributes["managedBy"], any(`CN=Raman\, Priya,OU=Staff,DC=lab,DC=test`))
				if _, bad := o.Attributes["groupType"]; bad {
					t.Error("groupType is a judge key: it enters through Facts only")
				}
				if o.Enabled != nil || o.UserAccountControl != nil {
					t.Error("a group has no account state")
				}
			}},
		{"ou", entry(ouGUID, "OU=Staff,DC=lab,DC=test", gid(domainNC),
			attrs(nil).classes("top", "organizationalUnit").with("description", txt("Staff accounts"), txt("second"))),
			func(t *testing.T, o inventory.Observation) {
				eq(t, "kind", o.Kind, inventory.KindOU)
				eq(t, "class", o.Class, "organizationalUnit")
				eq(t, "rdn", o.RDN, "OU=Staff")
				eq(t, "description", o.Attributes["description"], any("Staff accounts"))
			}},
		{"contact", entry(13, "CN=Vendor Contact,OU=Staff,DC=lab,DC=test", gid(ouGUID),
			attrs(nil).classes("top", "person", "organizationalPerson", "contact").with("mail", txt("v@vendor.test")).
				with("company", txt("Vendor"))),
			func(t *testing.T, o inventory.Observation) {
				eq(t, "kind", o.Kind, inventory.KindContact)
				eq(t, "class", o.Class, "contact")
				eq(t, "company", o.Attributes["company"], any("Vendor"))
				eq(t, "inputs", o.InputsRead, inventory.InputsRead(0))
			}},
		{"domain head", entry(domainNC, "DC=lab,DC=test", nil,
			attrs(nil).classes("top", "domain", "domainDNS").with("objectSid", sidv(domainSID()))),
			func(t *testing.T, o inventory.Observation) {
				eq(t, "kind", o.Kind, inventory.KindOther) // DM-16 carries any other class as data
				eq(t, "class", o.Class, "domainDNS")
				eq(t, "parent", string(o.Parent), "")
				eq(t, "nc", string(o.NC), string(o.Object)) // the head is its own naming context
				eq(t, "rdn", o.RDN, "DC=lab")
				eq(t, "ancestry", len(o.Ancestry), 0)
			}},
	}
	m := mapper(dirsync.Config{})
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) { tc.want(t, mustMap(t, m, tc.entry).Observation) })
	}
}

// AC1: the time inputs set an InputsRead bit only for inputs that were requested and present; an absent
// attribute is not read (zero, bit clear), never a fabricated value; present-with-no-value is read and empty.
func Test_time_inputs_are_tri_state(t *testing.T) {
	user := func(a attrs) *connectorv1.DirectoryEntry {
		return entry(20, "CN=U,OU=Staff,DC=lab,DC=test", gid(ouGUID),
			a.classes("top", "person", "organizationalPerson", "user").with("userAccountControl", i32(0x200)))
	}
	all := inventory.ReadLockoutTime | inventory.ReadPwdLastSet | inventory.ReadAccountExpires | inventory.ReadLastLogonTimestamp

	t.Run("present", func(t *testing.T) {
		o := mustMap(t, mapper(dirsync.Config{}), user(attrs(nil).with("lockoutTime", at(logon)).with("pwdLastSet", at(pwdSet)).
			with("accountExpires", at(logon.Add(24*time.Hour))).with("lastLogonTimestamp", at(logon)))).Observation
		eq(t, "inputs", o.InputsRead, all)
		if !o.LockoutTime.Equal(logon) || !o.PwdLastSet.Equal(pwdSet) || !o.AccountExpires.Equal(logon.Add(24*time.Hour)) || !o.LastLogonTimestamp.Equal(logon) {
			t.Errorf("times = %v %v %v %v", o.LockoutTime, o.PwdLastSet, o.AccountExpires, o.LastLogonTimestamp)
		}
	})
	t.Run("absent is not read", func(t *testing.T) {
		o := mustMap(t, mapper(dirsync.Config{}), user(nil)).Observation
		eq(t, "inputs", o.InputsRead, inventory.InputsRead(0))
		if !o.LockoutTime.IsZero() || !o.PwdLastSet.IsZero() || !o.AccountExpires.IsZero() || !o.LastLogonTimestamp.IsZero() || o.HasSPN != nil {
			t.Error("an absent attribute produced a value")
		}
	})
	t.Run("not requested is not read even when the entry carries it", func(t *testing.T) {
		m := mapper(dirsync.Config{Requested: []string{"objectClass", "userAccountControl", "lockoutTime"}})
		o := mustMap(t, m, user(attrs(nil).with("lockoutTime", at(logon)).with("pwdLastSet", at(pwdSet)).with("servicePrincipalName", txt("HTTP/x")))).Observation
		eq(t, "inputs", o.InputsRead, inventory.ReadLockoutTime)
		if !o.PwdLastSet.IsZero() || o.HasSPN != nil {
			t.Error("an attribute that was not requested leaked into the observation")
		}
	})
	t.Run("zero and never", func(t *testing.T) {
		zero, max := sentinel(connectorv1.TimeSentinel_TIME_SENTINEL_ZERO), sentinel(connectorv1.TimeSentinel_TIME_SENTINEL_MAX)
		o := mustMap(t, mapper(dirsync.Config{}), user(attrs(nil).with("lockoutTime", zero).with("pwdLastSet", zero).with("accountExpires", max))).Observation
		eq(t, "inputs", o.InputsRead, inventory.ReadLockoutTime|inventory.ReadPwdLastSet|inventory.ReadAccountExpires)
		if !o.LockoutTime.IsZero() || !o.PwdLastSet.IsZero() || !o.AccountExpires.IsZero() {
			t.Error("0 and MAX are 'no time' with the bit set")
		}
		o = mustMap(t, mapper(dirsync.Config{}), user(attrs(nil).with("accountExpires", zero))).Observation
		eq(t, "accountExpires 0 is never too", o.InputsRead, inventory.ReadAccountExpires)
	})
	t.Run("present with no value is read and empty", func(t *testing.T) {
		o := mustMap(t, mapper(dirsync.Config{}), user(attrs(nil).with("lockoutTime").with("servicePrincipalName"))).Observation
		eq(t, "inputs", o.InputsRead, inventory.ReadLockoutTime)
		if o.HasSPN == nil || *o.HasSPN {
			t.Errorf("HasSPN = %v, want false (read, none)", o.HasSPN)
		}
	})
	t.Run("MAX is only a way of saying never for accountExpires", func(t *testing.T) {
		_, err := mapper(dirsync.Config{}).Map(user(attrs(nil).with("pwdLastSet", sentinel(connectorv1.TimeSentinel_TIME_SENTINEL_MAX))))
		wantMalformed(t, err, "pwdLastSet", dirsync.CodeBadTime)
	})
	t.Run("spn", func(t *testing.T) {
		o := mustMap(t, mapper(dirsync.Config{}), user(attrs(nil).with("servicePrincipalName", txt("HTTP/a"), txt("HTTP/b")))).Observation
		if o.HasSPN == nil || !*o.HasSPN {
			t.Errorf("HasSPN = %v, want true", o.HasSPN)
		}
		// T-1129: the values are stored for search, bounded (the first 64).
		if got, _ := o.Attributes["servicePrincipalName"].([]string); len(got) != 2 || got[0] != "HTTP/a" {
			t.Errorf("SPN values = %v", o.Attributes["servicePrincipalName"])
		}
	})
}

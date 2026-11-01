package sync_test

import (
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	dirsync "github.com/skenzeriq/activediq/internal/directory/sync"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

func groupEntry(a attrs) *connectorv1.DirectoryEntry {
	return entry(30, "CN=Team,OU=Groups,DC=lab,DC=test", gid(ouGUID), a.classes("top", "group").with("groupType", i32(-2147483646)))
}

func members(from, to uint64) []*connectorv1.AttributeValue {
	var vs []*connectorv1.AttributeValue
	for n := from; n <= to; n++ {
		vs = append(vs, dnv("CN=m,DC=lab,DC=test", gid(n)))
	}
	return vs
}

// AC2: Members are the DnValue GUIDs; MembersComplete only when the entry carries the whole set.
func Test_members_and_completeness(t *testing.T) {
	m := mapper(dirsync.Config{})
	t.Run("three members, whole set", func(t *testing.T) {
		got := mustMap(t, m, groupEntry(attrs(nil).with("member", members(100, 102)...)))
		o := got.Observation
		if len(o.Members) != 3 || string(o.Members[0]) != gtext(100) || string(o.Members[2]) != gtext(102) || !o.MembersComplete {
			t.Errorf("members = %v complete=%v", o.Members, o.MembersComplete)
		}
	})
	t.Run("a ranged slice is not complete", func(t *testing.T) {
		a := attrs(nil).with("member", members(100, 102)...)
		a[len(a)-1].Complete = false
		a[len(a)-1].Range = &connectorv1.ValueRange{Start: 0, End: 2}
		o := mustMap(t, m, groupEntry(a)).Observation
		if len(o.Members) != 3 || o.MembersComplete {
			t.Errorf("members = %d complete=%v: a slice must not let absent members be removed", len(o.Members), o.MembersComplete)
		}
	})
	t.Run("a range that is the whole set is complete", func(t *testing.T) {
		a := attrs(nil).with("member", members(100, 101)...)
		a[len(a)-1].Range = &connectorv1.ValueRange{Start: 0, End: 1, Terminal: true}
		if !mustMap(t, m, groupEntry(a)).Observation.MembersComplete {
			t.Error("0-* is the whole set")
		}
	})
	t.Run("a member value without a GUID makes the set incomplete", func(t *testing.T) {
		got := mustMap(t, m, groupEntry(attrs(nil).with("member", append(members(100, 101), dnv("CN=x,DC=lab,DC=test", nil))...)))
		eq(t, "unresolved", got.MembersUnresolved, 1)
		if got.Observation.MembersComplete || len(got.Observation.Members) != 2 {
			t.Errorf("members=%d complete=%v", len(got.Observation.Members), got.Observation.MembersComplete)
		}
	})
	t.Run("an empty group that was read is complete and empty", func(t *testing.T) {
		o := mustMap(t, m, groupEntry(attrs(nil).with("member"))).Observation
		if len(o.Members) != 0 || !o.MembersComplete {
			t.Errorf("members=%v complete=%v", o.Members, o.MembersComplete)
		}
	})
	t.Run("member not on the entry is not read", func(t *testing.T) {
		o := mustMap(t, m, groupEntry(nil)).Observation
		if len(o.Members) != 0 || o.MembersComplete {
			t.Errorf("members=%v complete=%v: nothing may be removed on a group whose members were not read", o.Members, o.MembersComplete)
		}
	})
	t.Run("duplicates are one edge", func(t *testing.T) {
		o := mustMap(t, m, groupEntry(attrs(nil).with("member", append(members(100, 101), members(100, 100)...)...))).Observation
		eq(t, "members", len(o.Members), 2)
	})
	t.Run("members of a non-group are ignored", func(t *testing.T) {
		e := entry(31, "CN=u,OU=Staff,DC=lab,DC=test", gid(ouGUID), attrs(nil).classes("top", "user").with("member", members(100, 100)...))
		if o := mustMap(t, m, e).Observation; len(o.Members) != 0 || o.MembersComplete {
			t.Error("a user has no member edges")
		}
	})
	t.Run("a 50 000-member group is mapped whole", func(t *testing.T) {
		o := mustMap(t, m, groupEntry(attrs(nil).with("member", members(1000, 51000)...))).Observation
		if len(o.Members) != 50001 || !o.MembersComplete {
			t.Errorf("members=%d complete=%v", len(o.Members), o.MembersComplete)
		}
	})
}

// AC2: primaryGroupID resolves to a group GUID of the same domain, or is left zero with a reason.
func Test_primary_group(t *testing.T) {
	idx := dirsync.NewGroupIndex()
	idx.Add(sidBytes(513), inventory.GUID(gtext(900)))
	user := func(a attrs) *connectorv1.DirectoryEntry {
		return entry(40, "CN=U,OU=Staff,DC=lab,DC=test", gid(ouGUID), a.classes("top", "user").with("userAccountControl", i32(0x200)))
	}
	withRID := func(n int32) attrs {
		return attrs(nil).with("objectSid", sidv(domSID(1105))).with("primaryGroupID", i32(n))
	}

	tests := []struct {
		name   string
		m      *dirsync.Mapper
		entry  *connectorv1.DirectoryEntry
		status dirsync.PrimaryGroupStatus
		group  string
	}{
		{"resolved", mapper(dirsync.Config{Groups: idx}), user(withRID(513)), dirsync.PrimaryGroupResolved, gtext(900)},
		{"unresolved: no such group in the domain", mapper(dirsync.Config{Groups: idx}), user(withRID(514)), dirsync.PrimaryGroupUnresolved, ""},
		{"primaryGroupID not read", mapper(dirsync.Config{Groups: idx}), user(attrs(nil).with("objectSid", sidv(domSID(1105)))), dirsync.PrimaryGroupNotRead, ""},
		{"objectSid not read", mapper(dirsync.Config{Groups: idx}), user(attrs(nil).with("primaryGroupID", i32(513))), dirsync.PrimaryGroupNoSID, ""},
		{"no resolver", mapper(dirsync.Config{}), user(withRID(513)), dirsync.PrimaryGroupNoResolver, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := mustMap(t, tc.m, tc.entry)
			eq(t, "status", got.PrimaryGroup, tc.status)
			eq(t, "group", string(got.Observation.PrimaryGroup), tc.group)
			if got.Observation.PrimaryGroupID == nil && tc.status != dirsync.PrimaryGroupNotRead {
				t.Error("primaryGroupID itself is still recorded")
			}
		})
	}
	t.Run("a group from another domain never resolves a RID of this one", func(t *testing.T) {
		other := dirsync.NewGroupIndex()
		other.Add(append([]byte{1, 5, 0, 0, 0, 0, 0, 5}, make([]byte, 20)...), inventory.GUID(gtext(901)))
		got := mustMap(t, mapper(dirsync.Config{Groups: other}), user(withRID(513)))
		eq(t, "status", got.PrimaryGroup, dirsync.PrimaryGroupUnresolved)
	})
}

// AC4: a deleted or recycled entry keeps its GUID and lastKnownParent, not the Deleted Objects container.
func Test_deleted_and_recycled(t *testing.T) {
	deletedObjects := gid(500)
	lkp := dnv("OU=Staff,DC=lab,DC=test", gid(ouGUID))
	m := mapper(dirsync.Config{})
	deletedDN := "CN=Raman\\0ADEL:" + gtext(50) + ",CN=Deleted Objects,DC=lab,DC=test"

	t.Run("deleted", func(t *testing.T) {
		e := entry(50, deletedDN, deletedObjects,
			attrs(nil).classes("top", "person", "organizationalPerson", "user").with("isDeleted", boolean(true)).
				with("lastKnownParent", lkp).with("sAMAccountName", txt("praman")).with("userAccountControl", i32(0x200)).
				with("pwdLastSet", at(pwdSet)))
		o := mustMap(t, m, e).Observation
		eq(t, "state", o.State, inventory.ObjDeleted)
		eq(t, "guid", string(o.Object), gtext(50))
		eq(t, "parent", string(o.Parent), gtext(ouGUID))
		eq(t, "kind", o.Kind, inventory.KindUser)
		eq(t, "lastKnownParent kept", o.Attributes["lastKnownParent"], any("OU=Staff,DC=lab,DC=test"))
		eq(t, "ancestry (a chain is the caller's)", len(o.Ancestry), 0)
		if o.InputsRead != 0 || o.UserAccountControl != nil || o.Enabled != nil {
			t.Error("a tombstone's account-state inputs are not state")
		}
	})
	t.Run("recycled with nothing else", func(t *testing.T) {
		e := entry(51, "CN=Gone\\0ADEL:"+gtext(51)+",CN=Deleted Objects,DC=lab,DC=test", deletedObjects,
			attrs(nil).with("isDeleted", boolean(true)).with("isRecycled", boolean(true)).with("lastKnownParent", lkp))
		o := mustMap(t, m, e).Observation
		eq(t, "state", o.State, inventory.ObjRecycled)
		eq(t, "parent", string(o.Parent), gtext(ouGUID))
		eq(t, "kind", o.Kind, inventory.KindOther)
		eq(t, "class", o.Class, "top")
	})
	t.Run("no lastKnownParent GUID leaves no parent, never the container", func(t *testing.T) {
		e := entry(52, deletedDN, deletedObjects, attrs(nil).classes("top", "group").with("isDeleted", boolean(true)))
		o := mustMap(t, m, e).Observation
		eq(t, "parent", string(o.Parent), "")
		eq(t, "state", o.State, inventory.ObjDeleted)
	})
	t.Run("a live entry without objectClass is refused", func(t *testing.T) {
		_, err := m.Map(entry(53, "CN=x,DC=lab,DC=test", gid(ouGUID), nil))
		wantMalformed(t, err, "objectClass", dirsync.CodeMissing)
	})
	t.Run("a live entry without a parent must be the NC head", func(t *testing.T) {
		_, err := m.Map(entry(54, "CN=x,DC=lab,DC=test", nil, attrs(nil).classes("top", "user")))
		wantMalformed(t, err, "parentGuid", dirsync.CodeNCHead)
	})
}

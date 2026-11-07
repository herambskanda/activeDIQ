package sync_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	dirsync "github.com/skenzeriq/activediq/internal/directory/sync"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

func octets(b []byte) *connectorv1.AttributeValue {
	return &connectorv1.AttributeValue{Value: &connectorv1.AttributeValue_Octets{Octets: b}}
}

// canary is in every malformed value below: no error may carry it.
const canary = "CANARY-VALUE-7731"

// AC5: a malformed value refuses the entry with an error that names the attribute and never echoes the value.
func Test_malformed_values_are_refused_without_echo(t *testing.T) {
	user := func(a attrs) *connectorv1.DirectoryEntry {
		return entry(70, "CN=U,OU=Staff,DC=lab,DC=test", gid(ouGUID), a.classes("top", "person", "organizationalPerson", "user"))
	}
	bigDN := "CN=" + strings.Repeat("a", 5000) + ",DC=lab,DC=test"
	tests := []struct {
		name  string
		entry *connectorv1.DirectoryEntry
		attr  string
		code  dirsync.Code
	}{
		{"uac of the wrong type", user(attrs(nil).with("userAccountControl", txt(canary))), "userAccountControl", dirsync.CodeType},
		{"sid of the wrong type", user(attrs(nil).with("objectSid", txt(canary))), "objectSid", dirsync.CodeType},
		{"sid truncated", user(attrs(nil).with("objectSid", sidv(&connectorv1.Sid{Value: []byte(canary)}))), "objectSid", dirsync.CodeBadSID},
		{"sid with trailing bytes", user(attrs(nil).with("objectSid", sidv(&connectorv1.Sid{Value: append(sidBytes(1), 0)}))), "objectSid", dirsync.CodeBadSID},
		{"sid empty", user(attrs(nil).with("objectSid", sidv(&connectorv1.Sid{}))), "objectSid", dirsync.CodeBadSID},
		{"sam twice", user(attrs(nil).with("sAMAccountName", txt(canary), txt(canary))), "sAMAccountName", dirsync.CodeMultiValued},
		{"sam with NUL", user(attrs(nil).with("sAMAccountName", txt("a\x00"+canary))), "sAMAccountName", dirsync.CodeBadText},
		{"sam not UTF-8", user(attrs(nil).with("sAMAccountName", txt("\xff\xfe"+canary))), "sAMAccountName", dirsync.CodeBadText},
		{"sam too long", user(attrs(nil).with("sAMAccountName", txt(strings.Repeat(canary, 30)))), "sAMAccountName", dirsync.CodeTooLong},
		{"duplicate attribute", user(attrs(nil).with("mail", txt(canary)).with("MAIL", txt(canary))), "mail", dirsync.CodeDuplicate},
		{"primaryGroupID negative", user(attrs(nil).with("primaryGroupID", i32(-1))), "primaryGroupID", dirsync.CodeRange},
		{"lockoutTime a string", user(attrs(nil).with("lockoutTime", txt(canary))), "lockoutTime", dirsync.CodeType},
		{"pwdLastSet before 1601", user(attrs(nil).with("pwdLastSet", at(created.AddDate(-500, 0, 0)))), "pwdLastSet", dirsync.CodeBadTime},
		{"whenCreated a sentinel", user(attrs(nil).with("whenCreated", sentinel(connectorv1.TimeSentinel_TIME_SENTINEL_ZERO))), "whenCreated", dirsync.CodeBadTime},
		{"consistency guid short", user(attrs(nil).with("mS-DS-ConsistencyGuid", octets([]byte(canary)))), "mS-DS-ConsistencyGuid", dirsync.CodeBadGUID},
		{"consistency guid nil", user(attrs(nil).with("mS-DS-ConsistencyGuid", octets(make([]byte, 16)))), "mS-DS-ConsistencyGuid", dirsync.CodeBadGUID},
		{"objectClass too long", entry(70, "CN=U,DC=lab,DC=test", gid(ouGUID), attrs(nil).classes(strings.Repeat("c", 101))), "objectClass", dirsync.CodeTooLong},
		{"object guid of the wrong length", &connectorv1.DirectoryEntry{ObjectGuid: &connectorv1.Guid{Value: []byte(canary)},
			Dn: &connectorv1.DnValue{DisplayDn: "CN=U,DC=lab,DC=test"}, ParentGuid: gid(ouGUID)}, "objectGUID", dirsync.CodeBadGUID},
		{"object guid nil", &connectorv1.DirectoryEntry{ObjectGuid: &connectorv1.Guid{Value: make([]byte, 16)},
			Dn: &connectorv1.DnValue{DisplayDn: "CN=U,DC=lab,DC=test"}, ParentGuid: gid(ouGUID)}, "objectGUID", dirsync.CodeBadGUID},
		{"object guid absent", &connectorv1.DirectoryEntry{Dn: &connectorv1.DnValue{DisplayDn: "CN=U,DC=lab,DC=test"}, ParentGuid: gid(ouGUID)}, "objectGUID", dirsync.CodeBadGUID},
		{"parent guid wrong length", &connectorv1.DirectoryEntry{ObjectGuid: gid(70), ParentGuid: &connectorv1.Guid{Value: []byte(canary)},
			Dn: &connectorv1.DnValue{DisplayDn: "CN=U,DC=lab,DC=test"}, Attributes: attrs(nil).classes("user")}, "parentGuid", dirsync.CodeBadGUID},
		{"dn missing", entry(70, "", gid(ouGUID), attrs(nil).classes("user")), "dn", dirsync.CodeMissing},
		{"dn malformed", entry(70, "CN=a,,"+canary, gid(ouGUID), attrs(nil).classes("user")), "dn", dirsync.CodeBadDN},
		{"dn with an unescaped comma in a value", entry(70, "CN=Raman, Priya"+canary+"=x,DC=lab", gid(ouGUID), attrs(nil).classes("user")), "dn", dirsync.CodeBadDN},
		{"dn too long", entry(70, bigDN, gid(ouGUID), attrs(nil).classes("user")), "dn", dirsync.CodeTooLong},
		{"own parent", entry(70, "CN=U,DC=lab,DC=test", gid(70), attrs(nil).classes("user")), "parentGuid", dirsync.CodeBadGUID},
		{"member of the wrong type", groupEntry(attrs(nil).with("member", txt(canary))), "member", dirsync.CodeType},
		{"member guid short", groupEntry(attrs(nil).with("member", dnv("CN=x,DC=lab", &connectorv1.Guid{Value: []byte(canary)}))), "member", dirsync.CodeBadGUID},
		{"group that is its own member", groupEntry(attrs(nil).with("member", dnv("CN=Team,OU=Groups,DC=lab,DC=test", gid(30)))), "member", dirsync.CodeBadGUID},
		{"groupType a string", entry(30, "CN=Team,OU=Groups,DC=lab,DC=test", gid(ouGUID), attrs(nil).classes("top", "group").with("groupType", txt(canary))), "groupType", dirsync.CodeType},
		{"managedBy a string", groupEntry(attrs(nil).with("managedBy", txt(canary))), "managedBy", dirsync.CodeType},
		{"attribute bag too large", user(attrs(nil).with("msDS-AllowedToDelegateTo", func() []*connectorv1.AttributeValue {
			var vs []*connectorv1.AttributeValue
			for i := 0; i < 100; i++ {
				vs = append(vs, txt(strings.Repeat("x", 1000)))
			}
			return vs
		}()...)), "attributes", dirsync.CodeAttributesSize},
	}
	m := mapper(dirsync.Config{})
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := m.Map(tc.entry)
			wantMalformed(t, err, tc.attr, tc.code)
			if strings.Contains(err.Error(), "CANARY") || strings.Contains(err.Error(), "aaaa") {
				t.Errorf("the error echoes the value: %q", err.Error())
			}
		})
	}
	t.Run("a nil entry", func(t *testing.T) {
		_, err := m.Map(nil)
		if !errors.Is(err, dirsync.ErrMalformed) {
			t.Errorf("err = %v", err)
		}
	})
}

// A refused entry does not stop the batch: the caller counts the typed error and carries on.
func Test_a_refused_entry_does_not_abort_the_batch(t *testing.T) {
	m := mapper(dirsync.Config{})
	entries := []*connectorv1.DirectoryEntry{
		entry(80, "CN=A,OU=Staff,DC=lab,DC=test", gid(ouGUID), attrs(nil).classes("top", "user")),
		entry(81, "CN=B,OU=Staff,DC=lab,DC=test", gid(ouGUID), attrs(nil).classes("top", "user").with("objectSid", sidv(&connectorv1.Sid{Value: []byte{1}}))),
		entry(82, "CN=C,OU=Staff,DC=lab,DC=test", gid(ouGUID), attrs(nil).classes("top", "user")),
	}
	var ok int
	refused := map[string]int{}
	for _, e := range entries {
		if _, err := m.Map(e); err != nil {
			var se *dirsync.Error
			if !errors.As(err, &se) {
				t.Fatalf("untyped error %v", err)
			}
			refused[se.Attr+"/"+string(se.Code)]++
			continue
		}
		ok++
	}
	if ok != 2 || refused["objectSid/bad_sid"] != 1 {
		t.Errorf("ok=%d refused=%v", ok, refused)
	}
}

// The GUID the connector sends is in RFC 4122 order (the order of the canonical text), not LDAP wire order.
func Test_guid_is_canonical_text_of_the_rfc_bytes(t *testing.T) {
	g := &connectorv1.Guid{Value: []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}}
	e := &connectorv1.DirectoryEntry{ObjectGuid: g, ParentGuid: gid(ouGUID), Dn: &connectorv1.DnValue{DisplayDn: "CN=U,DC=lab,DC=test"},
		Attributes: attrs(nil).classes("top", "user")}
	o := mustMap(t, mapper(dirsync.Config{}), e).Observation
	eq(t, "object", string(o.Object), "00112233-4455-6677-8899-aabbccddeeff")
}

// Whatever the directory sends, an Observation the mapper returns satisfies the bounds the store holds
// (so one hostile entry can never fail a Populate batch), and the mapper never panics.
func Fuzz_map_never_panics_and_respects_store_bounds(f *testing.F) {
	f.Add([]byte(canary), int32(0x202), "CN=U,DC=lab,DC=test", int64(1))
	f.Add([]byte{1, 1, 0, 0, 0, 0, 0, 5, 1, 0, 0, 0}, int32(-1), "CN=a\\,b,OU=x", int64(1<<40))
	f.Add([]byte{}, int32(0), "", int64(-1))
	m := mapper(dirsync.Config{Groups: dirsync.NewGroupIndex()})
	f.Fuzz(func(t *testing.T, raw []byte, n int32, dn string, secs int64) {
		e := &connectorv1.DirectoryEntry{ObjectGuid: &connectorv1.Guid{Value: raw}, ParentGuid: &connectorv1.Guid{Value: raw}, Dn: &connectorv1.DnValue{DisplayDn: dn},
			Attributes: attrs(nil).classes("user", dn).with("objectSid", sidv(&connectorv1.Sid{Value: raw})).with("userAccountControl", i32(n)).
				with("primaryGroupID", i32(n)).with("sAMAccountName", txt(dn)).with("member", dnv(dn, &connectorv1.Guid{Value: raw})).
				with("pwdLastSet", &connectorv1.AttributeValue{Value: &connectorv1.AttributeValue_Time{Time: &connectorv1.TimeValue{
					Kind: &connectorv1.TimeValue_FiletimeTicksOutOfRange{FiletimeTicksOutOfRange: secs}}}})}
		got, err := m.Map(e)
		if err != nil {
			var se *dirsync.Error
			if !errors.As(err, &se) || strings.Contains(err.Error(), dn) && len(dn) > 3 {
				t.Fatalf("untyped or echoing error %q", err)
			}
			return
		}
		o := got.Observation
		if len(o.DN) > 4096 || len(o.RDN) > 1024 || len(o.SAMAccountName) > 256 || len(o.Class) > 100 || strings.ContainsRune(o.DN+o.RDN+o.SAMAccountName+o.Class, 0) {
			t.Fatalf("observation outside the store's bounds")
		}
		if o.Kind != inventory.KindGroup && (len(o.Members) > 0 || o.MembersComplete) {
			t.Fatalf("members on a non-group")
		}
	})
}

// T-1250: a bound is the schema's rangeUpper in characters, not bytes. A value at the rangeUpper that a
// non-admin may write (a computer's creator writes sAMAccountName and dNSHostName) must map; one over it is
// refused.
func Test_bounds_are_the_schema_range_upper_in_characters(t *testing.T) {
	m := mapper(dirsync.Config{})
	comp := func(a attrs) *connectorv1.DirectoryEntry {
		return entry(90, "CN=PC1,OU=Staff,DC=lab,DC=test", gid(ouGUID), a.classes("top", "computer"))
	}
	for _, tc := range []struct {
		name, attr string
		ok, over   string
	}{
		{"sAMAccountName 256 chars", "sAMAccountName", strings.Repeat("é", 256), strings.Repeat("é", 257)},
		{"userPrincipalName 1024 chars", "userPrincipalName", strings.Repeat("é", 1024), strings.Repeat("é", 1025)},
		{"displayName 256 chars", "displayName", strings.Repeat("é", 256), strings.Repeat("é", 1025)},
		{"dNSHostName 2048 chars", "dNSHostName", strings.Repeat("a", 2048), strings.Repeat("a", 2049)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := m.Map(comp(attrs(nil).with(tc.attr, txt(tc.ok)))); err != nil {
				t.Fatalf("at the rangeUpper: %v", err)
			}
			_, err := m.Map(comp(attrs(nil).with(tc.attr, txt(tc.over))))
			wantMalformed(t, err, tc.attr, dirsync.CodeTooLong)
		})
	}
}

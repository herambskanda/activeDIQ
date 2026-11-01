package ad

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/attr/secretattr"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/directory/ldapfilter"
)

// secretSession is a Session with no connection and a schema that knows the static SecretAttrs, so a
// request that reaches the network fails with DC_UNREACHABLE and one refused earlier fails otherwise.
func secretSession() *Session {
	extra := []ldapfilter.AttrInfo{}
	for _, n := range secretattr.Static() {
		extra = append(extra, ldapfilter.AttrInfo{Name: n, Syntax: ldapfilter.SynOctet, Secret: true})
	}
	extra = append(extra, ldapfilter.AttrInfo{Name: "ms-Mcs-AdmPwd", Syntax: ldapfilter.SynString, Secret: true})
	return &Session{schema: DefaultSchema().With(extra...)}
}

func TestDecodeIncrementalName(t *testing.T) {
	cases := []struct {
		in   string
		base string
		op   ChangeOp
		bad  bool
	}{
		{"member", "member", 0, false},
		{"member;range=1-1", "member", OpValuesAdded, false},
		{"Member;Range=1-1", "Member", OpValuesAdded, false},
		{"member;range=0-0", "member", OpValuesRemoved, false},
		{"member;range=0-1499", "", 0, true}, // a paging cursor is not a feed form
		{"member;range=1500-*", "", 0, true}, // the ranged loop is never applied to feed output
		{"member;range=2-2", "", 0, true},
		{"member;binary", "", 0, true},
		{"member;range=x-y", "", 0, true},
	}
	for _, c := range cases {
		base, op, err := decodeIncrementalName(c.in)
		if c.bad {
			if CodeOf(err) != CodeProtocol {
				t.Errorf("%q: err=%v, want PROTOCOL_ERROR", c.in, err)
			}
			continue
		}
		if err != nil || base != c.base || op != c.op {
			t.Errorf("%q: %q %v %v", c.in, base, op, err)
		}
	}
}

func FuzzDecodeIncrementalName(f *testing.F) {
	for _, s := range []string{"member", "member;range=1-1", "a;range=0-0", ";range=", "x;range=1-*", "x;;range=1-1"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, name string) {
		base, op, err := decodeIncrementalName(name)
		if err != nil {
			return
		}
		if base == "" && name != "" {
			t.Fatalf("%q decoded to an empty base", name)
		}
		if op != 0 && op != OpValuesAdded && op != OpValuesRemoved {
			t.Fatalf("%q: op %v", name, op)
		}
	})
}

func ldapEntry(dnStr string, attrs ...*ldap.EntryAttribute) *ldap.Entry {
	return &ldap.Entry{DN: dnStr, Attributes: attrs}
}

func attr(name string, vals ...string) *ldap.EntryAttribute {
	bv := make([][]byte, len(vals))
	sv := make([]string, len(vals))
	for i, v := range vals {
		bv[i], sv[i] = []byte(v), v
	}
	return &ldap.EntryAttribute{Name: name, Values: sv, ByteValues: bv}
}

func rawAttr(name string, vals ...[]byte) *ldap.EntryAttribute {
	return &ldap.EntryAttribute{Name: name, ByteValues: vals}
}

func wantSet(names ...string) map[string]struct{} {
	m := map[string]struct{}{}
	for _, n := range append(append([]string(nil), dirSyncMandatory...), names...) {
		m[strings.ToLower(n)] = struct{}{}
	}
	return m
}

func TestDecodeChangeNormalisesAndStrips(t *testing.T) {
	s := secretSession()
	g := guid.GUID{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01}
	pg := guid.GUID{0x01}
	e := ldapEntry("CN=GG-Big,OU=Groups,DC=lab,DC=test",
		rawAttr("objectGUID", g.Bytes()),
		rawAttr("parentGUID", pg.Bytes()),
		attr("name", "GG-Big"),
		attr("member;range=1-1", "CN=added,DC=lab,DC=test"),
		attr("member;range=0-0", "CN=gone,DC=lab,DC=test"),
		attr("description"), // cleared
		attr("displayName", "Big"),
		attr("pwdLastSet", "133000000000000000"),
		attr("unicodePwd", "must-never-leave"),
		attr("ntPwdHistory", "x"),
		attr("ms-Mcs-AdmPwd", "laps"),
		attr("whenChanged", "20260101000000.0Z"), // not requested: ignored, not a secret, not counted
	)
	oc, dropped, err := s.decodeChange(e, wantSet("member", "description", "displayName", "pwdLastSet"))
	if err != nil {
		t.Fatal(err)
	}
	if dropped != 3 {
		t.Errorf("dropped %d, want 3", dropped)
	}
	if oc.GUID != g || oc.State != StateLive || !oc.HasParent || oc.Parent != pg || oc.DN != e.DN {
		t.Errorf("identity fields: %+v", oc)
	}
	got := map[string]AttributeChange{}
	for _, a := range oc.Attributes {
		got[strings.ToLower(a.Name)+"/"+string(rune('0'+a.Op))] = a
		low := strings.ToLower(a.Name)
		if low == "unicodepwd" || low == "ntpwdhistory" || low == "ms-mcs-admpwd" || low == "whenchanged" {
			t.Errorf("attribute %q leaked", a.Name)
		}
		for _, v := range a.Values {
			if bytes.Contains(v, []byte("must-never-leave")) || bytes.Contains(v, []byte("laps")) {
				t.Errorf("secret value leaked in %q", a.Name)
			}
		}
	}
	check := func(key string, op ChangeOp, vals ...string) {
		a, ok := got[key]
		if !ok || a.Op != op || len(a.Values) != len(vals) {
			t.Errorf("%s: %+v", key, a)
			return
		}
		for i, v := range vals {
			if string(a.Values[i]) != v {
				t.Errorf("%s value %d: %q", key, i, a.Values[i])
			}
		}
	}
	check("member/"+string(rune('0'+OpValuesAdded)), OpValuesAdded, "CN=added,DC=lab,DC=test")
	check("member/"+string(rune('0'+OpValuesRemoved)), OpValuesRemoved, "CN=gone,DC=lab,DC=test")
	check("description/"+string(rune('0'+OpCleared)), OpCleared)
	check("displayname/"+string(rune('0'+OpSet)), OpSet, "Big")
	check("pwdlastset/"+string(rune('0'+OpSet)), OpSet, "133000000000000000")
	check("name/"+string(rune('0'+OpSet)), OpSet, "GG-Big")
	for _, n := range []string{"objectguid", "parentguid", "isdeleted"} {
		for k := range got {
			if strings.HasPrefix(k, n+"/") {
				t.Errorf("%s must be folded into the identity fields", n)
			}
		}
	}
}

func TestDecodeChangeStates(t *testing.T) {
	s := secretSession()
	g := guid.GUID{9}
	live := ldapEntry("CN=a", rawAttr("objectGUID", g.Bytes()))
	del := ldapEntry("CN=a\\0ADEL:x,CN=Deleted Objects", rawAttr("objectGUID", g.Bytes()), attr("isDeleted", "TRUE"), attr("lastKnownParent", "OU=Old,DC=lab"))
	rec := ldapEntry("CN=a", rawAttr("objectGUID", g.Bytes()), attr("isDeleted", "TRUE"), attr("isRecycled", "TRUE"))
	for _, c := range []struct {
		e    *ldap.Entry
		want ObjectState
	}{{live, StateLive}, {del, StateDeleted}, {rec, StateRecycled}} {
		oc, _, err := s.decodeChange(c.e, wantSet())
		if err != nil || oc.State != c.want || oc.HasParent {
			t.Errorf("%s: %+v %v", c.e.DN, oc, err)
		}
	}
	oc, _, _ := s.decodeChange(del, wantSet())
	if oc.DN != del.DN || len(oc.Attributes) != 1 || oc.Attributes[0].Name != "lastKnownParent" {
		t.Errorf("tombstone: %+v", oc)
	}
	// An entry with no objectGUID, or a malformed one, is an error and never an anonymous change.
	if _, _, err := s.decodeChange(ldapEntry("CN=x"), wantSet()); CodeOf(err) != CodeProtocol {
		t.Errorf("missing GUID: %v", err)
	}
	if _, _, err := s.decodeChange(ldapEntry("CN=x", rawAttr("objectGUID", []byte{1, 2})), wantSet()); CodeOf(err) != CodeProtocol {
		t.Errorf("short GUID: %v", err)
	}
	// An unexpected range on a feed entry fails the batch rather than guessing.
	if _, _, err := s.decodeChange(ldapEntry("CN=x", rawAttr("objectGUID", g.Bytes()), attr("member;range=0-1499", "a")), wantSet("member")); CodeOf(err) != CodeProtocol {
		t.Errorf("paging range: %v", err)
	}
}

func TestDecodeChangeMergesSplitRangeAttributes(t *testing.T) {
	s := secretSession()
	g := guid.GUID{7}
	e := ldapEntry("CN=G", rawAttr("objectGUID", g.Bytes()),
		attr("member;range=1-1", "a"), attr("member;range=1-1", "b"))
	oc, _, err := s.decodeChange(e, wantSet("member"))
	if err != nil || len(oc.Attributes) != 1 || len(oc.Attributes[0].Values) != 2 {
		t.Fatalf("%+v %v", oc, err)
	}
}

// A secret named in the request fails before any request reaches the DC: this session has no
// connection, so a request that got as far as the network would be DC_UNREACHABLE.
func TestDirSyncNamedSecretFailsBeforeAnyRequest(t *testing.T) {
	s := secretSession()
	nc := dn.GUIDRef(guid.GUID{1})
	for _, name := range []string{"unicodePwd", "ntPwdHistory", "ms-Mcs-AdmPwd", "UNICODEPWD"} {
		_, err := s.DirSync(context.Background(), DirSyncRequest{NC: nc, Attributes: []string{"displayName", name}})
		if CodeOf(err) != CodeSecretAttribute {
			t.Errorf("%s: %v", name, err)
		}
		_, err = s.DirSyncCycle(context.Background(), DirSyncRequest{NC: nc, Attributes: []string{name}}, nil)
		if CodeOf(err) != CodeSecretAttribute {
			t.Errorf("cycle %s: %v", name, err)
		}
	}
	for _, name := range []string{"*", "+", "tokenGroups", "x;range=0-1", "nosuchattr"} {
		_, err := s.DirSync(context.Background(), DirSyncRequest{NC: nc, Attributes: []string{name}})
		if CodeOf(err) == CodeUnreachable || err == nil {
			t.Errorf("%q must be refused before the network: %v", name, err)
		}
	}
}

func TestDirSyncControlsAreClosed(t *testing.T) {
	ctrls := dirSyncControls([]byte{1})
	if len(ctrls) != 2 || ctrls[0].GetControlType() != ldap.ControlTypeDirSync || ctrls[1].GetControlType() != "1.2.840.113556.1.4.417" {
		t.Fatalf("controls %v", ctrls)
	}
	for _, c := range ctrls {
		if !bytes.Contains(c.Encode().Bytes(), []byte{0x01, 0x01, 0xff}) { // BOOLEAN TRUE
			t.Errorf("%s not critical", c.GetControlType())
		}
	}
	// The mandatory set holds what the contract names, and nothing that tombstones lack.
	for _, n := range []string{"objectGUID", "objectClass", "name", "isDeleted", "isRecycled", "lastKnownParent"} {
		found := false
		for _, m := range dirSyncMandatory {
			found = found || m == n
		}
		if !found {
			t.Errorf("mandatory set lacks %s", n)
		}
	}
	for _, m := range dirSyncMandatory {
		if strings.EqualFold(m, "objectCategory") {
			t.Error("objectCategory is not on tombstones")
		}
	}
}

// The DirSync and show-deleted OIDs are written in package scope only (FF-SP2 escape-control-oid).
// The scanner in tools/fitness/safeprim proves it tree-wide; this keeps the package honest on its own.
func TestEscapeOIDsOnlyInScope(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, _ := os.ReadFile(f)
		for _, oid := range []string{"1.2.840.113556.1.4.841", "1.2.840.113556.1.4.2090", "1.2.840.113556.1.4.417"} {
			if bytes.Contains(b, []byte(oid)) {
				t.Errorf("%s names %s outside scope", f, oid)
			}
		}
	}
}

// A caller cannot ask for other flags, DirSync EX or another control: the request has no field for any
// of them, and a new field must be a deliberate change to this list.
func TestDirSyncRequestHasNoFlagsOrControls(t *testing.T) {
	rt := reflect.TypeOf(DirSyncRequest{})
	var got []string
	for i := 0; i < rt.NumField(); i++ {
		got = append(got, rt.Field(i).Name)
	}
	if want := []string{"NC", "Cookie", "Attributes"}; !reflect.DeepEqual(got, want) {
		t.Errorf("DirSyncRequest fields %v, want %v", got, want)
	}
}

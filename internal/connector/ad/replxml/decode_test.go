package replxml

import (
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
)

const (
	g1 = "4f7a1c2e-0b3d-4c5e-8a9f-1234567890ab"
	g2 = "a1b2c3d4-e5f6-4708-9a0b-c1d2e3f4a5b6"
	g3 = "00112233-4455-6677-8899-aabbccddeeff"
)

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestDecodeNeighbors_valid(t *testing.T) {
	n, e := DecodeNeighbors(readFile(t, "valid/neighbor.xml"))
	if e != nil {
		t.Fatal(e)
	}
	if n.Partition.String() != g1 || n.SourceDSA.String() != g2 {
		t.Errorf("guids %s %s", n.Partition, n.SourceDSA)
	}
	if n.PartitionDisplayDN != "DC=corp,DC=example,DC=com" || n.SourceDNSHost != "dc02.corp.example.com" {
		t.Errorf("text %q %q", n.PartitionDisplayDN, n.SourceDNSHost)
	}
	if n.LastSuccess.Kind != TimeAt || !n.LastSuccess.At.Equal(mustTime(t, "2026-10-01T08:30:15Z")) {
		t.Errorf("last success %+v", n.LastSuccess)
	}
	if n.ConsecutiveFailures != (U32{0, true}) || n.LastResultWin32 != (U32{0, true}) || n.Flags != (U32{2147483664, true}) {
		t.Errorf("numbers %+v %+v %+v", n.ConsecutiveFailures, n.LastResultWin32, n.Flags)
	}
	if n.UnknownElements != 0 {
		t.Errorf("unknown %d", n.UnknownElements)
	}
}

func TestDecodeNeighbors_failing_and_missing(t *testing.T) {
	n, e := DecodeNeighbors(readFile(t, "valid/neighbor_failing.xml"))
	if e != nil {
		t.Fatal(e)
	}
	if n.LastSuccess.Kind != TimeZero {
		t.Errorf("FILETIME 0 must be Zero, got %+v", n.LastSuccess)
	}
	if n.LastAttempt.Kind != TimeAt || n.LastAttempt.At.Nanosecond() != 123456700 {
		t.Errorf("fraction %+v", n.LastAttempt)
	}
	if n.ConsecutiveFailures.V != 14 || n.LastResultWin32.V != 1722 {
		t.Errorf("%+v %+v", n.ConsecutiveFailures, n.LastResultWin32)
	}
	// A field the DC omitted is unset, never zero (rule 10).
	if n.Flags.Set || n.Flags.V != 0 || n.PartitionDisplayDN == "" {
		t.Errorf("flags %+v", n.Flags)
	}
	if n.SourceDSA.IsSet() == false || (Neighbor{}).Partition.IsSet() {
		t.Error("set/unset")
	}
	empty, e := DecodeNeighbors([]byte("<DS_REPL_NEIGHBOR/>"))
	if e != nil || !reflect.DeepEqual(empty, Neighbor{}) {
		t.Errorf("empty root: %+v %v", empty, e)
	}
	if empty.LastAttempt.Kind != TimeUnset || empty.SourceDSA.Bytes() != nil || empty.SourceDSA.String() != "" {
		t.Error("omitted fields must read as unset")
	}
}

func TestDecodePendingOps_valid(t *testing.T) {
	o, e := DecodePendingOps(readFile(t, "valid/pending_op.xml"))
	if e != nil {
		t.Fatal(e)
	}
	if o.SerialNumber.V != 77 || o.Priority.V != 1 || o.OpType.V != 2 || o.Options.V != 16 ||
		o.DSA.String() != g2 || o.Partition.String() != g1 || o.DSADNSHost != "dc02.corp.example.com" ||
		o.Enqueued.Kind != TimeAt {
		t.Errorf("%+v", o)
	}
}

func TestDecodeFailures_valid(t *testing.T) {
	f, e := DecodeFailures(readFile(t, "valid/failure.xml"))
	if e != nil {
		t.Fatal(e)
	}
	if f.DSA.String() != g2 || f.Count.V != 5 || f.LastResultWin32.V != 8524 ||
		!f.FirstFailure.At.Equal(mustTime(t, "2026-09-30T23:59:59Z")) {
		t.Errorf("%+v", f)
	}
}

func TestDecodeAttrMetaData_valid(t *testing.T) {
	m, e := DecodeAttrMetaData(readFile(t, "valid/attr_meta.xml"))
	if e != nil {
		t.Fatal(e)
	}
	if m.AttributeName != "cn" || m.Version.V != 3 || m.OriginatingUSN.V != 40001 || m.LocalUSN.V != 40002 ||
		m.OriginatingDSA.String() != g3 || !m.OriginTime.At.Equal(mustTime(t, "2026-05-02T10:11:12Z")) {
		t.Errorf("%+v", m)
	}
	if _, e := DecodeAttrMetaData([]byte("<DS_REPL_ATTR_META_DATA><dwVersion>1</dwVersion></DS_REPL_ATTR_META_DATA>")); e == nil || e.Code != CodeMissingField {
		t.Errorf("name is required: %v", e)
	}
}

// Acceptance 5 (X7): names and numbers only; a unicodePwd change carries no value bytes.
func TestDecodeAttrMetaData_unicodePwd_names_never_values(t *testing.T) {
	raw := readFile(t, "valid/attr_meta_unicodepwd.xml")
	m, e := DecodeAttrMetaData(raw)
	if e != nil {
		t.Fatal(e)
	}
	if m.AttributeName != "unicodePwd" || m.Version.V != 7 || m.OriginatingUSN.V != 9001 || m.LocalUSN.V != 9002 ||
		m.OriginatingDSA.String() != g3 || m.OriginTime.Kind != TimeAt {
		t.Errorf("%+v", m)
	}
	dump := fmt.Sprintf("%+v %#v", m, m)
	if strings.Contains(dump, "NTDS Settings") || strings.Contains(dump, "DC=corp") {
		t.Errorf("the originating DSA DN leaked into the output: %s", dump)
	}
}

func TestDecodeValueMetaData_drops_value(t *testing.T) {
	const secret = "S3CRET-VALUE-BYTES"
	doc := strings.Replace(string(readFile(t, "valid/value_meta.xml")),
		"<cbData>0</cbData>", "<cbData>18</cbData><pbData>"+secret+"</pbData>", 1)
	m, e := DecodeValueMetaData([]byte(doc))
	if e != nil {
		t.Fatal(e)
	}
	if m.AttributeName != "member" || m.TargetGUID.String() != g1 || m.Created.Kind != TimeAt ||
		m.Deleted.Kind != TimeZero || m.Version.V != 1 || m.OriginatingUSN.V != 500 || m.LocalUSN.V != 501 {
		t.Errorf("%+v", m)
	}
	dump := fmt.Sprintf("%+v %#v", m, m)
	for _, bad := range []string{secret, "Smith", "OU=Staff", "NTDS"} {
		if strings.Contains(dump, bad) {
			t.Errorf("value %q leaked: %s", bad, dump)
		}
	}
	// the structure has no field that could hold a value
	for _, typ := range []reflect.Type{reflect.TypeOf(AttrMeta{}), reflect.TypeOf(ValueMeta{})} {
		for i := 0; i < typ.NumField(); i++ {
			if f := typ.Field(i); f.Type.Kind() == reflect.Slice || f.Type.Kind() == reflect.Map {
				t.Errorf("%s.%s can hold a value", typ.Name(), f.Name)
			}
		}
	}
	// a pbData as long as a value is accepted and still dropped (it is opaque value bytes, X7)
	big := strings.Replace(string(readFile(t, "valid/value_meta.xml")), "<cbData>0</cbData>", "<pbData>"+strings.Repeat("ab", 20000)+"</pbData>", 1)
	if m, e := DecodeValueMetaData([]byte(big)); e != nil || m.AttributeName != "member" {
		t.Errorf("large pbData: %v", e)
	}
	// but a DN is bounded by X3
	longDN := strings.Replace(string(readFile(t, "valid/value_meta.xml")), "CN=Smith", strings.Repeat("A", 2000), 1)
	if _, e := DecodeValueMetaData([]byte(longDN)); e == nil || e.Code != CodeTextTooLong {
		t.Errorf("long DN: %v", e)
	}
}

// Acceptance 1: one case each, all five decoders, nothing populated.
func TestRefusals_fixed_codes_no_fields(t *testing.T) {
	root := map[string]string{
		"DecodeNeighbors": "DS_REPL_NEIGHBOR", "DecodePendingOps": "DS_REPL_OP", "DecodeFailures": "DS_REPL_KCC_DSA_FAILURE",
		"DecodeAttrMetaData": "DS_REPL_ATTR_META_DATA", "DecodeValueMetaData": "DS_REPL_VALUE_META_DATA",
	}
	dupField := map[string]string{
		"DS_REPL_NEIGHBOR": "dwReplicaFlags", "DS_REPL_OP": "ulOptions", "DS_REPL_KCC_DSA_FAILURE": "cNumFailures",
		"DS_REPL_ATTR_META_DATA": "dwVersion", "DS_REPL_VALUE_META_DATA": "dwVersion",
	}
	cases := []struct {
		name string
		doc  func(root string) string
		want Code
	}{
		{"DOCTYPE", func(r string) string { return `<!DOCTYPE x><` + r + `/>` }, CodeForbiddenDirective},
		{"DOCTYPE with internal subset", func(r string) string { return `<!DOCTYPE x [<!ENTITY a "b">]><` + r + `/>` }, CodeForbiddenDirective},
		{"ENTITY declaration", func(r string) string { return `<!ENTITY a "b"><` + r + `/>` }, CodeForbiddenDirective},
		{"directive inside the root", func(r string) string { return `<` + r + `><!ENTITY a "b"></` + r + `>` }, CodeForbiddenDirective},
		{"PI before root", func(r string) string { return `<?pi x?><` + r + `/>` }, CodeForbiddenPI},
		{"PI inside root", func(r string) string { return `<` + r + `><?pi x?></` + r + `>` }, CodeForbiddenPI},
		{"PI after root", func(r string) string { return `<` + r + `/><?pi x?>` }, CodeForbiddenPI},
		{"xml declaration not first", func(r string) string { return ` <?xml version="1.0"?><` + r + `/>` }, CodeForbiddenPI},
		{"xml declaration twice", func(r string) string { return `<?xml version="1.0"?><?xml version="1.0"?><` + r + `/>` }, CodeForbiddenPI},
		{"encoding ISO-8859-1", func(r string) string { return `<?xml version="1.0" encoding="ISO-8859-1"?><` + r + `/>` }, CodeBadEncoding},
		{"encoding UTF-16", func(r string) string { return `<?xml version="1.0" encoding="UTF-16"?><` + r + `/>` }, CodeBadEncoding},
		{"UTF-16 BOM", func(r string) string { return "\xff\xfe<\x00" }, CodeBadEncoding},
		{"wrong root", func(r string) string { return `<DS_REPL_OTHER/>` }, CodeBadRoot},
		{"namespaced root", func(r string) string { return `<` + r + ` xmlns="urn:x"/>` }, CodeBadRoot},
		{"undeclared entity", func(r string) string { return `<` + r + `>&xxe;</` + r + `>` }, CodeMalformed},
		{"text in root", func(r string) string { return `<` + r + `>hello</` + r + `>` }, CodeBadStructure},
		{"NUL", func(r string) string { return `<` + r + `>` + "\x00" + `</` + r + `>` }, CodeBadText},
		{"two roots", func(r string) string { return `<` + r + `/><` + r + `/>` }, CodeTrailingContent},
		{"text after root", func(r string) string { return `<` + r + `/>x` }, CodeTrailingContent},
		{"duplicate known field", func(r string) string {
			f := dupField[r]
			return `<` + r + `><` + f + `>1</` + f + `><` + f + `>2</` + f + `></` + r + `>`
		}, CodeDuplicateElement},
	}
	for dn, dec := range decoders {
		for _, c := range cases {
			t.Run(dn+"/"+c.name, func(t *testing.T) {
				v, e := dec([]byte(c.doc(root[dn])))
				if e == nil {
					t.Fatalf("decoded %+v", v)
				}
				if e.Code != c.want {
					t.Errorf("code %s, want %s", e.Code, c.want)
				}
				if !reflect.ValueOf(v).IsZero() {
					t.Errorf("fields populated on error: %+v", v)
				}
				if strings.Contains(e.Error(), "xxe") {
					t.Error("error text carries input")
				}
			})
		}
	}
	// A comment is skipped, CDATA is text, the lower-case utf-8 label is fine.
	ok := `<?xml version="1.0" encoding="utf-8"?><!-- note --><DS_REPL_ATTR_META_DATA><pszAttributeName><![CDATA[c<n]]></pszAttributeName></DS_REPL_ATTR_META_DATA>`
	m, e := DecodeAttrMetaData([]byte(ok))
	if e != nil || m.AttributeName != "c<n" {
		t.Errorf("%+v %v", m, e)
	}
}

// Acceptance 3 / CC-REPLXML-03.
func TestUnknownElement_counted_not_exposed(t *testing.T) {
	n, e := DecodeNeighbors(readFile(t, "valid/neighbor_unknown_element.xml"))
	if e != nil {
		t.Fatal(e)
	}
	if n.UnknownElements != 2 { // dwFutureField and nested (its subtree is one skipped element)
		t.Errorf("unknown = %d, want 2", n.UnknownElements)
	}
	if n.Partition.String() != g1 || n.PartitionDisplayDN != "DC=corp,DC=example,DC=com" {
		t.Errorf("%+v", n)
	}
	if reflect.TypeOf(n).NumField() != 10 {
		t.Error("Neighbor gained a field; unknown elements must not be exposed")
	}
}

// Acceptance 3 / CC-REPLXML-04: a bad time is bad_time, never zero and never now.
func TestBadTime(t *testing.T) {
	bad := []string{
		"", "0", "now", "yesterday", "2026-10-01", "2026-10-01 08:30:15Z", "2026-10-01T08:30:15", "2026-10-01T08:30:15+02:00",
		"2026-10-01T08:30:15z", "2026-13-01T00:00:00Z", "2026-02-30T00:00:00Z", "2026-10-01T24:00:00Z", "2026-10-01T00:60:00Z",
		"2026-10-01T00:00:60Z", "1600-12-31T23:59:59Z", "2026-10-01T08:30:15.Z", "2026-10-01T08:30:15.123456789Z",
		"2026-10-01T08:30:15.1x3Z", "+026-10-01T08:30:15Z", "-2026-10-01T08:30:15Z",
		"20261001T083015Z", "133700000000000000",
	}
	for _, s := range bad {
		doc := "<DS_REPL_NEIGHBOR><ftimeLastSyncSuccess>" + s + "</ftimeLastSyncSuccess></DS_REPL_NEIGHBOR>"
		if s == "" {
			doc = "<DS_REPL_NEIGHBOR><ftimeLastSyncSuccess/></DS_REPL_NEIGHBOR>"
		}
		n, e := DecodeNeighbors([]byte(doc))
		if e == nil || e.Code != CodeBadTime {
			t.Errorf("%q: got %+v %v, want bad_time", s, n.LastSuccess, e)
		}
		if n.LastSuccess.Kind != TimeUnset || !n.LastSuccess.At.IsZero() {
			t.Errorf("%q: time populated on error", s)
		}
	}
	good := map[string]time.Time{
		"2026-02-28T23:59:59Z":         time.Date(2026, 2, 28, 23, 59, 59, 0, time.UTC),
		"2028-02-29T00:00:00Z":         time.Date(2028, 2, 29, 0, 0, 0, 0, time.UTC),
		"1601-01-01T00:00:01Z":         time.Date(1601, 1, 1, 0, 0, 1, 0, time.UTC),
		"2026-10-01T08:30:15.5Z":       time.Date(2026, 10, 1, 8, 30, 15, 500000000, time.UTC),
		"  2026-10-01T08:30:15Z\n":     time.Date(2026, 10, 1, 8, 30, 15, 0, time.UTC),
		"9999-12-31T23:59:59.9999999Z": time.Date(9999, 12, 31, 23, 59, 59, 999999900, time.UTC),
	}
	for s, want := range good {
		n, e := DecodeNeighbors([]byte("<DS_REPL_NEIGHBOR><ftimeLastSyncSuccess>" + s + "</ftimeLastSyncSuccess></DS_REPL_NEIGHBOR>"))
		if e != nil || n.LastSuccess.Kind != TimeAt || !n.LastSuccess.At.Equal(want) {
			t.Errorf("%q: %+v %v", s, n.LastSuccess, e)
		}
	}
}

func TestBadNumber(t *testing.T) {
	for _, s := range []string{"", "-1", "+1", "1.0", "0x10", "1 2", "4294967296", "99999999999", "١٢", "1_0", "00000000000"} {
		_, e := DecodeNeighbors([]byte("<DS_REPL_NEIGHBOR><cNumConsecutiveSyncFailures>" + s + "</cNumConsecutiveSyncFailures></DS_REPL_NEIGHBOR>"))
		if e == nil || e.Code != CodeBadNumber {
			t.Errorf("%q: %v", s, e)
		}
	}
	n, e := DecodeNeighbors([]byte("<DS_REPL_NEIGHBOR><cNumConsecutiveSyncFailures>4294967295</cNumConsecutiveSyncFailures></DS_REPL_NEIGHBOR>"))
	if e != nil || n.ConsecutiveFailures.V != 4294967295 {
		t.Errorf("max uint32: %+v %v", n, e)
	}
	m, e := DecodeAttrMetaData([]byte("<DS_REPL_ATTR_META_DATA><pszAttributeName>a</pszAttributeName><usnLocalChange>18446744073709551615</usnLocalChange></DS_REPL_ATTR_META_DATA>"))
	if e != nil || m.LocalUSN.V != ^uint64(0) {
		t.Errorf("max uint64: %+v %v", m, e)
	}
	if _, e := DecodeAttrMetaData([]byte("<DS_REPL_ATTR_META_DATA><pszAttributeName>a</pszAttributeName><usnLocalChange>18446744073709551616</usnLocalChange></DS_REPL_ATTR_META_DATA>")); e == nil || e.Code != CodeBadNumber {
		t.Errorf("uint64 overflow: %v", e)
	}
}

// Acceptance 3 / CC-REPLXML-04: GUID byte order follows contract rule 9 (RFC 4122 order, the
// order of the canonical text), cross-checked against the objectGUID codec's wire order.
func TestGUID_order_matches_rule9(t *testing.T) {
	// objectGUID wire order for 4f7a1c2e-0b3d-4c5e-8a9f-1234567890ab is mixed-endian.
	wire := []byte{0x2e, 0x1c, 0x7a, 0x4f, 0x3d, 0x0b, 0x5e, 0x4c, 0x8a, 0x9f, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab}
	w, err := guid.FromBytes(wire)
	if err != nil {
		t.Fatal(err)
	}
	if w.String() != g1 {
		t.Fatalf("codec says %s", w.String())
	}
	n, e := DecodeNeighbors([]byte("<DS_REPL_NEIGHBOR><uuidNamingContextObjGuid>" + strings.ToUpper(g1) + "</uuidNamingContextObjGuid></DS_REPL_NEIGHBOR>"))
	if e != nil {
		t.Fatal(e)
	}
	want := []byte{0x4f, 0x7a, 0x1c, 0x2e, 0x0b, 0x3d, 0x4c, 0x5e, 0x8a, 0x9f, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab}
	if !reflect.DeepEqual(n.Partition.Bytes(), want) {
		t.Errorf("bytes % x, want RFC 4122 order % x", n.Partition.Bytes(), want)
	}
	if n.Partition.String() != w.String() {
		t.Errorf("text %s vs codec %s", n.Partition, w)
	}
	// Bytes returns a copy.
	b := n.Partition.Bytes()
	b[0] = 0
	if n.Partition.Bytes()[0] != 0x4f {
		t.Error("Bytes aliases the Guid")
	}
	for _, s := range []string{"", "{" + g1 + "}", g1[:35], g1 + "0", strings.Replace(g1, "-", "", -1), strings.Replace(g1, "4f7a", "4g7a", 1), "4f7a1c2e_0b3d-4c5e-8a9f-1234567890ab", "4f7a1c2e-0b3d-4c5e-8a9f-1234567890aé"} {
		doc := "<DS_REPL_NEIGHBOR><uuidSourceDsaObjGuid>" + s + "</uuidSourceDsaObjGuid></DS_REPL_NEIGHBOR>"
		n, e := DecodeNeighbors([]byte(doc))
		if e == nil || e.Code != CodeBadGUID || n.SourceDSA.IsSet() {
			t.Errorf("%q: %v", s, e)
		}
	}
}

// X3: limits that the committed corpus cannot reach through the 64 KiB value cap are exercised
// with the internal limits, and the DC-supplied limits are the documented constants.
func TestLimits(t *testing.T) {
	if MaxValueBytes != 65536 || MaxCallBytes != 8<<20 || MaxElements != 20000 || MaxDepth != 8 || MaxAttrs != 16 || MaxText != 1024 {
		t.Fatal("limits drifted from connector-contract §5.7 X2/X3")
	}
	// The hard element cap is reachable only when the allocation-derived cap is above it, which needs
	// a large document: raise the input limit and inflate the document with comments.
	lim := defaultLimits
	lim.input = 100 << 20
	pad := strings.Repeat("<!--"+strings.Repeat("x", 900)+"-->", 800)
	if elementLimit(len(pad), MaxElements) != MaxElements {
		t.Fatal("pad too small for the hard cap")
	}
	d2 := []byte("<DS_REPL_NEIGHBOR>" + pad + strings.Repeat("<a/>", 20001) + "</DS_REPL_NEIGHBOR>")
	if _, e := parse(d2, neighborSpec, lim); e == nil || e.Code != CodeTooManyElements {
		t.Errorf("20,001 elements: %v", e)
	}
	d3 := []byte("<DS_REPL_NEIGHBOR>" + pad + strings.Repeat("<a/>", 20000-0) + "</DS_REPL_NEIGHBOR>")
	// root + 20,000 children = 20,001 elements: one over; 19,999 children is exactly the cap
	d3 = []byte("<DS_REPL_NEIGHBOR>" + pad + strings.Repeat("<a/>", 19999) + "</DS_REPL_NEIGHBOR>")
	if p, e := parse(d3, neighborSpec, lim); e != nil || p.unknown != 19999 {
		t.Errorf("20,000 elements: %v", e)
	}
	depth := func(n int) []byte {
		return []byte("<DS_REPL_NEIGHBOR><u>" + strings.Repeat("<a>", n-2) + strings.Repeat("</a>", n-2) + "</u></DS_REPL_NEIGHBOR>")
	}
	if _, e := DecodeNeighbors(depth(8)); e != nil {
		t.Errorf("depth 8: %v", e)
	}
	if _, e := DecodeNeighbors(depth(9)); e == nil || e.Code != CodeTooDeep {
		t.Errorf("depth 9: %v", e)
	}
	attrs := func(n int) []byte {
		var sb strings.Builder
		sb.WriteString("<DS_REPL_NEIGHBOR>")
		sb.WriteString("<u")
		for i := 0; i < n; i++ {
			sb.WriteString(" a" + strconv.Itoa(i) + `="v"`)
		}
		sb.WriteString("/></DS_REPL_NEIGHBOR>")
		return []byte(sb.String())
	}
	if n, e := DecodeNeighbors(attrs(16)); e != nil || n.UnknownElements != 1 {
		t.Errorf("16 attrs: %v", e)
	}
	if _, e := DecodeNeighbors(attrs(17)); e == nil || e.Code != CodeTooManyAttrs {
		t.Errorf("17 attrs: %v", e)
	}
	text := func(n int) []byte {
		return []byte("<DS_REPL_NEIGHBOR><pszNamingContext>" + strings.Repeat("a", n) + "</pszNamingContext></DS_REPL_NEIGHBOR>")
	}
	if _, e := DecodeNeighbors(text(1024)); e != nil {
		t.Errorf("1024-byte text: %v", e)
	}
	if _, e := DecodeNeighbors(text(1025)); e == nil || e.Code != CodeTextTooLong {
		t.Errorf("1025-byte text: %v", e)
	}
	// text split across CDATA and comments is still one field
	split := "<DS_REPL_NEIGHBOR><pszNamingContext>" + strings.Repeat("a", 600) + "<!--c-->" + "<![CDATA[" + strings.Repeat("b", 600) + "]]></pszNamingContext></DS_REPL_NEIGHBOR>"
	if _, e := DecodeNeighbors([]byte(split)); e == nil || e.Code != CodeTextTooLong {
		t.Errorf("split text: %v", e)
	}
	long := "<DS_REPL_NEIGHBOR><u a=\"" + strings.Repeat("v", 1025) + "\"/></DS_REPL_NEIGHBOR>"
	if _, e := DecodeNeighbors([]byte(long)); e == nil || e.Code != CodeTextTooLong {
		t.Errorf("attribute value: %v", e)
	}
	if _, e := DecodeNeighbors(make([]byte, MaxValueBytes+1)); e == nil || e.Code != CodeTooLarge {
		t.Errorf("64 KiB + 1: %v", e)
	}
	// an unknown element carrying text and children under the limits is skipped, never exposed
	n, e := DecodeNeighbors([]byte("<DS_REPL_NEIGHBOR><x><y>" + strings.Repeat("t", 1000) + "</y></x></DS_REPL_NEIGHBOR>"))
	if e != nil || n.UnknownElements != 1+0 && n.UnknownElements != 2 {
		t.Errorf("skip: %+v %v", n, e)
	}
}

func TestBudget(t *testing.T) {
	var b Budget
	for i := 0; i < 128; i++ {
		if e := b.Take(MaxValueBytes); e != nil {
			t.Fatalf("take %d: %v", i, e)
		}
	}
	if e := b.Take(1); e == nil || e.Code != CodeTooLarge {
		t.Errorf("129th 64 KiB: %v", e)
	}
	var c Budget
	if e := c.Take(-1); e == nil {
		t.Error("negative")
	}
}

func TestErrorText_fixed(t *testing.T) {
	var nilErr *DecodeError
	if nilErr.Error() == "" {
		t.Error("nil receiver")
	}
	_, e := DecodeNeighbors([]byte("<!DOCTYPE secret-marker><DS_REPL_NEIGHBOR/>"))
	if e == nil || e.Error() != "replxml: forbidden_directive" {
		t.Errorf("%v", e)
	}
}

// X6: the package imports nothing that can do I/O. (RX2 is the CI form of this check.)
func TestPure(t *testing.T) {
	deny := map[string]bool{"net": true, "os": true, "net/http": true, "io/ioutil": true, "os/exec": true, "plugin": true, "unsafe": true, "reflect": true, "log": true, "log/slog": true, "fmt": true}
	files, _ := filepath.Glob("*.go")
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		af, err := parser.ParseFile(fset, f, src, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range af.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			if deny[p] {
				t.Errorf("%s imports %s", f, p)
			}
			if strings.Contains(p, ".") && !strings.HasPrefix(p, "encoding/") {
				t.Errorf("%s imports non-standard %s", f, p)
			}
		}
		s := string(src)
		for _, bad := range []string{"CharsetReader = ", "Entity = &", "Entity = map", "Strict = false"} {
			if strings.Contains(s, bad) {
				t.Errorf("%s: %q", f, bad)
			}
		}
	}
}

// Valid corpus files are valid UTF-8 and decode with the matching decoder: the seed corpus is real.
func TestValidCorpusDecodes(t *testing.T) {
	want := map[string]string{
		"neighbor.xml": "DecodeNeighbors", "neighbor_failing.xml": "DecodeNeighbors", "neighbor_unknown_element.xml": "DecodeNeighbors",
		"pending_op.xml": "DecodePendingOps", "failure.xml": "DecodeFailures", "attr_meta.xml": "DecodeAttrMetaData",
		"attr_meta_unicodepwd.xml": "DecodeAttrMetaData", "value_meta.xml": "DecodeValueMetaData",
	}
	files, _ := filepath.Glob(filepath.Join("testdata", "valid", "*.xml"))
	if len(files) != len(want) {
		t.Fatalf("%d valid files, %d expected", len(files), len(want))
	}
	for name, dn := range want {
		b := readFile(t, "valid/"+name)
		if !utf8.Valid(b) {
			t.Errorf("%s not UTF-8", name)
		}
		if _, e := decoders[dn](b); e != nil {
			t.Errorf("%s: %v", name, e)
		}
	}
}

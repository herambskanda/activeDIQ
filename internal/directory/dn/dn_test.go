package dn

import (
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/attr/sid"
)

func mustParse(t *testing.T, s string, m Mode) DN {
	t.Helper()
	d, err := Parse(s, m)
	if err != nil {
		t.Fatalf("Parse(%q): %v", s, err)
	}
	return d
}

func parent(t *testing.T) DN { return mustParse(t, "OU=Staff,DC=corp,DC=example", Strict) }

func TestBuilderVectors(t *testing.T) {
	cases := []struct{ id, in, want string }{
		{"B01", "Smith, John", `CN=Smith\, John`},
		{"B02", ",OU=Domain Admins", `CN=\,OU\3DDomain Admins`},
		{"B03", "a+CN=b", `CN=a\+CN\3Db`},
		{"B04a", " lead", `CN=\ lead`},
		{"B04b", "trail ", `CN=trail\ `},
		{"B05a", " ", `CN=\ `},
		{"B05b", "  ", `CN=\ \ `},
		{"B06a", "#admins", `CN=\#admins`},
		{"B06b", "a#b", `CN=a#b`},
		{"B07", `"quoted"`, `CN=\"quoted\"`},
		{"B08", `back\slash`, `CN=back\\slash`},
		{"B09", "<x>;y", `CN=\<x\>\;y`},
		{"B10a", "line1\nline2", `CN=line1\0Aline2`},
		{"B10b", "a\rb", `CN=a\0Db`},
		{"B11", "a/b", `CN=a\2Fb`},
		{"B15", "𝔘ser Zoë", `CN=𝔘ser Zoë`},
		{"DEL", "a\x7fb", `CN=a\7Fb`},
	}
	for _, c := range cases {
		d, err := Child(parent(t), CN, c.in)
		if err != nil {
			t.Fatalf("%s: %v", c.id, err)
		}
		want := c.want + ",OU=Staff,DC=corp,DC=example"
		if got := string(d.Render()); got != want {
			t.Errorf("%s: got %q want %q", c.id, got, want)
		}
		back, err := Parse(d.Render(), Strict)
		if err != nil || !Equal(back, d) || back.RDNs()[0].Value() != c.in {
			t.Errorf("%s: round trip: %v %v", c.id, err, back.RDNs()[0].Value())
		}
	}
}

func TestBuilderErrors(t *testing.T) {
	cases := []struct {
		id   string
		in   string
		kind Kind
	}{
		{"B12", "a\x00b", NulInString},
		{"B13", "", EmptyRDNValue},
		{"B14", strings.Repeat("a", 65), ValueTooLong},
		{"B14b", strings.Repeat("𝔘", 33), ValueTooLong}, // 66 UTF-16 units
		{"B16", "\xff", InvalidUTF8},
	}
	for _, c := range cases {
		_, err := Child(DN{}, CN, c.in)
		if KindOf(err) != c.kind {
			t.Errorf("%s: %v", c.id, err)
		}
	}
	if _, err := Child(DN{}, CN, strings.Repeat("a", 64)); err != nil {
		t.Errorf("64 chars: %v", err)
	}
	if _, err := Child(DN{}, CN, strings.Repeat("𝔘", 32)); err != nil {
		t.Errorf("32 astral = 64 units: %v", err)
	}
	if _, err := Child(DN{}, OID, "x"); KindOf(err) != UnknownRDNType {
		t.Error("OID type must not be buildable")
	}
	if _, err := ParseRDNType("CN=x,OU"); KindOf(err) != UnknownRDNType {
		t.Error("B17")
	}
}

func TestParseVectors(t *testing.T) {
	d := mustParse(t, `CN=evil\,OU=HR,DC=corp,DC=example`, Strict)
	if d.Len() != 3 || d.RDNs()[0].Value() != "evil,OU=HR" {
		t.Fatalf("P01 %v", d.RDNs())
	}
	if d.IsDescendantOf(mustParse(t, "OU=HR,DC=corp,DC=example", Strict)) {
		t.Error("P01: escaped comma defeated scope")
	}
	if !Equal(mustParse(t, "cn=A,ou=HR,dc=corp,dc=example", Strict), mustParse(t, "CN=a,OU=hr,DC=CORP,DC=EXAMPLE", Strict)) {
		t.Error("P02")
	}
	a, b := mustParse(t, `CN=Smith\2C John,DC=x`, Strict), mustParse(t, `CN=Smith\, John,DC=x`, Strict)
	if !Equal(a, b) || a.Render() != `CN=Smith\, John,DC=x` || b.Render() != a.Render() {
		t.Error("P03")
	}
	bad := []struct {
		id, in string
		kind   Kind
	}{
		{"P04", "CN=a,,DC=x", EmptyRDN},
		{"P04b", "CN=a,", EmptyRDN},
		{"P05", `CN=a\`, DanglingEscape},
		{"P06", `CN=a\zz,DC=x`, InvalidEscape},
		{"P06b", `CN=a\2,DC=x`, InvalidEscape},
		{"P07", `CN=a\c3,DC=x`, InvalidUTF8},
		{"P08", "CN=a+CN=b,DC=x", MultiValuedRDN},
		{"P11", "<GUID=0102030405060708090a0b0c0d0e0f10>", UseObjectRef},
		{"P12", "<GUID=0102030405060708090a0b0c0d0e0f10>;<SID=S-1-5-21-1-2-3-500>;CN=x,DC=y", UseObjectRef},
		{"P14", "CN=x, OU=y", UnexpectedSpace},
		{"P14b", "CN=x ,OU=y", UnexpectedSpace},
		{"P14c", "CN= x,OU=y", UnexpectedSpace},
		{"P14d", "CN =x", UnexpectedSpace},
		{"P17", `CN="Smith, John",DC=x`, QuotedValueNotSupported},
		{"P18", strings.Repeat("a=b,", 10000) + "DC=x", TooLong},
		{"P18b", strings.Repeat("CN=a,", 65) + "DC=x", TooLong},
		{"MiB", "CN=" + strings.Repeat("a", 1<<20), TooLong},
		{"hash", "CN=#04024869", HexValueForbidden},
		{"nul", "CN=a\x00b", NulInString},
		{"nulhex", `CN=a\00b`, NulInString},
		{"unesc<", "CN=a<b", UnescapedSpecial},
		{"unesc;", "CN=a;b", UnescapedSpecial},
		{"midquote", `CN=a"b`, UnescapedSpecial},
		{"unknown", "XX=a", UnknownRDNType},
		{"noeq", "CN", MissingEquals},
		{"emptyval", "CN=,DC=x", EmptyRDNValue},
		{"empty", "", EmptyRDN},
		{"badutf8", "CN=a\xffb", InvalidUTF8},
		{"brace", "<x>", UnescapedSpecial},
	}
	for _, c := range bad {
		if _, err := Parse(c.in, Strict); KindOf(err) != c.kind {
			t.Errorf("%s: %q: got %v want %s", c.id, c.in, err, c.kind)
		}
	}
	// P09, P10: deleted and conflict objects re-render identically.
	for _, s := range []string{
		`CN=John Doe\0ADEL:6c3a4f9b-1c2d-4e5f-8a9b-0c1d2e3f4a5b,CN=Deleted Objects,DC=corp,DC=example`,
		`CN=Jane\0ACNF:6c3a4f9b-1c2d-4e5f-8a9b-0c1d2e3f4a5b,OU=Staff,DC=corp,DC=example`,
	} {
		d := mustParse(t, s, Strict)
		if !strings.Contains(d.RDNs()[0].Value(), "\n") || string(d.Render()) != s {
			t.Errorf("P09/10: %q", d.Render())
		}
	}
	// P14 lenient, P15, P16.
	if got := mustParse(t, " CN = x , OU=y ", Lenient).Render(); got != "CN=x,OU=y" {
		t.Errorf("P14 lenient: %q", got)
	}
	if got := mustParse(t, `CN=trail\ ,DC=x`, Lenient).Render(); got != `CN=trail\ ,DC=x` {
		t.Errorf("escaped trailing space kept in lenient: %q", got)
	}
	if got := mustParse(t, "CN=a=b,DC=x", Strict); got.RDNs()[0].Value() != "a=b" || got.Render() != `CN=a\3Db,DC=x` {
		t.Error("P15")
	}
	o := mustParse(t, "1.3.6.1.4.1.1466.0=#04024869,DC=x", Strict)
	if string(o.RDNs()[0].Opaque()) != "\x04\x02Hi" || o.RDNs()[0].Value() != "" || o.RDNs()[0].Type() != OID {
		t.Error("P16")
	}
	if _, err := DNRef(o).ForRequest(); KindOf(err) != NotRequestable {
		t.Error("P16: opaque DN must not be sendable")
	}
	if Equal(mustParse(t, "CN=José,OU=Staff,DC=x", Strict), mustParse(t, "CN=Jose,OU=Staff,DC=x", Strict)) {
		t.Error("P19")
	}
}

func TestDescendantAndParent(t *testing.T) {
	c := mustParse(t, "CN=a,OU=Staff,DC=corp,DC=example", Strict)
	if !c.IsDescendantOf(parent(t)) || c.IsDescendantOf(c) || parent(t).IsDescendantOf(c) {
		t.Error("descendant")
	}
	if !Equal(c.Parent(), parent(t)) {
		t.Error("parent")
	}
}

func TestErrorsIs(t *testing.T) {
	_, err := Parse("CN=a\\", Strict)
	if !errors.Is(err, &Error{Kind: DanglingEscape}) || strings.Contains(err.Error(), "CN") {
		t.Error(err)
	}
}

var (
	testGUID = func() guid.GUID {
		g, err := guid.FromBytes([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
		if err != nil {
			panic(err)
		}
		return g
	}()
	testSID = func() sid.SID {
		s, err := sid.Parse("S-1-5-21-1-2-3-500")
		if err != nil {
			panic(err)
		}
		return s
	}()
)

func TestObjectRef(t *testing.T) {
	const gref = "<GUID=0102030405060708090a0b0c0d0e0f10>"
	r, err := ParseObjectRef(gref) // DN-P11
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := r.ForRequest(); got != gref {
		t.Error(got)
	}
	if g, ok := r.GUID(); !ok || g != testGUID {
		t.Error("guid")
	}
	if got, _ := GUIDRef(testGUID).ForRequest(); got != gref {
		t.Error(got)
	}
	// Dashed and upper-case keyword forms are accepted and normalised.
	r2, err := ParseObjectRef("<guid=" + testGUID.String() + ">")
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := r2.ForRequest(); got != gref {
		t.Error(got)
	}
	// SID, text and binary.
	sref, _ := SIDRef(testSID).ForRequest()
	if !strings.HasPrefix(sref, "<SID=01") || !strings.HasSuffix(sref, ">") {
		t.Error(sref)
	}
	for _, in := range []string{sref, "<SID=S-1-5-21-1-2-3-500>"} {
		r, err := ParseObjectRef(in)
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if s, ok := r.SID(); !ok || s != testSID {
			t.Error("sid", in)
		}
	}
	// DN reference.
	r3, err := ParseObjectRef(`CN=a\,b,DC=x`)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := r3.ForRequest(); got != `CN=a\,b,DC=x` {
		t.Error(got)
	}
	// P13 and friends.
	for _, in := range []string{
		"<GUID=01020304>,CN=x", "<GUID=01020304>", gref + ")(cn=*", gref + ",CN=x", "<GUID=" + gref + ">",
		"<GUID=>", "<GUID>", "<WKGUID=0102030405060708090a0b0c0d0e0f10>", "<GUID=0102030405060708090a0b0c0d0e0fzz>",
		"<GUID=00000000000000000000000000000000>", "<SID=zz>", "<SID=S-1-5-21-1-2-3-500>;CN=x", "<GUID=*>",
		"<GUID=0102030405060708090a0b0c0d0e0f10;x>", " <GUID=0102030405060708090a0b0c0d0e0f10>", "<",
	} {
		if _, err := ParseObjectRef(in); err == nil {
			t.Errorf("accepted %q", in)
		}
	}
	if _, err := (ObjectRef{}).ForRequest(); err == nil {
		t.Error("zero ref must not be sendable")
	}
	if _, err := DNRef(DN{}).ForRequest(); err == nil {
		t.Error("empty DN ref must not be sendable")
	}
}

func TestExtendedDN(t *testing.T) { // DN-P12
	in := "<GUID=0102030405060708090a0b0c0d0e0f10>;<SID=S-1-5-21-1-2-3-500>;CN=x\\, y,DC=y"
	e, err := ParseExtendedDN(in)
	if err != nil || e.GUID != testGUID || !e.HasSID || e.SID != testSID || e.DN.Render() != `CN=x\, y,DC=y` {
		t.Fatalf("%+v %v", e, err)
	}
	e, err = ParseExtendedDN("<GUID=0102030405060708090a0b0c0d0e0f10>;CN=x,DC=y")
	if err != nil || e.HasSID {
		t.Fatal(err)
	}
	for _, bad := range []string{
		"CN=x,DC=y", "<SID=S-1-5-21-1-2-3-500>;CN=x", "<GUID=0102030405060708090a0b0c0d0e0f10>", "<GUID=01>;CN=x",
		"<GUID=0102030405060708090a0b0c0d0e0f10>;<GUID=0102030405060708090a0b0c0d0e0f10>;CN=x",
		"<SID=S-1-5-21-1-2-3-500>;<GUID=0102030405060708090a0b0c0d0e0f10>;CN=x",
		"<GUID=0102030405060708090a0b0c0d0e0f10>;<SID=S-1-5-21-1-2-3-500>;",
	} {
		if _, err := ParseExtendedDN(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

// FuzzRoundTrip: any value Child accepts renders to text that parses (Strict) back to an equal DN
// with the identical value, and the rendered text has no unescaped structure beyond its commas.
func FuzzRoundTrip(f *testing.F) {
	for _, s := range []string{"a", "Smith, John", ",OU=x", "a+b", " ", "#x", "\"q\"", `\`, "<>;", "a\nb", "𝔘", "a=b", "a/b", "x ", "\x7f"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, v string) {
		d, err := ChildMax(parent2(), CN, v, 0)
		if err != nil {
			return
		}
		text := d.Render()
		back, err := Parse(text, Strict)
		if err != nil {
			t.Fatalf("render %q does not parse: %v", text, err)
		}
		if back.Len() != 3 || back.RDNs()[0].Value() != v || !Equal(back, d) || back.Render() != text {
			t.Fatalf("round trip lost %q: %q", v, text)
		}
		if !IsDescendantOf(back, parent2()) {
			t.Fatalf("scope escape for %q", v)
		}
	})
}

func parent2() DN {
	d, err := Parse("OU=Staff,DC=corp", Strict)
	if err != nil {
		panic(err)
	}
	return d
}

// FuzzParse: Parse never panics, and whatever it accepts re-renders to text that parses to an equal
// DN (render is a fixed point).
func TestLenientOpaqueSeparator(t *testing.T) {
	for _, c := range []struct {
		in   string
		kind Kind
	}{
		{"1.2.3.4=#0401 +CN=a,DC=x", MultiValuedRDN},
		{"1.2.3.4=#0401 X,DC=x", UnescapedSpecial},
		{"1.2.3.4=#0401 XCN=evil,DC=x", UnescapedSpecial},
	} {
		if _, err := Parse(c.in, Lenient); KindOf(err) != c.kind {
			t.Errorf("%q: got %v want %s", c.in, err, c.kind)
		}
	}
	if d, err := Parse("1.2.3.4=#0401 ,DC=x", Lenient); err != nil || d.Len() != 2 {
		t.Errorf("valid lenient opaque: %v", err)
	}
}

func TestForRequestBoundsRenderedLength(t *testing.T) {
	d, err := Parse("CN="+strings.Repeat("=", 6000)+",DC=x", Strict)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DNRef(d).ForRequest(); KindOf(err) != TooLong {
		t.Errorf("got %v want TooLong", err)
	}
}

func FuzzParse(f *testing.F) {
	for _, s := range []string{`CN=a,DC=x`, `CN=a\,b,DC=x`, "1.2.3=#0400,DC=x", `CN=\ x\ ,DC=x`, "CN=a\xff", "<GUID=00>", `CN=a\2cb`} {
		f.Add(s, uint8(0))
		f.Add(s, uint8(1))
	}
	f.Fuzz(func(t *testing.T, s string, m uint8) {
		d, err := Parse(s, Mode(m&1))
		if err != nil {
			return
		}
		if d.Len() > strings.Count(s, ",")+1 {
			t.Fatalf("more RDNs than separators in %q", s)
		}
		for _, r := range d.RDNs() {
			if !utf8.ValidString(r.Value()) || strings.IndexByte(r.Value(), 0) >= 0 {
				t.Fatalf("bad value from %q", s)
			}
		}
		text := d.Render()
		back, err := Parse(text, Strict)
		if err != nil || !Equal(back, d) || back.Render() != text {
			t.Fatalf("not a fixed point: %q -> %q (%v)", s, text, err)
		}
	})
}

func FuzzObjectRef(f *testing.F) {
	for _, s := range []string{"<GUID=0102030405060708090a0b0c0d0e0f10>", "<SID=S-1-5-21-1-2-3-500>", "CN=a,DC=x", "<GUID=>)(cn=*"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		r, err := ParseObjectRef(s)
		if err != nil {
			return
		}
		out, err := r.ForRequest()
		if err != nil {
			return
		}
		r2, err := ParseObjectRef(out)
		if err != nil {
			t.Fatalf("%q -> %q does not reparse: %v", s, out, err)
		}
		if out2, _ := r2.ForRequest(); out2 != out {
			t.Fatalf("ForRequest not stable: %q vs %q", out, out2)
		}
	})
}

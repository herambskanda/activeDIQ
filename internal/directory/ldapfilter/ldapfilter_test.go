package ldapfilter

import (
	"bytes"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/attr/sid"
	"github.com/skenzeriq/activediq/internal/platform/corpus"
	"github.com/skenzeriq/activediq/internal/platform/corpus/corpustest"
)

// testSchema is the slice of the AD schema the vectors use.
var testSchema = NewSchema(
	AttrInfo{Name: "cn", Syntax: SynString},
	AttrInfo{Name: "mail", Syntax: SynString},
	AttrInfo{Name: "objectClass", Syntax: SynString},
	AttrInfo{Name: "objectGUID", Syntax: SynGUID},
	AttrInfo{Name: "objectSid", Syntax: SynSID},
	AttrInfo{Name: "manager", Syntax: SynDN},
	AttrInfo{Name: "memberOf", Syntax: SynDN},
	AttrInfo{Name: "member", Syntax: SynDN},
	AttrInfo{Name: "groupType", Syntax: SynInt32},
	AttrInfo{Name: "userAccountControl", Syntax: SynInt32},
	AttrInfo{Name: "sAMAccountType", Syntax: SynInt32},
	AttrInfo{Name: "pwdLastSet", Syntax: SynInt64},
	AttrInfo{Name: "whenCreated", Syntax: SynGenTime},
	AttrInfo{Name: "msDS-User-Account-Control-Computed", Syntax: SynInt32, Constructed: true},
	AttrInfo{Name: "unicodePwd", OID: "1.2.840.113556.1.4.90", Syntax: SynOctet},
	AttrInfo{Name: "customSecret", OID: "1.2.3.4.5", Syntax: SynString, Secret: true},
)

// textDN stands in for P2 (internal/directory/dn, T-0102): its text is already canonical.
type textDN string

func (d textDN) CanonicalString() string { return string(d) }

func attrOf(t testing.TB, r corpus.Record, name string) (AttrName, error) {
	in, err := r.Arg(name)
	if err != nil {
		t.Fatal(err)
	}
	return ParseAttrName(in.Text(), testSchema)
}

func valueOf(r corpus.Record, vname string) (Value, error) {
	in, err := r.Arg(vname)
	if err != nil {
		return Value{}, err
	}
	k := "string"
	if _, ok := r.Args["kind"]; ok && vname == "value" {
		kin, _ := r.Arg("kind")
		k = kin.Text()
	}
	switch k {
	case "string":
		return String(in.Text()), nil
	case "bytes":
		return Bytes(in.Raw), nil
	case "guid":
		g, err := guid.FromBytes(in.Raw)
		return GUID(g), err
	case "sid":
		s, err := sid.FromBytes(in.Raw)
		return SID(s), err
	case "dn":
		return DNValue(textDN(in.Text())), nil
	case "int32":
		n, err := strconv.ParseInt(in.Text(), 10, 32)
		return Int32(int32(n)), err
	case "int64":
		n, err := strconv.ParseInt(in.Text(), 10, 64)
		return Int64(n), err
	case "gentime":
		return GeneralizedTime(time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)), nil
	}
	return Value{}, corpustest.Skip("unknown kind " + k)
}

func result(f Filter, err error) corpus.Result {
	if err != nil {
		return corpustest.Err(Code(err))
	}
	s, err := Render(f, testSchema)
	if err != nil {
		return corpustest.Err(Code(err))
	}
	return corpustest.Render(string(s))
}

func TestCorpus(t *testing.T) {
	corpustest.Run(t, "go/ldapfilter", "ldapfilter", func(r corpus.Record) (corpus.Result, error) {
		if r.Call == "Or" {
			return result(Or(), nil), nil
		}
		if r.Call == "ParseAttrName" {
			in, err := r.Arg("value")
			if err != nil {
				return corpus.Result{}, err
			}
			n, err := ParseAttrName(in.Text(), testSchema)
			if err != nil {
				return corpustest.Err(Code(err)), nil
			}
			return corpustest.Render(n.String()), nil
		}
		a, aerr := attrOf(t, r, "attr")
		if aerr != nil {
			return corpustest.Err(Code(aerr)), nil
		}
		switch r.Call {
		case "Eq", "Ge", "Le", "Approx", "AndEq", "InChain":
			var v Value
			var err error
			if r.Call == "InChain" {
				in, _ := r.Arg("value")
				v = DNValue(textDN(in.Text()))
			} else if v, err = valueOf(r, "value"); err != nil {
				return corpus.Result{}, err
			}
			switch r.Call {
			case "Eq":
				return result(Eq(a, v), nil), nil
			case "Ge":
				return result(Ge(a, v), nil), nil
			case "Le":
				return result(Le(a, v), nil), nil
			case "Approx":
				return result(Approx(a, v), nil), nil
			case "InChain":
				in, _ := r.Arg("value")
				return result(InChain(a, textDN(in.Text())), nil), nil
			}
			a2, aerr := attrOf(t, r, "attr2")
			if aerr != nil {
				return corpustest.Err(Code(aerr)), nil
			}
			in2, _ := r.Arg("value2")
			return result(And(Eq(a, v), Eq(a2, String(in2.Text()))), nil), nil
		case "Prefix", "Contains":
			in, _ := r.Arg("value")
			if r.Call == "Prefix" {
				return result(Prefix(a, in.Text()), nil), nil
			}
			return result(Contains(a, in.Text()), nil), nil
		case "BitAnd":
			in, _ := r.Arg("mask")
			n, err := strconv.ParseUint(in.Text(), 10, 32)
			if err != nil {
				return corpus.Result{}, err
			}
			return result(BitAnd(a, uint32(n)), nil), nil
		case "NotPresent":
			return result(Not(Present(a)), nil), nil
		}
		return corpus.Result{}, corpustest.Skip("unknown call " + r.Call)
	})
}

func must(t *testing.T, name string) AttrName {
	t.Helper()
	a, err := ParseAttrName(name, testSchema)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func wantCode(t *testing.T, f Filter, code string) {
	t.Helper()
	if _, err := Render(f, testSchema); Code(err) != code {
		t.Fatalf("Render error = %v, want %s", err, code)
	}
}

func TestLimits(t *testing.T) {
	cn := must(t, "cn")
	var f Filter = Eq(cn, String("x"))
	for i := 0; i < MaxDepth; i++ {
		f = Not(f)
	}
	wantCode(t, f, TooDeep)
	f = Eq(cn, String("x"))
	for i := 0; i < MaxDepth-2; i++ {
		f = Not(f)
	}
	if _, err := Render(f, testSchema); err != nil {
		t.Fatalf("depth %d: %v", MaxDepth-1, err)
	}
	kids := make([]Filter, MaxFanOut+1)
	for i := range kids {
		kids[i] = Present(cn)
	}
	wantCode(t, Or(kids...), TooWide)
	many := make([]Filter, 0, 600)
	for i := 0; i < 600; i++ {
		many = append(many, And(Present(cn)))
	}
	wantCode(t, And(And(many[:200]...), And(many[200:400]...), And(many[400:]...)), TooManyNodes)
	big := String(strings.Repeat("a", MaxValueBytes))
	if _, err := Render(Eq(cn, big), testSchema); err != nil {
		t.Fatalf("value at the limit: %v", err)
	}
	// Each value is within its limit, the whole filter is not.
	parts := make([]Filter, 0, 5)
	for i := 0; i < 5; i++ {
		parts = append(parts, Eq(cn, String(strings.Repeat("\x01", MaxValueBytes/2))))
	}
	wantCode(t, And(parts...), FilterTooLong)
}

func TestZeroValuesAreRefused(t *testing.T) {
	wantCode(t, nil, InvalidFilter)
	wantCode(t, Eq(AttrName{}, String("x")), InvalidAttributeName)
	wantCode(t, Eq(must(t, "cn"), Value{}), InvalidValue)
	wantCode(t, And(nil), InvalidFilter)
	wantCode(t, Not(nil), InvalidFilter)
	wantCode(t, Eq(must(t, "manager"), DNValue(nil)), InvalidValue)
	if _, err := Render(Present(must(t, "cn")), nil); Code(err) != UnknownAttribute {
		t.Fatalf("nil schema: %v", err)
	}
}

func TestSubstringShapes(t *testing.T) {
	cn := must(t, "cn")
	got, err := Render(Substring(cn, "a*", []string{"(", "b"}, "\\z"), testSchema)
	if err != nil || got != `(cn=a\2a*\28*b*\5cz)` {
		t.Fatalf("got %q, %v", got, err)
	}
	wantCode(t, Substring(cn, "a", []string{""}, "b"), EmptySubstring)
	wantCode(t, Substring(cn, "", nil, ""), EmptySubstring)
	wantCode(t, Substring(cn, "a\x00", nil, ""), NulInString)
	wantCode(t, Prefix(must(t, "groupType"), "1"), ValueKindMismatch)
}

func TestBitMasksAreUnsignedDecimal(t *testing.T) {
	got, err := Render(BitOr(must(t, "groupType"), 0xFFFFFFFF), testSchema)
	if err != nil || got != "(groupType:1.2.840.113556.1.4.804:=4294967295)" {
		t.Fatalf("got %q, %v", got, err)
	}
	wantCode(t, BitAnd(must(t, "cn"), 1), ValueKindMismatch)
}

func TestInChainIsExpensive(t *testing.T) {
	f := And(Present(must(t, "cn")), Not(InChain(must(t, "memberOf"), textDN("CN=G,DC=x"))))
	if !IsExpensive(f) || IsExpensive(Present(must(t, "cn"))) {
		t.Fatal("IsExpensive wrong")
	}
	wantCode(t, InChain(must(t, "cn"), textDN("CN=G")), ValueKindMismatch)
}

func TestParseAttrNameGrammar(t *testing.T) {
	sc := NewSchema(AttrInfo{Name: "cn", Syntax: SynString}, AttrInfo{Name: "commonName", OID: "2.5.4.3", Syntax: SynString})
	for in, code := range map[string]string{
		"": InvalidAttributeName, "1cn": InvalidAttributeName, "-cn": InvalidAttributeName, "c n": InvalidAttributeName,
		"cn)": InvalidAttributeName, "cn\x00": InvalidAttributeName, "cn:dn": InvalidAttributeName, "cn,": InvalidAttributeName,
		"2.5.": InvalidAttributeName, "2..5": InvalidAttributeName, "02.5": InvalidAttributeName, "2.5.4.x": InvalidAttributeName,
		"cn;x": AttributeOptionsNotAllowed, "cn;": AttributeOptionsNotAllowed, "ünï": InvalidAttributeName,
		strings.Repeat("a", 129): InvalidAttributeName, "nope": UnknownAttribute,
	} {
		if _, err := ParseAttrName(in, sc); Code(err) != code {
			t.Errorf("ParseAttrName(%q) = %v, want %s", in, err, code)
		}
	}
	for _, in := range []string{"cn", "CN", "2.5.4.3"} {
		if _, err := ParseAttrName(in, sc); err != nil {
			t.Errorf("ParseAttrName(%q): %v", in, err)
		}
	}
}

func TestOIDResolvesToOneEntry(t *testing.T) {
	sc := NewSchema(
		AttrInfo{Name: "unicodePwd", OID: "1.2.840.113556.1.4.90", Syntax: SynOctet},
		AttrInfo{Name: "ms-Mcs-AdmPwd", OID: "1.2.840.113556.1.8000.2554.50051.45980.28112.18903.35903.6685103.1234.1.1", Syntax: SynString},
		AttrInfo{Name: "customSecret", OID: "1.2.3.4.5", Syntax: SynString, Secret: true},
		AttrInfo{Name: "cn", OID: "2.5.4.3", Syntax: SynString},
		AttrInfo{Name: "9.9.9", Syntax: SynString}, // OID-shaped Name: refused
	)
	for _, oid := range []string{"1.2.840.113556.1.4.90", "1.2.840.113556.1.8000.2554.50051.45980.28112.18903.35903.6685103.1234.1.1", "1.2.3.4.5"} {
		a, err := ParseAttrName(oid, sc)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range []Filter{Eq(a, String("x")), Ge(a, String("x")), Present(a), Contains(a, "x")} {
			if _, err := Render(f, sc); Code(err) != SecretAttribute {
				t.Errorf("%s: want SecretAttribute, got %v", oid, err)
			}
		}
	}
	if _, err := ParseAttrName("9.9.9", sc); Code(err) != UnknownAttribute {
		t.Errorf("OID-shaped Name admitted: %v", err)
	}
	a, _ := ParseAttrName("2.5.4.3", sc)
	got, err := Render(Present(a), sc)
	if err != nil || got != "(cn=*)" {
		t.Errorf("got %q %v", got, err)
	}
}

func TestErrorCarriesNoValue(t *testing.T) {
	_, err := Render(Eq(must(t, "cn"), String("secret\x00")), testSchema)
	var e *Error
	if !errors.As(err, &e) || strings.Contains(err.Error(), "secret") {
		t.Fatalf("error %v leaks the value", err)
	}
}

// unescape is an independent reading of RFC 4515 values: \hh pairs decode, nothing else is special.
func unescape(s string) ([]byte, bool) {
	var out []byte
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			out = append(out, s[i])
			continue
		}
		if i+2 >= len(s) {
			return nil, false
		}
		n, err := strconv.ParseUint(s[i+1:i+3], 16, 8)
		if err != nil {
			return nil, false
		}
		out = append(out, byte(n))
		i += 2
	}
	return out, true
}

func FuzzFilter(f *testing.F) {
	corpustest.Seed(f, "ldapfilter")
	cn := AttrName{"cn"}
	f.Fuzz(func(t *testing.T, in []byte) {
		out, err := Render(Eq(cn, String(string(in))), testSchema)
		if err != nil {
			return
		}
		s := string(out)
		data := strings.TrimSuffix(strings.TrimPrefix(s, "(cn="), ")")
		if data == s || len(data) == len(s) {
			t.Fatalf("structure lost: %q", s)
		}
		corpustest.NoUnescapedSpecial(t, data, "*()\x00/") // roundtrip below covers the backslash
		back, ok := unescape(data)                         // roundtrip: render, then read the octets back
		if !ok || !bytes.Equal(back, in) {
			t.Fatalf("roundtrip: %q -> %q -> %x", in, s, back)
		}
		sub, err := Render(Substring(cn, string(in), []string{string(in)}, string(in)), testSchema)
		if err != nil {
			t.Fatalf("substring of a renderable value: %v", err)
		}
		inner := strings.TrimSuffix(strings.TrimPrefix(string(sub), "(cn="), ")")
		if got := strings.Count(inner, "*"); got != 2 {
			t.Fatalf("substring has %d structural stars, want 2: %q", got, sub)
		}
	})
}

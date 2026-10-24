package ldapfilter

import (
	"errors"
	"strings"
	"testing"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/skenzeriq/activediq/internal/directory/dn"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// restrictedCaller cannot read anything under OU=Restricted.
type restrictedCaller struct{}

func (restrictedCaller) CanReadObject(d dn.DN) (bool, error) {
	return !strings.Contains(d.String(), "OU=Restricted"), nil
}

type brokenCaller struct{}

func (brokenCaller) CanReadObject(dn.DN) (bool, error) { return false, errors.New("dc down") }

func parseCode(s string, c Caller, l Limits) string {
	_, err := ParseAdminFilter(s, testSchema, c, l)
	return Code(err)
}

func TestParseAdminFilterRejects(t *testing.T) {
	for in, want := range map[string]string{
		"":                          SyntaxError,
		"()":                        SyntaxError,
		"(cn)":                      SyntaxError,
		"(&(cn=a)":                  SyntaxError,
		"(&cn=a)":                   SyntaxError,
		"(!(cn=a)(cn=b))":           SyntaxError,
		"( cn=a)":                   SyntaxError,
		"(cn=a(b))":                 SyntaxError,
		"(cn>=a*)":                  SyntaxError,
		"(&)":                       EmptyComposite,
		"(unicodePwd=*)":            ForbiddenAttribute,
		"(UNICODEPWD=x)":            ForbiddenAttribute,
		"(1.2.840.113556.1.4.90=x)": ForbiddenAttribute,
		"(customSecret=x)":          ForbiddenAttribute,
		"(nosuch=x)":                UnknownAttribute,
		"(msDS-User-Account-Control-Computed=16)": ConstructedNotFilterable,
		"(cn:=x)":                           UnsupportedMatchingRule,
		"(cn:dn:1.2.840.113556.1.4.803:=x)": UnsupportedMatchingRule,
		"(userAccountControl:1.2.840.113556.1.4.803:=-1)":         InvalidValue,
		"(userAccountControl:1.2.840.113556.1.4.803:=4294967296)": InvalidValue,
		"(cn:1.2.840.113556.1.4.803:=2)":                          ValueKindMismatch,
		"(userAccountControl=abc)":                                InvalidValue,
		"(cn=\xff)":                                               InvalidUTF8,
		"(cn=\\00)":                                               NulInString,
		"(manager=CN=a*)":                                         SubstringOnDN,
		"(manager=not a dn)":                                      InvalidValue,
		"(cn=a\\":                                                 InvalidEscape,
	} {
		if got := parseCode(in, restrictedCaller{}, Limits{}); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
}

func TestParseAdminFilterLimits(t *testing.T) {
	nest := func(n int) string { return strings.Repeat("(!", n) + "(cn=a)" + strings.Repeat(")", n) }
	if got := parseCode(nest(MaxDepth-1), nil, Limits{}); got != "" {
		t.Errorf("depth at the limit: %q", got)
	}
	if got := parseCode(nest(MaxDepth), nil, Limits{}); got != TooDeep {
		t.Errorf("depth over the limit: %q", got)
	}
	if got := parseCode(nest(200000), nil, Limits{MaxFilterBytes: 1 << 30}); got != FilterTooLong && got != TooDeep {
		t.Errorf("huge nesting: %q", got)
	}
	if got := parseCode(nest(10), nil, Limits{MaxDepth: 5}); got != TooDeep {
		t.Errorf("narrowed depth: %q", got)
	}
	if got := parseCode(nest(10), nil, Limits{MaxDepth: 1 << 20}); got != "" {
		t.Errorf("a caller cannot widen limits but 10 deep must pass: %q", got)
	}
	wide := "(|" + strings.Repeat("(cn=a)", MaxFanOut+1) + ")"
	if got := parseCode(wide, nil, Limits{MaxNodes: 1 << 20}); got != TooWide {
		t.Errorf("fan-out: %q", got)
	}
	many := "(&" + strings.Repeat("(|(cn=a)(cn=b))", 200) + ")"
	if got := parseCode(many, nil, Limits{}); got != TooManyNodes {
		t.Errorf("nodes: %q", got)
	}
	if got := parseCode("(cn="+strings.Repeat("a", MaxValueBytes+1)+")", nil, Limits{}); got != ValueTooLong {
		t.Errorf("value: %q", got)
	}
	if got := parseCode("(cn=a)", nil, Limits{MaxFilterBytes: 3}); got != FilterTooLong {
		t.Errorf("input bytes: %q", got)
	}
}

func TestParseAdminFilterDNReadability(t *testing.T) {
	const ok = "(memberOf=CN=Staff,OU=Groups,DC=corp,DC=example)"
	const secret = "(memberOf=CN=Project X,OU=Restricted,DC=corp,DC=example)"
	if got := parseCode(ok, restrictedCaller{}, Limits{}); got != "" {
		t.Errorf("readable: %q", got)
	}
	for _, in := range []string{secret, "(manager<=CN=x,OU=Restricted,DC=a)", "(memberOf:1.2.840.113556.1.4.1941:=CN=x,OU=Restricted,DC=a)"} {
		if got := parseCode(in, restrictedCaller{}, Limits{}); got != ReferencedObjectNotReadable {
			t.Errorf("%q: %q", in, got)
		}
	}
	// Existence must not leak: an unreadable DN and a missing one answer the same way.
	if got := parseCode(ok, nil, Limits{}); got != ReferencedObjectNotReadable {
		t.Errorf("nil caller must fail closed: %q", got)
	}
	if got := parseCode(ok, brokenCaller{}, Limits{}); got != ReferenceCheckFailed {
		t.Errorf("caller error: %q", got)
	}
	// A DN escaped at the filter layer arrives at the DN parser intact.
	f, err := ParseAdminFilter(`(manager=CN=Smith\5c, John,OU=Sales,DC=corp,DC=example)`, testSchema, restrictedCaller{}, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	s, _ := Render(f, testSchema)
	if want := `(manager=CN=Smith\5c, John,OU=Sales,DC=corp,DC=example)`; string(s) != want {
		t.Errorf("got %s want %s", s, want)
	}
}

func TestParseAdminFilterRendersCanonically(t *testing.T) {
	for in, want := range map[string]string{
		`(&(cn=a*b*c)(|(mail=x*)(!(cn=*))))`: `(&(cn=a*b*c)(|(mail=x*)(!(cn=*))))`,
		`(cn=*a*)`:                           `(cn=*a*)`,
		`(cn=a\2Ab)`:                         `(cn=a\2ab)`,
		`(cn=\41)`:                           `(cn=A)`,
		`(pwdLastSet>=132000000000000000)`:   `(pwdLastSet>=132000000000000000)`,
		`(userAccountControl<=5)`:            `(userAccountControl<=5)`,
		`(cn~=smyth)`:                        `(cn~=smyth)`,
		`(whenCreated>=20240102030405.0Z)`:   `(whenCreated>=20240102030405.0Z)`,
		`(objectGUID=\01\02\03\04\05\06\07\08\09\0a\0b\0c\0d\0e\0f\10)`: `(objectGUID=\01\02\03\04\05\06\07\08\09\0a\0b\0c\0d\0e\0f\10)`,
	} {
		f, err := ParseAdminFilter(in, testSchema, nil, Limits{})
		if err != nil {
			t.Errorf("%s: %v", in, err)
			continue
		}
		if s, _ := Render(f, testSchema); string(s) != want {
			t.Errorf("%s: got %s want %s", in, s, want)
		}
	}
}

func FuzzParseAdminFilter(f *testing.F) {
	for _, s := range []string{"(cn=a)", "(&(cn=a*b)(!(mail=*)))", `(cn=\2a)`, "(memberOf:1.2.840.113556.1.4.1941:=CN=a,DC=b)", "(|(cn=a)(cn=b))"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		f1, err := ParseAdminFilter(in, testSchema, allowAll{}, Limits{})
		if err != nil {
			return
		}
		r1, err := Render(f1, testSchema)
		if err != nil {
			t.Fatalf("a parsed filter must render: %v", err)
		}
		// Idempotent: the canonical text parses back to the same canonical text.
		f2, err := ParseAdminFilter(string(r1), testSchema, allowAll{}, Limits{})
		if err != nil {
			t.Fatalf("canonical %q does not reparse: %v", r1, err)
		}
		if r2, _ := Render(f2, testSchema); r1 != r2 {
			t.Fatalf("not idempotent: %q -> %q", r1, r2)
		}
	})
}

type allowAll struct{}

func (allowAll) CanReadObject(dn.DN) (bool, error) { return true, nil }

func ast(n func(*connectorv1.Filter)) *connectorv1.Filter { m := &connectorv1.Filter{}; n(m); return m }

func eqText(attr, v string) *connectorv1.Filter {
	return &connectorv1.Filter{Node: &connectorv1.Filter_Equal{Equal: &connectorv1.Comparison{Attribute: attr,
		Value: &connectorv1.FilterValue{Value: &connectorv1.FilterValue_Text{Text: v}}}}}
}

func TestParseFilterAST(t *testing.T) {
	list := func(k ...*connectorv1.Filter) *connectorv1.FilterList { return &connectorv1.FilterList{Children: k} }
	good := &connectorv1.Filter{Node: &connectorv1.Filter_And{And: list(eqText("cn", "*)(uid=*"),
		&connectorv1.Filter{Node: &connectorv1.Filter_Not{Not: &connectorv1.Filter{Node: &connectorv1.Filter_Present{Present: "mail"}}}})}}
	f, err := ParseFilterAST(good, testSchema, nil, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if s, _ := Render(f, testSchema); string(s) != `(&(cn=\2a\29\28uid=\2a)(!(mail=*)))` {
		t.Errorf("got %s", s)
	}
	deep := eqText("cn", "a")
	for i := 0; i < 10000; i++ {
		deep = &connectorv1.Filter{Node: &connectorv1.Filter_Not{Not: deep}}
	}
	badGUIDKind := eqText("objectGUID", "04030201-0605-0807-090a-0b0c0d0e0f10")
	dnAt := func(a, ou string) *connectorv1.Filter {
		return &connectorv1.Filter{Node: &connectorv1.Filter_Equal{Equal: &connectorv1.Comparison{Attribute: a,
			Value: &connectorv1.FilterValue{Value: &connectorv1.FilterValue_Dn{Dn: &connectorv1.Dn{Rdns: []*connectorv1.Rdn{
				{Type: "CN", Value: &connectorv1.Rdn_Text{Text: "Project X, Inc"}},
				{Type: "OU", Value: &connectorv1.Rdn_Text{Text: ou}},
				{Type: "DC", Value: &connectorv1.Rdn_Text{Text: "corp"}}}}}}}}}
	}
	nanos := &connectorv1.Filter{Node: &connectorv1.Filter_Equal{Equal: &connectorv1.Comparison{Attribute: "pwdLastSet",
		Value: &connectorv1.FilterValue{Value: &connectorv1.FilterValue_FileTime{FileTime: &timestamppb.Timestamp{Seconds: 1700000000, Nanos: 150}}}}}}
	for name, c := range map[string]struct {
		in   *connectorv1.Filter
		want string
	}{
		"nil":            {nil, InvalidFilter},
		"empty node":     {&connectorv1.Filter{}, InvalidFilter},
		"empty and":      {ast(func(m *connectorv1.Filter) { m.Node = &connectorv1.Filter_And{And: list()} }), EmptyComposite},
		"secret":         {eqText("unicodePwd", "x"), ForbiddenAttribute},
		"secret present": {&connectorv1.Filter{Node: &connectorv1.Filter_Present{Present: "msLAPS-EncryptedPasswordHistory"}}, ForbiddenAttribute},
		"options":        {eqText("cn;binary", "x"), AttributeOptionsNotAllowed},
		"deep":           {deep, TooDeep},
		"kind":           {badGUIDKind, ValueKindMismatch},
		"empty value":    {eqText("cn", ""), EmptyAssertion},
		"no value":       {&connectorv1.Filter{Node: &connectorv1.Filter_Equal{Equal: &connectorv1.Comparison{Attribute: "cn"}}}, InvalidValue},
		"unreadable dn":  {dnAt("memberOf", "Restricted"), ReferencedObjectNotReadable},
		"sub-100ns":      {nanos, InvalidValue},
		"wide": {ast(func(m *connectorv1.Filter) {
			k := make([]*connectorv1.Filter, MaxFanOut+1)
			for i := range k {
				k[i] = eqText("cn", "a")
			}
			m.Node = &connectorv1.Filter_Or{Or: list(k...)}
		}), TooWide},
		"substring on dn": {&connectorv1.Filter{Node: &connectorv1.Filter_Substring{Substring: &connectorv1.Substring{Attribute: "manager", Any: []string{"x"}}}}, SubstringOnDN},
		"empty substring": {&connectorv1.Filter{Node: &connectorv1.Filter_Substring{Substring: &connectorv1.Substring{Attribute: "cn"}}}, EmptySubstring},
		"bit and on text": {&connectorv1.Filter{Node: &connectorv1.Filter_BitAnd{BitAnd: &connectorv1.BitMatch{Attribute: "cn", Mask: 2}}}, ValueKindMismatch},
	} {
		if _, err := ParseFilterAST(c.in, testSchema, restrictedCaller{}, Limits{}); Code(err) != c.want {
			t.Errorf("%s: got %q want %q", name, Code(err), c.want)
		}
	}
	// A readable DN renders through the P2 builder: the comma in the value is escaped.
	f, err = ParseFilterAST(dnAt("memberOf", "Groups"), testSchema, restrictedCaller{}, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if s, _ := Render(f, testSchema); string(s) != `(memberOf=CN=Project X\5c, Inc,OU=Groups,DC=corp)` {
		t.Errorf("got %s", s)
	}
}

func TestParseFilterASTJSON(t *testing.T) {
	f, err := ParseFilterASTJSON([]byte(`{"and":{"children":[{"equal":{"attribute":"cn","value":{"text":"a*"}}},{"bitAnd":{"attribute":"userAccountControl","mask":2}}]}}`), testSchema, nil, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if s, _ := Render(f, testSchema); string(s) != `(&(cn=a\2a)(userAccountControl:1.2.840.113556.1.4.803:=2))` {
		t.Errorf("got %s", s)
	}
	for in, want := range map[string]string{
		`{`:                        SyntaxError,
		`{"nosuch":1}`:             SyntaxError,
		`{}`:                       InvalidFilter,
		`{"present":"unicodePwd"}`: ForbiddenAttribute,
	} {
		if _, err := ParseFilterASTJSON([]byte(in), testSchema, nil, Limits{}); Code(err) != want {
			t.Errorf("%s: got %q want %q", in, Code(err), want)
		}
	}
	if _, err := ParseFilterASTJSON(make([]byte, 5*MaxFilterBytes), testSchema, nil, Limits{}); Code(err) != FilterTooLong {
		t.Errorf("oversize JSON: %v", err)
	}
}

func TestParseFilterASTNarrowedMaxValueBytes(t *testing.T) {
	long := strings.Repeat("a", 100)
	sub := func(s *connectorv1.Substring) *connectorv1.Filter {
		s.Attribute = "cn"
		return &connectorv1.Filter{Node: &connectorv1.Filter_Substring{Substring: s}}
	}
	cases := map[string]*connectorv1.Filter{
		"text":    eqText("cn", long),
		"initial": sub(&connectorv1.Substring{Initial: &long}),
		"any":     sub(&connectorv1.Substring{Any: []string{long}}),
		"final":   sub(&connectorv1.Substring{Final: &long}),
		"octets": {Node: &connectorv1.Filter_Equal{Equal: &connectorv1.Comparison{Attribute: "cn",
			Value: &connectorv1.FilterValue{Value: &connectorv1.FilterValue_Octets{Octets: []byte(long)}}}}},
	}
	for name, in := range cases {
		if _, err := ParseFilterAST(in, testSchema, nil, Limits{MaxValueBytes: 10}); Code(err) != ValueTooLong {
			t.Errorf("%s: got %v", name, err)
		}
		if _, err := ParseFilterAST(in, testSchema, nil, Limits{}); Code(err) == ValueTooLong {
			t.Errorf("%s: default limits must accept 100 bytes", name)
		}
	}
}

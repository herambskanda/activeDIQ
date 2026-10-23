package scan

import (
	"sort"
	"strings"
	"testing"
)

// The OData fixtures FX-1 to FX-11 and the negative controls FX-N1 and FX-N2 of
// knowledge/development/architecture/safe-primitives-odata.md §6. Each fixture is product code
// outside the odata home; each must produce exactly the named rules, and the controls none.

// odataStubs is a minimal odata and graphschema pair so the fixtures type-check for the go/analysis
// passes. The real packages live in internal/directory/odata.
var odataStubs = map[string]string{
	"internal/directory/odata/odata.go": `package odata

import "net/url"

type Name string
type String string
type Prop[V any] struct{ n Name }
type Filter struct{}
type Query struct{}
type Segment struct{}
type Request struct{}

func StringProp(n Name) Prop[String]                 { return Prop[String]{n} }
func Eq[V any](p Prop[V], v V) Filter                { return Filter{} }
func (Query) Filter(f Filter) Query                  { return Query{} }
func Seg(n Name) Segment                             { return Segment{} }
func Get(s ...Segment) Request                       { return Request{} }
func (Request) With(q Query) Request                 { return Request{} }
func (Request) URL(b *url.URL) *url.URL              { return b }
`,
	"internal/directory/odata/graphschema/graphschema.go": `package graphschema

import "fx.test/internal/directory/odata"

var UserPrincipalName = odata.StringProp("userPrincipalName")
`,
}

func withStubs(files map[string]string) map[string]string {
	for k, v := range odataStubs {
		files[k] = v
	}
	return files
}

const (
	fxFile   = "internal/modules/m/m.go"
	fxGraph  = "internal/connector/graph/g.go"
	fxHeader = "package m\n\nimport (\n\t\"fmt\"\n\t\"net/url\"\n\t\"strings\"\n\n\t\"fx.test/internal/directory/odata\"\n\t\"fx.test/internal/directory/odata/graphschema\"\n)\n\nvar (\n\t_ = fmt.Sprintf\n\t_ = url.Values{}\n\t_ = strings.Join\n\t_ = odata.Get\n\t_ = graphschema.UserPrincipalName\n)\n\n"
)

// odataRules returns the sorted, de-duplicated odata and quote-doubling rules reported in file by
// the literal scanner (FF-SP3) and the type-aware passes (FF-SP2).
func odataRules(t *testing.T, files map[string]string, file string, typed bool) []string {
	t.Helper()
	root := tree(t, withStubs(files))
	fs, err := Scan(root, AllChecks())
	if err != nil {
		t.Fatal(err)
	}
	if typed { // the type-aware passes load the module once per shipped platform: slow
		af, err := Analyze(root)
		if err != nil {
			t.Fatal(err)
		}
		fs = append(fs, af...)
	}
	set := map[string]bool{}
	for _, f := range fs {
		if f.File == file {
			set[f.Rule] = true
		}
	}
	var out []string
	for r := range set {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

func fixture(body string) map[string]string {
	return map[string]string{fxFile: fxHeader + body + "\n"}
}

func TestODataFixtures(t *testing.T) {
	fixtures := []struct {
		id    string
		files map[string]string
		file  string
		want  []string
		typed bool // needs the go/analysis passes
	}{
		{"FX-1 principalId filter (reads.go:198)", fixture(`func f(q url.Values, id string) { q.Set("$filter", "principalId eq '"+id+"'") }`), fxFile,
			[]string{"odata-filter-shape", "odata-option-literal"}, false},
		{"FX-2 appId key (reads.go:125)", fixture(`func f(id string) string { return "servicePrincipals(appId='" + id + "')" }`), fxFile,
			[]string{"odata-key-shape"}, false},
		{"FX-3 key with a verb", fixture(`func f(upn string) string { return fmt.Sprintf("users('%s')", upn) }`), fxFile,
			[]string{"odata-key-shape"}, false},
		{"FX-4 filter with a verb", fixture(`func f(n string) string { return fmt.Sprintf("displayName eq '%s'", n) }`), fxFile,
			[]string{"odata-filter-shape"}, false},
		{"FX-5 filter through a const", fixture(`func f(x string) string { const p = "mail eq '"; return p + x + "'" }`), fxFile,
			[]string{"odata-filter-shape"}, false},
		{"FX-6 startswith through Join", fixture(`func f(x string) string { return strings.Join([]string{"startswith(displayName,'", x, "')"}, "") }`), fxFile,
			[]string{"odata-filter-shape"}, false},
		{"FX-7 quote doubling", fixture(`func f(v string) string { return strings.ReplaceAll(v, "'", "''") }`), fxFile,
			[]string{"quote-doubling"}, false},
		{"FX-8a percent-encoded option", fixture(`func f(x string) string { return "%24filter=" + x }`), fxFile,
			[]string{"odata-option-literal"}, false},
		{"FX-8b bare option key", fixture(`func f(q url.Values, x string) { q.Add("filter", x) }`), fxFile,
			[]string{"odata-option-literal"}, false},
		{"FX-8c mixed-case option key", fixture(`func f(q url.Values, x string) { q.Set("$Search", x) }`), fxFile,
			[]string{"odata-option-literal"}, false},
		{"FX-9 constant filter outside the home", fixture(`func f(q url.Values) { q.Set("$filter", "isAssignableToRole eq true") }`), fxFile,
			[]string{"odata-option-literal"}, false},
		{"FX-10 RawQuery from Values.Encode in the Graph connector", map[string]string{fxGraph: "package graph\n\nimport \"net/url\"\n\nfunc f(u *url.URL, v url.Values) { u.RawQuery = v.Encode() }\n"}, fxGraph,
			[]string{"graph-url-assembly"}, true},
		{"FX-11 odata.Name from user input", fixture(`func f(userInput string) odata.Segment { return odata.Seg(odata.Name(userInput)) }`), fxFile,
			[]string{"odataname"}, true},
		{"FX-12 url.Parse of a concatenation into NewRequest", map[string]string{fxGraph: "package graph\n\nimport (\n\t\"net/http\"\n\t\"net/url\"\n)\n\nfunc f(base, upn string) { u, _ := url.Parse(base + \"/users/\" + upn); _, _ = http.NewRequest(\"GET\", u.String(), nil) }\n"}, fxGraph,
			[]string{"graph-url-assembly"}, true},
		{"FX-13 JoinPath with a variable into NewRequest", map[string]string{fxGraph: "package graph\n\nimport (\n\t\"net/http\"\n\t\"net/url\"\n)\n\nfunc f(b *url.URL, upn string) { u := b.JoinPath(\"users\", upn); _, _ = http.NewRequest(\"GET\", u.String(), nil) }\n"}, fxGraph,
			[]string{"graph-url-assembly"}, true},
		{"FX-14a Opaque literal", map[string]string{fxGraph: "package graph\n\nimport \"net/url\"\n\nfunc f(h, upn string) *url.URL { return &url.URL{Scheme: \"https\", Host: h, Opaque: \"//g/users/\" + upn} }\n"}, fxGraph,
			[]string{"graph-url-assembly"}, true},
		{"FX-14b Opaque assignment", map[string]string{fxGraph: "package graph\n\nimport \"net/url\"\n\nfunc f(u *url.URL, upn string) { u.Opaque = \"//g/users/\" + upn }\n"}, fxGraph,
			[]string{"graph-url-assembly"}, true},
		{"FX-15 Host assignment", map[string]string{fxGraph: "package graph\n\nimport \"net/url\"\n\nfunc f(u *url.URL, h string) { u.Host = h }\n"}, fxGraph,
			[]string{"graph-url-assembly"}, true},
		{"FX-16 url.Parse as a function value", map[string]string{fxGraph: "package graph\n\nimport \"net/url\"\n\nfunc f(base, upn string) { p := url.Parse; u, _ := p(base + upn); _ = u }\n"}, fxGraph,
			[]string{"graph-url-assembly"}, true},
		{"FX-17 NewRequest in an unlisted function", map[string]string{fxGraph: "package graph\n\nimport (\n\t\"net/http\"\n\t\"net/url\"\n)\n\nfunc f(u *url.URL) { _, _ = http.NewRequest(\"GET\", u.String(), nil) }\n"}, fxGraph,
			[]string{"graph-url-assembly"}, true},
		{"FX-18 http.Get, Client.Get, a Request literal with Do, and RoundTrip, and a func-valued send in an unlisted function", map[string]string{fxGraph: "package graph\n\nimport (\n\t\"net/http\"\n\t\"net/url\"\n)\n\nfunc f(c *http.Client, u *url.URL, b string, send func(*http.Request) (*http.Response, error)) {\n\t_, _ = http.Get(b + \"/users\")\n\t_, _ = c.Get(b + \"/users\")\n\t_, _ = c.Do(&http.Request{URL: u})\n\t_, _ = c.Transport.RoundTrip(&http.Request{URL: u})\n\t_, _ = send(&http.Request{URL: u})\n}\n"}, fxGraph,
			[]string{"graph-url-assembly"}, true},
		{"FX-8d count and skip options", fixture(`func f(x string) string { return "users?$count=true&$skip=" + x }`), fxFile,
			[]string{"odata-option-literal"}, false},
		{"FX-N1 the builder", fixture(`func f(v odata.String) odata.Request {
	return odata.Get(odata.Seg("users")).With(odata.Query{}.Filter(odata.Eq(graphschema.UserPrincipalName, v)))
}`), fxFile, nil, true},
		{"FX-N2 log text and a Filter field", fixture(`type opts struct{ Filter string }

func f() (string, opts) { return "filter applied", opts{Filter: "x"} }`), fxFile, nil, true},
	}
	for _, fx := range fixtures {
		t.Run(fx.id, func(t *testing.T) {
			got := odataRules(t, fx.files, fx.file, fx.typed)
			if strings.Join(got, ",") != strings.Join(fx.want, ",") {
				t.Fatalf("rules in %s: got %v, want %v", fx.file, got, fx.want)
			}
		})
	}
}

// Acceptance 2: the two lines of the pre-T-0117 reads.go (main 7cf9dfd :125 and :198), copied
// verbatim into a connector fixture, fail.
func TestODataPreMigrationReadsFail(t *testing.T) {
	const file = "internal/connector/graph/reads.go"
	src := `package graph

import "net/url"

type cfg struct{ ClientID string }
type Client struct{ cfg cfg }

func (c *Client) endpoint(q url.Values, p string) *url.URL { return nil }
func (c *Client) q(s string) url.Values                    { return nil }

func (c *Client) own() {
	_ = c.endpoint(c.q("id,appId,displayName,appRoles"), "servicePrincipals(appId='"+c.cfg.ClientID+"')")
}

func roles(principalID string) {
	q := url.Values{}
	q.Set("$filter", "principalId eq '"+principalID+"'")
	q.Set("$expand", "roleDefinition($select=id,displayName,templateId),principal($select=id)")
}
`
	got := odataRules(t, map[string]string{file: src}, file, true)
	for _, r := range []string{"odata-key-shape", "odata-filter-shape", "odata-option-literal"} {
		if !contains(got, r) {
			t.Errorf("pre-T-0117 reads.go lines not caught by %s; got %v", r, got)
		}
	}
}

// The helpers around the shape rules: the English word "filter", a bare ")" and prose with quotes
// are not OData.
func TestODataRulesIgnoreProse(t *testing.T) {
	for name, body := range map[string]string{
		"English word":       `func f(n int) string { return fmt.Sprintf("filter %d rows", n) }`,
		"quoted punctuation": `func f(k string) error { return fmt.Errorf("kind %q is lower-case letters, digits, '_' and '.' (at most 100)", k) }`,
		"closing paren":      `func f(x string) string { return "f(" + x }`[:0] + `func g(x string) string { return x + ")" }`,
		"own API query":      `func f(q url.Values) string { return q.Get("filter") }`,
	} {
		t.Run(name, func(t *testing.T) {
			if got := odataRules(t, fixture(body), fxFile, true); len(got) != 0 {
				t.Fatalf("expected no OData findings, got %v", got)
			}
		})
	}
}

// The home of the primitive and test files are not judged by the literal rules.
func TestODataHomeAndTestsExempt(t *testing.T) {
	home := "internal/directory/odata/render.go"
	test := "internal/modules/m/m_test.go"
	files := map[string]string{
		home: "package odata\n\nimport \"strings\"\n\nfunc r(q, v string) string { return \"$filter=\" + q + \" eq '\" + strings.ReplaceAll(v, \"'\", \"''\") + \"'\" }\n",
		test: "package m\n\nfunc f(x string) string { return \"$filter=a eq '\" + x + \"'\" }\n",
	}
	root := tree(t, withStubs(files))
	fs, err := Scan(root, AllChecks())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fs {
		if f.File == home || f.File == test {
			t.Fatalf("unexpected finding in an exempt file: %v", f)
		}
	}
}

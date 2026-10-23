package odata_test

import (
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/odata"
	"github.com/skenzeriq/activediq/internal/directory/odata/graphschema"
	"github.com/skenzeriq/activediq/internal/directory/odata/odatatest"
	"github.com/skenzeriq/activediq/internal/platform/corpus"
	"github.com/skenzeriq/activediq/internal/platform/corpus/corpustest"
)

var base = mustURL("https://graph.test/v1.0")

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

func code(err error) corpus.Result {
	if k := odata.KindOf(err); k != "" {
		return corpustest.Err(string(k))
	}
	return corpustest.Err("unexpected: " + err.Error())
}

func mustGUID(t testing.TB, s string) guid.GUID {
	t.Helper()
	g, err := guid.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// requestURI is the target a server sees: escaped path and raw query.
func requestURI(u *url.URL) string {
	s := u.EscapedPath()
	if u.RawQuery != "" {
		s += "?" + u.RawQuery
	}
	return s
}

func filterQuery(t testing.TB, f odata.Filter) (*url.URL, string) {
	t.Helper()
	u, err := odata.Get(odata.Seg("users")).With(odata.Query{}.Filter(f)).URL(base)
	if err != nil {
		t.Fatal(err)
	}
	q, ok := strings.CutPrefix(u.RawQuery, "$filter=")
	if !ok {
		t.Fatalf("query %q is not a lone $filter", u.RawQuery)
	}
	return u, q
}

// leaf is a constant filter used to build And shapes.
func leaf() odata.Filter { return odata.Eq(graphschema.GroupIsAssignableToRole, odata.BoolOf(true)) }

func filterResult(t testing.TB, r corpus.Record, f odata.Filter, want *odatatest.Node) (corpus.Result, error) {
	_, q := filterQuery(t, f)
	u, _ := odata.Get(odata.Seg("users")).With(odata.Query{}.Filter(f)).URL(base)
	got, err := odatatest.ParseRequest(requestURI(u), "/v1.0")
	if err != nil {
		return corpus.Result{}, err
	}
	if got.Filter == nil || len(got.Filter.Kids) != 0 && want == nil {
		return corpus.Result{}, errors.New("round trip lost the filter")
	}
	if want != nil && !sameNode(*got.Filter, *want) {
		return corpus.Result{}, errors.New("oracle parse differs from the input")
	}
	text := odata.Text(f)
	if k, _ := r.ExpectKey(); k == "value" {
		return corpustest.Value(map[string]string{"filter": text, "query": q})
	}
	return corpustest.Render(text), nil
}

func sameNode(a, b odatatest.Node) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

func TestCorpus(t *testing.T) {
	corpustest.Run(t, "go/odata", "odata", func(r corpus.Record) (corpus.Result, error) {
		if r.Kind != corpus.KindRuntime {
			return corpus.Result{}, corpustest.Skip("not a runtime record")
		}
		str := func(name string) string { in, _ := r.Arg(name); return in.Text() }
		switch r.Call {
		case "Str":
			in, err := r.Arg("value")
			if err != nil {
				return corpus.Result{}, err
			}
			s, err := odata.Str(in.Text())
			if err != nil {
				return code(err), nil
			}
			return corpustest.Render(odata.Text(odata.Eq(graphschema.UserPrincipalName, s))), nil
		case "Eq":
			s, err := odata.Str(str("value"))
			if err != nil {
				return code(err), nil
			}
			want := &odatatest.Node{Op: "eq", Prop: "userPrincipalName", Lits: []odatatest.Lit{{Kind: odatatest.LitString, Text: str("value")}}}
			return filterResult(t, r, odata.Eq(graphschema.UserPrincipalName, s), want)
		case "EqGUID":
			g := mustGUID(t, str("guid"))
			return filterResult(t, r, odata.Eq(graphschema.AppRoleAssignmentPrincipalID, odata.GUIDOf(g)), nil)
		case "EqGUIDText":
			g := mustGUID(t, str("guid"))
			return filterResult(t, r, odata.Eq(graphschema.RoleAssignmentPrincipalID, odata.GUIDTextOf(g)), nil)
		case "In":
			var vals []string
			if err := json.Unmarshal(r.Args["values"], &vals); err != nil {
				return corpus.Result{}, err
			}
			ss := make([]odata.String, len(vals))
			for i, v := range vals {
				s, err := odata.Str(v)
				if err != nil {
					return code(err), nil
				}
				ss[i] = s
			}
			f, err := odata.In(graphschema.UserPrincipalName, ss...)
			if err != nil {
				return code(err), nil
			}
			lits := make([]odatatest.Lit, len(vals))
			for i, v := range vals {
				lits[i] = odatatest.Lit{Kind: odatatest.LitString, Text: v}
			}
			return filterResult(t, r, f, &odatatest.Node{Op: "in", Prop: "userPrincipalName", Lits: lits})
		case "And":
			var depth, operands int
			_ = json.Unmarshal(r.Args["depth"], &depth)
			_ = json.Unmarshal(r.Args["operands"], &operands)
			var f odata.Filter = leaf()
			var err error
			for i := 0; i < depth && err == nil; i++ {
				f, err = odata.And(f, leaf())
			}
			if operands > 0 {
				fs := make([]odata.Filter, operands)
				for i := range fs {
					fs[i] = leaf()
				}
				f, err = odata.And(fs...)
			}
			if err != nil {
				return code(err), nil
			}
			return corpus.Result{}, errors.New("And was expected to fail")
		case "AndMixed":
			s, err := odata.Str(str("value"))
			if err != nil {
				return code(err), nil
			}
			f, err := odata.And(leaf(), odata.Eq(graphschema.DisplayName, s))
			if err != nil {
				return code(err), nil
			}
			return filterResult(t, r, f, &odatatest.Node{Op: "and", Kids: []odatatest.Node{
				{Op: "eq", Prop: "isAssignableToRole", Lits: []odatatest.Lit{{Kind: odatatest.LitBool, Text: "true"}}},
				{Op: "eq", Prop: "displayName", Lits: []odatatest.Lit{{Kind: odatatest.LitString, Text: str("value")}}}}})
		case "Key":
			u, err := odata.Get(odata.Seg(odata.Name(str("set"))), odata.Key(odata.GUIDOf(mustGUID(t, str("guid"))))).URL(base)
			return pathResult(t, u, err, odatatest.Segment{Kind: odatatest.SegName, Name: "users"}, 2)
		case "KeyStr":
			s, err := odata.Str(str("value"))
			if err != nil {
				return code(err), nil
			}
			seg, err := odata.KeyStr(odata.Name(str("set")), s)
			if err != nil {
				return code(err), nil
			}
			u, err := odata.Get(seg).URL(base)
			return pathResult(t, u, err, odatatest.Segment{Kind: odatatest.SegKeyStr, Name: str("set"), Val: odatatest.Lit{Kind: odatatest.LitString, Text: str("value")}}, 1)
		case "AltKeyStr":
			sv, err := odata.Str(str("value"))
			if err != nil {
				return code(err), nil
			}
			seg, err := odata.AltKey(odata.Name(str("set")), graphschema.UserPrincipalName, sv)
			if err != nil {
				return code(err), nil
			}
			u, err := odata.Get(seg).URL(base)
			return pathResult(t, u, err, odatatest.Segment{Kind: odatatest.SegAlt, Name: str("set"), Prop: "userPrincipalName", Val: odatatest.Lit{Kind: odatatest.LitString, Text: str("value")}}, 1)
		case "AltKey":
			var g guid.GUID // guid.Parse refuses the nil GUID, so the zero value stands for it
			if str("guid") != "00000000-0000-0000-0000-000000000000" {
				g = mustGUID(t, str("guid"))
			}
			seg, err := odata.AltKey(odata.Name(str("set")), graphschema.ServicePrincipalAppID, odata.GUIDTextOf(g))
			if err != nil {
				return code(err), nil
			}
			u, err := odata.Get(seg).URL(base)
			return pathResult(t, u, err, odatatest.Segment{Kind: odatatest.SegAlt, Name: str("set"), Prop: "appId", Val: odatatest.Lit{Kind: odatatest.LitString, Text: g.String()}}, 1)
		}
		return corpus.Result{}, corpustest.Skip("unknown call " + r.Call)
	})
}

// pathResult renders the raw path, and checks the oracle reads back the segment count and the keyed
// segment, with no query and no fragment.
func pathResult(t testing.TB, u *url.URL, err error, want odatatest.Segment, n int) (corpus.Result, error) {
	if err != nil {
		return code(err), nil
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return corpus.Result{}, errors.New("path rendered a query or fragment")
	}
	got, err := odatatest.ParseRequest(requestURI(u), "/v1.0")
	if err != nil {
		return corpus.Result{}, err
	}
	if len(got.Segments) != n || got.Segments[0] != want {
		return corpus.Result{}, errors.New("oracle parse differs from the input")
	}
	return corpustest.Render(u.EscapedPath()), nil
}

func TestPathDecodesToPath(t *testing.T) {
	s, err := odata.KeyStr("users", mustStr(t, "$a b@c'd"))
	if err != nil {
		t.Fatal(err)
	}
	u, err := odata.Get(s).URL(base)
	if err != nil {
		t.Fatal(err)
	}
	if u.Path != "/v1.0/users('$a b@c''d')" || u.EscapedPath() != "/v1.0/users('%24a%20b@c''d')" {
		t.Fatalf("Path=%q Escaped=%q", u.Path, u.EscapedPath())
	}
	if got := u.String(); got != "https://graph.test/v1.0/users('%24a%20b@c''d')" {
		t.Fatalf("String = %q", got)
	}
}

func mustStr(t testing.TB, s string) odata.String {
	t.Helper()
	v, err := odata.Str(s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestQueryOptions(t *testing.T) {
	q := odata.Query{}.
		Select(graphschema.ID, graphschema.DisplayName).
		Expand(graphschema.NavRoleDefinition, graphschema.ID, graphschema.TemplateID).
		Expand(graphschema.NavPrincipal, graphschema.ID).
		Filter(leaf()).Top(100).Count().OrderBy(graphschema.DisplayName, true)
	u, err := odata.Get(odata.Seg("groups")).With(q).URL(base)
	if err != nil {
		t.Fatal(err)
	}
	r, err := odatatest.ParseRequest(requestURI(u), "/v1.0")
	if err != nil {
		t.Fatalf("%v\n%s", err, u.RawQuery)
	}
	if r.Top != 100 || !r.Count || r.OrderBy != "displayName" || !r.Desc || len(r.Select) != 2 || len(r.Expand) != 2 ||
		r.Expand[0].Nav != "roleDefinition" || len(r.Expand[0].Select) != 2 || r.Filter == nil {
		t.Fatalf("parsed %+v", r)
	}
	if strings.Contains(u.RawQuery, "+") || strings.Contains(u.RawQuery, " ") {
		t.Fatalf("query %q has a + or space", u.RawQuery)
	}
	// Methods return copies: deriving from q leaves q unchanged.
	_ = q.Top(5).Expand("extra")
	if u2, _ := odata.Get(odata.Seg("groups")).With(q).URL(base); u2.RawQuery != u.RawQuery {
		t.Fatal("a derived Query changed its parent")
	}
}

func TestBadOptionsAreErrorsAtURL(t *testing.T) {
	for name, q := range map[string]odata.Query{
		"top zero":  odata.Query{}.Top(0),
		"top 1000":  odata.Query{}.Top(1000),
		"bad nav":   odata.Query{}.Expand("a b"),
		"zero prop": odata.Query{}.Select(odata.Prop[odata.String]{}),
	} {
		if _, err := odata.Get(odata.Seg("users")).With(q).URL(base); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if _, err := odata.Get(odata.Seg("a/b")).URL(base); odata.KindOf(err) != odata.InvalidName {
		t.Errorf("Seg(a/b) = %v", err)
	}
	if _, err := odata.Get(odata.Seg("..")).URL(base); odata.KindOf(err) != odata.InvalidName {
		t.Errorf("Seg(..) = %v", err)
	}
	if _, err := odata.Get(odata.Segment{}).URL(base); err == nil {
		t.Error("zero Segment accepted")
	}
	if _, err := odata.Get(odata.Cast("microsoft.graph.user")).URL(base); err != nil {
		t.Errorf("cast: %v", err)
	}
	if _, err := odata.Get(odata.Cast("microsoft..user")).URL(base); err == nil {
		t.Error("bad cast accepted")
	}
}

func TestURLLengthCap(t *testing.T) {
	s := mustStr(t, strings.Repeat("a", odata.MaxString))
	var fs []odata.Filter
	for range 3 {
		fs = append(fs, odata.Eq(graphschema.UserPrincipalName, s))
	}
	f, err := odata.And(fs...)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := odata.Get(odata.Seg("users")).With(odata.Query{}.Filter(f)).URL(base); odata.KindOf(err) != odata.TooLong {
		t.Fatalf("err = %v", err)
	}
}

func TestTimeLiteral(t *testing.T) {
	tm, err := odata.TimeOf(time.Date(2026, 10, 22, 14, 30, 0, 0, time.FixedZone("x", 3600)))
	if err != nil {
		t.Fatal(err)
	}
	if got := odata.Text(odata.Eq(odata.TimeProp("createdDateTime"), tm)); got != "createdDateTime eq 2026-10-22T13:30:00Z" {
		t.Fatalf("got %q", got)
	}
	if _, err := odata.TimeOf(time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("year 10000 accepted")
	}
	if got := odata.Text(odata.Eq(odata.IntProp("n"), odata.IntOf(-5))); got != "n eq -5" {
		t.Fatal(got)
	}
}

// Hostile values never become a second query option, a second literal or an extra path segment.
func FuzzOData(f *testing.F) {
	corpustest.Seed(f, "odata")
	f.Fuzz(func(t *testing.T, in []byte) {
		s, err := odata.Str(string(in))
		if err != nil {
			if k := odata.KindOf(err); k == "" {
				t.Fatalf("Str error is not typed: %v", err)
			}
			return
		}
		want := odatatest.Lit{Kind: odatatest.LitString, Text: string(in)}
		// Eq: roundtrip, one literal, one option.
		u, err := odata.Get(odata.Seg("users")).With(odata.Query{}.Filter(odata.Eq(graphschema.UserPrincipalName, s))).URL(base)
		if err == nil {
			r, perr := odatatest.ParseRequest(requestURI(u), "/v1.0")
			if perr != nil || r.Filter == nil || r.Filter.Op != "eq" || len(r.Filter.Lits) != 1 || r.Filter.Lits[0] != want {
				t.Fatalf("Eq(%q) rendered %q, oracle: %+v %v", in, u.RawQuery, r.Filter, perr)
			}
			if n := strings.Count(u.RawQuery, "&"); n != 0 {
				t.Fatalf("raw query %q has %d separators", u.RawQuery, n)
			}
			corpustest.NoUnescapedSpecial(t, strings.TrimPrefix(u.RawQuery, "$filter="), "&=#+ ()',$/\\")
		} else if odata.KindOf(err) != odata.TooLong {
			t.Fatalf("Eq URL: %v", err)
		}
		// In and And over the same value: literal count equals value count.
		in2, err := odata.In(graphschema.UserPrincipalName, s, s)
		if err != nil {
			t.Fatal(err)
		}
		both, err := odata.And(in2, odata.Eq(graphschema.UserPrincipalName, s))
		if err != nil {
			t.Fatal(err)
		}
		if u, err := odata.Get(odata.Seg("users")).With(odata.Query{}.Filter(both)).URL(base); err == nil {
			r, perr := odatatest.ParseRequest(requestURI(u), "/v1.0")
			if perr != nil || r.Filter == nil || len(r.Filter.Kids) != 2 || len(r.Filter.Kids[0].Lits) != 2 ||
				r.Filter.Kids[0].Lits[1] != want || r.Filter.Kids[1].Lits[0] != want {
				t.Fatalf("And(%q): %v %+v", in, perr, r.Filter)
			}
		}
		// KeyStr: segment count and the key value survive; no query, no fragment, no dot-segment.
		seg, err := odata.KeyStr("users", s)
		if err != nil {
			if k := odata.KindOf(err); k != odata.SlashInKey && k != odata.InvalidValue {
				t.Fatalf("KeyStr: %v", err)
			}
			return
		}
		u, err = odata.Get(odata.Seg("groups"), seg, odata.Seg("members")).URL(base)
		if err != nil {
			if odata.KindOf(err) != odata.TooLong {
				t.Fatalf("KeyStr URL: %v", err)
			}
			return
		}
		r, perr := odatatest.ParseRequest(requestURI(u), "/v1.0")
		if perr != nil || len(r.Segments) != 3 || r.Segments[1].Val != want || u.RawQuery != "" || u.Fragment != "" {
			t.Fatalf("KeyStr(%q) rendered %q: %+v %v", in, u.EscapedPath(), r.Segments, perr)
		}
		for _, p := range strings.Split(u.EscapedPath(), "/") {
			if p == "." || p == ".." {
				t.Fatalf("dot-segment in %q", u.EscapedPath())
			}
		}
		// AltKey over a GUID text.
		g := mustGUID(t, "7b3c1d5e-2f4a-4c8b-9d6e-0a1b2c3d4e5f")
		if as, err := odata.AltKey("servicePrincipals", graphschema.ServicePrincipalAppID, odata.GUIDTextOf(g)); err != nil {
			t.Fatal(err)
		} else if au, _ := odata.Get(as).URL(base); au == nil || strings.Count(au.EscapedPath(), "/") != 2 {
			t.Fatalf("AltKey path %v", au)
		}
	})
}

package odatatest_test

import (
	"net/url"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/odata/odatatest"
)

// The parser accepts exactly what the primitive emits and nothing else.
func TestRejectsWhatThePrimitiveNeverEmits(t *testing.T) {
	for name, target := range map[string]string{
		"outside base":        "/v2/users",
		"fragment":            "/v1.0/users#x",
		"dot segment":         "/v1.0/users/../me",
		"empty segment":       "/v1.0/users//x",
		"unencoded paren key": "/v1.0/users('a)b')",
		"lower-case hex":      "/v1.0/users('%2fa')",
		"slash in key":        "/v1.0/users('a%2Fb')",
		"undoubled quote":     "/v1.0/users('O'Neil')",
		"plus for space":      "/v1.0/users?$filter=a+eq+true",
		"raw quote in query":  "/v1.0/users?$filter=a%20eq%20'x'",
		"bare option name":    "/v1.0/users?filter=a%20eq%20true",
		"encoded dollar":      "/v1.0/users?%24filter=a%20eq%20true",
		"duplicate option":    "/v1.0/users?$top=1&$top=2",
		"unknown option":      "/v1.0/users?$search=x",
		"or operator":         "/v1.0/users?$filter=a%20eq%20true%20or%20b%20eq%20true",
		"unparenthesised and": "/v1.0/users?$filter=a%20eq%20true%20and%20b%20eq%20true",
		"truncated percent":   "/v1.0/users?$filter=a%2",
		"top zero":            "/v1.0/users?$top=0",
		"top padded":          "/v1.0/users?$top=010",
		"trailing filter":     "/v1.0/users?$filter=a%20eq%20true%20",
	} {
		if r, err := odatatest.ParseRequest(target, "/v1.0"); err == nil {
			t.Errorf("%s: accepted %q as %+v", name, target, r)
		}
	}
}

func TestParsesTheEmittedShapes(t *testing.T) {
	f := strings.ReplaceAll(url.QueryEscape("(a eq true) and (b in ('x'', y', 'z'))"), "+", "%20")
	r, err := odatatest.ParseRequest("/v1.0/groups/7b3c1d5e-2f4a-4c8b-9d6e-0a1b2c3d4e5f/members?$filter="+f+"&$top=5", "/v1.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Segments) != 3 || r.Segments[1].Kind != odatatest.SegKey || r.Top != 5 {
		t.Fatalf("%+v", r)
	}
	in := r.Filter.Kids[1]
	if in.Op != "in" || len(in.Lits) != 2 || in.Lits[0].Text != "x', y" || in.Lits[1].Text != "z" {
		t.Fatalf("in = %+v", in)
	}
}

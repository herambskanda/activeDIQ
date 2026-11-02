package report_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/report"
)

// AC 2: a request that carries an LDAP filter string as a parameter is rejected as an unknown
// parameter when decoded into report types, and the filter text is never echoed.
func TestDecodeRefusesLDAPFilterAsParameter(t *testing.T) {
	const ldap = `(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))`
	for name, body := range map[string]string{
		"top-level ldapFilter": `{"ldapFilter":"` + ldap + `"}`,
		"top-level filter":     `{"filter":"` + ldap + `"}`,
		"top-level sql":        `{"sql":"SELECT 1"}`,
		"undeclared param":     `{"params":{"ldapFilter":"` + ldap + `"}}`,
		"undeclared param obj": `{"params":{"ldap":{"days":30}}}`,
		"name that is a query": `{"params":{"` + ldap + `":{"days":30}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			p, preset, err := report.DecodeRunParams([]byte(body), usersDef())
			wantCode(t, err, report.CodeUnknownParameter)
			if preset != "" || p.Params != nil || p.Filters != nil {
				t.Fatalf("a refused body produced params: %+v", p)
			}
			if strings.Contains(err.Error(), "objectClass") || strings.Contains(err.Error(), "SELECT") || strings.Contains(err.Error(), "803") {
				t.Fatalf("error echoes the request: %v", err)
			}
		})
	}
}

func TestDecodeAcceptsTypedParameters(t *testing.T) {
	body := `{"preset":"inactive","connections":["00000001-0000-0000-0000-000000000000"],
	  "params":{"days":{"days":45}},"columns":["name","status"],"sort":[{"column":"name","dir":"desc"}],
	  "filters":[{"cmp":{"col":"name","op":"prefix","value":{"text":"a"}}}],
	  "include":[{"connection":"00000001-0000-0000-0000-000000000000","root":"00000002-0000-0000-0000-000000000000","depth":"one_level"}]}`
	p, preset, err := report.DecodeRunParams([]byte(body), usersDef())
	if err != nil || preset != "inactive" {
		t.Fatalf("decode: %v %q", err, preset)
	}
	q, err := report.Resolve(usersDef(), preset, p, usersDataset())
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(q.Columns) != 2 || q.Sort[0].Dir != report.Desc || len(q.Narrowing.Include) != 1 || q.Narrowing.Include[0].Depth != report.DepthOneLevel {
		t.Fatalf("query = %+v", q)
	}
}

func TestDecodeIsStrict(t *testing.T) {
	for name, body := range map[string]string{
		"trailing data":        `{} {}`,
		"not an object":        `[]`,
		"bad guid":             `{"connections":["not-a-guid"]}`,
		"zero guid":            `{"subjects":["00000000-0000-0000-0000-000000000000"]}`,
		"unknown field nested": `{"include":[{"connection":"00000001-0000-0000-0000-000000000000","root":"00000002-0000-0000-0000-000000000000","depth":"subtree","dn":"OU=x"}]}`,
		"bad depth":            `{"include":[{"connection":"00000001-0000-0000-0000-000000000000","root":"00000002-0000-0000-0000-000000000000","depth":"deep"}]}`,
		"param two kinds":      `{"params":{"days":{"days":30,"enum":"x"}}}`,
		"param string":         `{"params":{"days":"30"}}`,
		"unknown operator":     `{"filters":[{"cmp":{"col":"name","op":"like","value":{"text":"a"}}}]}`,
		"filter extra field":   `{"filters":[{"cmp":{"col":"name","op":"eq","value":{"text":"a"},"raw":"x"}}]}`,
		"two node kinds":       `{"filters":[{"and":[],"or":[]}]}`,
		"bad sort dir":         `{"sort":[{"column":"name","dir":"sideways"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := report.DecodeRunParams([]byte(body), usersDef()); err == nil {
				t.Fatal("accepted")
			} else if _, ok := report.CodeOf(err); !ok {
				t.Fatalf("untyped error: %v", err)
			}
		})
	}
}

func TestExprJSONRoundTrip(t *testing.T) {
	in := `{"and":[{"cmp":{"col":"status","op":"eq","value":{"enum":"enabled"}}},{"not":{"cmp":{"col":"pwd_last_set","op":"older_than_days","param":"days"}}}]}`
	e, err := report.UnmarshalExpr([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != in {
		t.Fatalf("round trip:\n got %s\nwant %s", out, in)
	}
}

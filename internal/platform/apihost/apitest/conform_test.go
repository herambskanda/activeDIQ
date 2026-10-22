package apitest_test

import (
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/apihost/apitest"
	"github.com/skenzeriq/activediq/internal/platform/apihost/apitypes"
)

type resp struct{ body any }

func (resp) StatusCode() int                    { return 200 }
func (r resp) ResponseBody() any                { return r.body }
func (resp) ResponseHeaders() map[string]string { return nil }

func TestViolations(t *testing.T) {
	if v := apitest.Violations(resp{}); len(v) != 0 {
		t.Fatalf("no body, no violation: %v", v)
	}
	if v := apitest.Violations(resp{body: apitypes.ObjectView{DN: "cn=a"}}); len(v) != 0 {
		t.Fatalf("a conforming body: %v", v)
	}
	if v := apitest.Violations(resp{body: apitypes.ObjectView{DN: strings.Repeat("a", 5000)}}); len(v) == 0 {
		t.Fatal("a dn above maxLength must be a violation")
	}
	if v := apitest.Violations(resp{body: []apitypes.ObjectView{{}, {DN: strings.Repeat("a", 5000)}}}); len(v) == 0 || !strings.Contains(v[0], "/1/dn") {
		t.Fatalf("a violation in a slice element must name its pointer: %v", v)
	}
	if v := apitest.Violations(resp{body: struct{ A string }{}}); len(v) == 0 {
		t.Fatal("a struct with no generated validator is itself a violation")
	}
	if v := apitest.Violations(resp{body: apihost.Stream{}}); len(v) != 0 {
		t.Fatalf("a binary download has no schema: %v", v)
	}
	if v := apitest.Violations(nil); len(v) == 0 {
		t.Fatal("a nil response is a violation")
	}
}

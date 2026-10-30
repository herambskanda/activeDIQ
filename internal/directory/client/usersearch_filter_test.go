package client

import (
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/ldapfilter"
)

// The search text reaches the directory only as a value of a typed filter node. With LDAP metacharacters
// in it, the filter that the connector renders (through the same parser and renderer) has exactly the
// structure of a harmless term, and the metacharacters are RFC 4515 escapes (acceptance 3).
func TestUserFilterEscapesMetacharactersThroughTheSafeBuilder(t *testing.T) {
	sc := ldapfilter.NewSchema(
		ldapfilter.AttrInfo{Name: "objectClass", Syntax: ldapfilter.SynString},
		ldapfilter.AttrInfo{Name: "displayName", Syntax: ldapfilter.SynString},
		ldapfilter.AttrInfo{Name: "sAMAccountName", Syntax: ldapfilter.SynString},
		ldapfilter.AttrInfo{Name: "userPrincipalName", Syntax: ldapfilter.SynString},
	)
	render := func(text string) string {
		t.Helper()
		f, err := ldapfilter.ParseFilterAST(userFilter(text), sc, nil, ldapfilter.Limits{})
		if err != nil {
			t.Fatalf("the typed tree was rejected: %v", err)
		}
		s, err := ldapfilter.Render(f, sc)
		if err != nil {
			t.Fatalf("render: %v", err)
		}
		return s.String()
	}
	plain := render("lab")
	hostile := render(`x*)(objectClass=*)(|(a=\`)
	for _, c := range []string{"(", ")", "*"} {
		if strings.Count(hostile, c) != strings.Count(plain, c) {
			t.Fatalf("a hostile term changed the filter's structure (%q count): %s", c, hostile)
		}
	}
	for _, want := range []string{`\2a`, `\29`, `\28`, `\5c`} {
		if !strings.Contains(hostile, want) {
			t.Errorf("expected the escape %s in %s", want, hostile)
		}
	}
}

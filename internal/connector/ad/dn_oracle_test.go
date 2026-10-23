package ad

import (
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/skenzeriq/activediq/internal/directory/dn"
)

// Safe-primitives §4.6 oracle: the go-ldap DN parser is the independent implementation that `dn`
// (own RFC 4514 renderer and parser, blueprint §7.4) is checked against. This is the one place the
// library's ParseDN and EscapeDN may be used (tests are exempt from ldap-dn-library).

// hostileValues are CN values that stress every escaping rule.
var hostileValues = []string{
	"Smith, John", ",OU=Domain Admins", "a+CN=b", " lead", "trail ", " ", "  ", "#admins", "a#b",
	`"quoted"`, `back\slash`, "<x>;y", "line1\nline2", "a\rb", "a/b", "a=b", "a\x7fb", "a\tb",
	"𝔘ser Zoë", "日本語,テスト", `\,`, `\\`, `x\`, ")(cn=*)", "*", "a b", "é,é", "a b",
}

func flatten(t *testing.T, p *ldap.DN) []string {
	t.Helper()
	var out []string
	for _, r := range p.RDNs {
		if len(r.Attributes) != 1 {
			t.Fatalf("multi-valued RDN from go-ldap: %v", r)
		}
		out = append(out, strings.ToUpper(r.Attributes[0].Type)+"="+r.Attributes[0].Value)
	}
	return out
}

func ours(d dn.DN) []string {
	var out []string
	for _, r := range d.RDNs() {
		out = append(out, strings.ToUpper(r.Type().String())+"="+r.Value())
	}
	return out
}

func equalLists(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// dn renders, go-ldap parses: structure and values must match what was built.
func TestOracleRenderParsedByGoLDAP(t *testing.T) {
	base, err := dn.Parse("OU=Staff,DC=corp,DC=example", dn.Strict)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range hostileValues {
		d, err := dn.Child(base, dn.CN, v)
		if err != nil {
			t.Errorf("%q: builder: %v", v, err)
			continue
		}
		text, err := dn.DNRef(d).ForRequest()
		if err != nil {
			t.Errorf("%q: ForRequest: %v", v, err)
			continue
		}
		p, err := ldap.ParseDN(text)
		if err != nil {
			t.Errorf("%q: go-ldap rejects %q: %v", v, text, err)
			continue
		}
		if got, want := flatten(t, p), ours(d); !equalLists(got, want) {
			t.Errorf("%q: rendered %q: go-ldap %q, dn %q", v, text, got, want)
		}
	}
}

// go-ldap escapes, dn parses: EscapeDN output (a different but valid escaping) must read back to
// the same value through the strict parser.
func TestOracleGoLDAPEscapeParsedByDN(t *testing.T) {
	for _, v := range hostileValues {
		if !strings.ContainsRune(v, 0) && !isValidUTF8(v) {
			continue
		}
		text := "CN=" + ldap.EscapeDN(v) + ",DC=corp,DC=example"
		d, err := dn.Parse(text, dn.Strict)
		if err != nil {
			t.Errorf("%q: dn rejects go-ldap escaping %q: %v", v, text, err)
			continue
		}
		rs := d.RDNs()
		if len(rs) != 3 || rs[0].Value() != v {
			t.Errorf("%q: via %q dn read %q", v, text, ours(d))
		}
		p, err := ldap.ParseDN(text)
		if err != nil {
			t.Errorf("%q: go-ldap cannot read its own escaping %q: %v", v, text, err)
			continue
		}
		if got, want := flatten(t, p), ours(d); !equalLists(got, want) {
			t.Errorf("%q: %q: go-ldap %q, dn %q", v, text, got, want)
		}
	}
}

func isValidUTF8(s string) bool { return strings.ToValidUTF8(s, "�") == s }

// Hand-written wire texts in the shapes DCs and other tools emit, parsed by both.
func TestOracleWireTextsAgree(t *testing.T) {
	texts := []string{
		`CN=evil\,OU=HR,DC=corp,DC=example`,
		`CN=Smith\2C John,DC=x`,
		`CN=Smith\, John,OU=A\+B,DC=x`,
		`CN=\ lead,DC=x`,
		`CN=trail\ ,DC=x`,
		`CN=\#hash,DC=x`,
		`CN=a\3Db,DC=x`,
		`CN=line1\0Aline2,DC=x`,
		`CN=a\5Cb,DC=x`,
		`CN=\"q\",DC=x`,
		`CN=\<a\>\;b,DC=x`,
		`cn=lower,ou=case,dc=x`,
		"CN=Zoë 日本,DC=x",
	}
	for _, text := range texts {
		d, err := dn.Parse(text, dn.Strict)
		if err != nil {
			t.Errorf("dn rejects %q: %v", text, err)
			continue
		}
		p, err := ldap.ParseDN(text)
		if err != nil {
			t.Errorf("go-ldap rejects %q: %v", text, err)
			continue
		}
		if got, want := flatten(t, p), ours(d); !equalLists(got, want) {
			t.Errorf("%q: go-ldap %q, dn %q", text, got, want)
		}
		// And the canonical rendering of what dn parsed is stable under go-ldap too.
		out, err := dn.DNRef(d).ForRequest()
		if err != nil {
			t.Errorf("%q: ForRequest: %v", text, err)
			continue
		}
		p2, err := ldap.ParseDN(out)
		if err != nil || !equalLists(flatten(t, p2), ours(d)) {
			t.Errorf("%q: canonical %q differs under go-ldap: %v", text, out, err)
		}
	}
}

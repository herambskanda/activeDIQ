package ad

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/ldapfilter"
)

func metaXML(name, when string) []byte {
	return []byte(fmt.Sprintf(`<DS_REPL_ATTR_META_DATA><pszAttributeName>%s</pszAttributeName><dwVersion>2</dwVersion><ftimeLastOriginatingChange>%s</ftimeLastOriginatingChange><uuidLastOriginatingDsaInvocationID>00112233-4455-6677-8899-aabbccddeeff</uuidLastOriginatingDsaInvocationID><usnOriginatingChange>1</usnOriginatingChange><usnLocalChange>2</usnLocalChange></DS_REPL_ATTR_META_DATA>`, name, when))
}

func TestChangeTimesFrom(t *testing.T) {
	vals := [][]byte{
		metaXML("mail", "2026-11-19T08:00:00Z"),
		metaXML("Mobile", "2026-11-18T01:02:03Z"),
		[]byte("<not-xml"),
		metaXML("otherMobile", "1601-01-01T00:00:00Z"), // FILETIME 0 is not an instant
		metaXML("cn", "2026-01-01T00:00:00Z"),          // not asked
	}
	got := changeTimesFrom([]string{"mail", "mobile", "otherMobile", "telephoneNumber"}, vals)
	if len(got) != 4 {
		t.Fatalf("keys = %v", got)
	}
	if c := got["mail"]; !c.Known || !c.At.Equal(time.Date(2026, 11, 19, 8, 0, 0, 0, time.UTC)) {
		t.Errorf("mail = %+v", c)
	}
	if c := got["mobile"]; !c.Known || c.At.Day() != 18 {
		t.Errorf("mobile (case-insensitive name) = %+v", c)
	}
	for _, n := range []string{"otherMobile", "telephoneNumber"} {
		if c := got[n]; c.Known || !c.At.IsZero() {
			t.Errorf("%s must be unknown with a zero At: %+v", n, c)
		}
	}
}

func TestChangeTimesFromUndecodableIsUnknown(t *testing.T) {
	got := changeTimesFrom([]string{"mail"}, [][]byte{[]byte(strings.Repeat("x", 10))})
	if got["mail"].Known {
		t.Error("undecodable metadata must be unknown")
	}
	if got := changeTimesFrom([]string{"mail"}, nil); got["mail"].Known {
		t.Error("absent metadata must be unknown")
	}
}

func TestChangeTimeAttrsKnownToSchema(t *testing.T) {
	s := newOffline()
	if _, err := s.checkAttrs([]string{"mail", "mobile", "otherMobile"}, false); err != nil {
		t.Fatalf("otherMobile must be a known attribute: %v", err)
	}
	// The metadata attribute is constructed: never filterable, only read.
	a, _ := ldapfilter.ParseAttrName("msDS-ReplAttributeMetaData", DefaultSchema())
	if _, err := ldapfilter.Render(ldapfilter.Present(a), DefaultSchema()); err == nil {
		t.Error("a filter on the constructed metadata attribute must be refused")
	}
}

func TestValidSignInName(t *testing.T) {
	for _, n := range []string{"", "a*", "*", "j*@corp", "a\x00b", "a\nb", strings.Repeat("a", 300)} {
		if validSignInName(n) {
			t.Errorf("%q accepted", n)
		}
	}
	for _, n := range []string{"jdoe", "j.doe@corp.example", "Ramán", "o'neil"} {
		if !validSignInName(n) {
			t.Errorf("%q refused", n)
		}
	}
}

func TestSignInFilterEscapes(t *testing.T) {
	s := newOffline()
	for _, name := range []string{"x)(objectClass=*", `a\2a`, "(|(cn=x))"} {
		f, err := signInFilter(s, name)
		if err != nil {
			t.Fatal(err)
		}
		out, err := ldapfilter.Render(f, s.schema)
		if err != nil {
			t.Fatalf("%q: %v", name, err)
		}
		str := out.String()
		if strings.Count(str, "(") != strings.Count(str, ")") || strings.Contains(str, "(objectClass=*)") {
			t.Errorf("%q rendered %q", name, str)
		}
		if strings.Contains(str, "x)(") || strings.Contains(str, "(|(cn=x))") {
			t.Errorf("%q injected into %q", name, str)
		}
	}
}

func signInEntry(attrs map[string]string) *Entry {
	m := map[string][][]byte{"objectGUID": {{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}}}
	for k, v := range attrs {
		m[k] = [][]byte{[]byte(v)}
	}
	return NewEntry("CN=u", m)
}

func TestSignInUserFrom(t *testing.T) {
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	past := fmt.Sprint((now.Add(-time.Hour).Unix() + 11644473600) * 10_000_000)
	future := fmt.Sprint((now.Add(time.Hour).Unix() + 11644473600) * 10_000_000)
	ok := map[string]string{"userAccountControl": "512", "pwdLastSet": future, "accountExpires": "9223372036854775807", "sAMAccountName": "jdoe"}
	with := func(k, v string) map[string]string {
		m := map[string]string{}
		for a, b := range ok {
			m[a] = b
		}
		m[k] = v
		return m
	}
	cases := []struct {
		name                          string
		attrs                         map[string]string
		disabled, expired, mustChange bool
		refused                       bool
	}{
		{"clean", ok, false, false, false, false},
		{"disabled", with("userAccountControl", "514"), true, false, false, false},
		{"expired", with("accountExpires", past), false, true, false, false},
		{"expires later", with("accountExpires", future), false, false, false, false},
		{"never (0)", with("accountExpires", "0"), false, false, false, false},
		{"must change", with("pwdLastSet", "0"), false, false, true, false},
		{"malformed uac", with("userAccountControl", "x"), false, false, false, true},
		{"malformed expiry", with("accountExpires", "-5"), false, false, false, true},
	}
	for _, c := range cases {
		u, err := signInUserFrom(signInEntry(c.attrs), now)
		if c.refused {
			if err == nil || CodeOf(err) != CodeObjectNotFound {
				t.Errorf("%s: err = %v", c.name, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if u.Disabled != c.disabled || u.Expired != c.expired || u.MustChange != c.mustChange {
			t.Errorf("%s: %+v", c.name, u)
		}
	}
}

package searchkey_test

import (
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/skenzeriq/activediq/internal/platform/searchkey"
)

// ADR-0011 rule 7: required vectors, and the upper/lower pairs.
func Test_NormName_vectors(t *testing.T) {
	for _, c := range []struct {
		want string
		in   []string
	}{
		{"lodz", []string{"Łódź", "łódź", "ŁÓDŹ"}},
		{"oster", []string{"Øster", "øster"}},
		{"istanbul", []string{"İstanbul", "ISTANBUL", "istanbul"}},
		{"strasse", []string{"Straße", "STRASSE"}},
		{"ss", []string{"ẞ"}},
		{"aesir", []string{"Æsir"}},
		{"thor", []string{"Þór"}},
		{"dorde", []string{"Đorđe"}},
		{"priya", []string{"Ｐｒｉｙａ"}},
		{"finn", []string{"ﬁnn"}},
		{"colleccio", []string{"col·lecció"}},
		{"priya raman", []string{"  Priya,  Raman ", "Priya.Raman", "PRIYA_RAMAN", "(Priya) Raman"}},
		// scripts without a Latin fold keep their letters
		{"москва", []string{"Москва"}},
		{"αθηνα", []string{"Αθήνα"}},
		{"東京", []string{"東京"}},
	} {
		for _, in := range c.in {
			if got := searchkey.NormName(in); got != c.want {
				t.Errorf("NormName(%q) = %q, want %q", in, got, c.want)
			}
		}
	}
}

func Test_NormIdent_keeps_punctuation(t *testing.T) {
	if got := searchkey.NormIdent("  J.Smith@Corp.LOCAL "); got != "j.smith@corp.local" {
		t.Fatalf("got %q", got)
	}
	if got := searchkey.NormIdent("ＣＯＲＰ\\JSmith$"); got != `corp\jsmith$` {
		t.Fatalf("got %q", got)
	}
	if a, b := searchkey.NormDN("CN=A, OU=B,  DC=c"), searchkey.NormDN("cn=a,ou=b,dc=c"); a != b {
		t.Fatalf("dn: %q vs %q", a, b)
	}
	if got := searchkey.NormDN(`CN=Raman\, Priya,DC=x`); got != `cn=raman\, priya,dc=x` {
		t.Fatalf("escaped comma kept: %q", got)
	}
}

func Test_Prepare_refusals_in_order(t *testing.T) {
	digits := strings.Repeat("1234567", 7) // 49
	for _, c := range []struct {
		name string
		in   string
		want error
	}{
		{"invalid utf8", "ab\xffcd", searchkey.ErrInvalidUTF8},
		{"nul", "ab\x00cd", searchkey.ErrNUL},
		{"4KiB+1", strings.Repeat("a", 4097), searchkey.ErrTooLong},
		{"257 runes", strings.Repeat("a", 257), searchkey.ErrTooManyRunes},
		// 257 compatibility runes that are 256 after NFKC is fine; 257 after NFKC is not
		{"257 runes after nfkc", strings.Repeat("ａ", 257), searchkey.ErrTooManyRunes},
		{"recovery ascii", digits, searchkey.ErrRecoveryPassword},
		{"recovery dashes", "123456-123456-123456-123456-123456-123456-123456-123456", searchkey.ErrRecoveryPassword},
		{"recovery fullwidth", strings.Repeat("１", 48), searchkey.ErrRecoveryPassword},
		{"recovery devanagari", strings.Repeat("१", 48), searchkey.ErrRecoveryPassword},
		{"recovery spaced", strings.Repeat("1 ", 48), searchkey.ErrRecoveryPassword},
	} {
		if _, err := searchkey.Prepare(c.in); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
		if _, err := searchkey.Classify(c.in); !errors.Is(err, c.want) {
			t.Errorf("%s: Classify err = %v, want %v", c.name, err, c.want)
		}
	}
	if _, err := searchkey.Prepare(strings.Repeat("1", 47)); err != nil {
		t.Errorf("47 digits are not a recovery password: %v", err)
	}
	if _, err := searchkey.Prepare(strings.Repeat("1", 24) + "x" + strings.Repeat("1", 24)); err != nil {
		t.Errorf("a letter breaks the run: %v", err)
	}
	if _, err := searchkey.Classify("   "); !errors.Is(err, searchkey.ErrEmpty) {
		t.Errorf("blank: %v", err)
	}
	// the refusal never carries the text
	_, err := searchkey.Prepare(digits)
	if strings.Contains(err.Error(), "1234567") {
		t.Fatal("refusal echoes the text")
	}
}

func Test_PrefixUpper_edges(t *testing.T) {
	for _, c := range []struct {
		in      string
		want    string
		bounded bool
	}{
		{"abc", "abd", true},
		{"a퟿", "a", true},
		{"a\U0010FFFF", "b", true},
		{"a\U0010FFFF\U0010FFFF", "b", true},
		{"\U0010FFFF\U0010FFFF", "", false},
		{"", "", false},
		{"é", "ê", true},
	} {
		got, ok := searchkey.PrefixUpper(c.in)
		if got != c.want || ok != c.bounded {
			t.Errorf("PrefixUpper(%q) = %q,%v want %q,%v", c.in, got, ok, c.want, c.bounded)
		}
		if ok && !utf8.ValidString(got) {
			t.Errorf("PrefixUpper(%q) is not valid UTF-8", c.in)
		}
		if ok && !(c.in < got) {
			t.Errorf("bound %q not above %q", got, c.in)
		}
	}
}

func Test_Classify_shapes(t *testing.T) {
	type want struct {
		shape searchkey.Shape
		exact []searchkey.Probe
	}
	for _, c := range []struct {
		name, in string
		shape    searchkey.Shape
		exact    []searchkey.Probe
		domain   string
	}{
		{"guid", "{AAAAAAAA-1111-4222-8333-444444444444}", searchkey.ShapeGUID,
			[]searchkey.Probe{{searchkey.KindGUID, "aaaaaaaa-1111-4222-8333-444444444444"}, {searchkey.KindConsistencyGUID, "aaaaaaaa-1111-4222-8333-444444444444"}}, ""},
		{"sid", "S-1-5-21-1-2-3-1105", searchkey.ShapeSID, []searchkey.Probe{{searchkey.KindSID, "s-1-5-21-1-2-3-1105"}}, ""},
		{"dn", "CN=Priya Raman, OU=People,DC=corp,DC=local", searchkey.ShapeDN, []searchkey.Probe{{searchkey.KindDN, "cn=priya raman,ou=people,dc=corp,dc=local"}}, ""},
		{"domain sam", `CORP\JSmith`, searchkey.ShapeDomainSAM, []searchkey.Probe{{searchkey.KindSAM, "jsmith"}}, "corp"},
		{"upn", "JSmith@Corp.Local", searchkey.ShapeEmail,
			[]searchkey.Probe{{searchkey.KindUPN, "jsmith@corp.local"}, {searchkey.KindMail, "jsmith@corp.local"}, {searchkey.KindSAM, "jsmith"}}, "corp.local"},
		{"host", "SRV01.corp.local", searchkey.ShapeSAM,
			[]searchkey.Probe{{searchkey.KindSAM, "srv01.corp.local"}, {searchkey.KindDNSHost, "srv01.corp.local"}, {searchkey.KindName, "srv01 corp local"}}, ""},
		{"free text", "Priya Raman", searchkey.ShapeText, nil, ""},
	} {
		p, err := searchkey.Classify(c.in)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if p.Shapes[0] != c.shape {
			t.Errorf("%s: shape %v want %v", c.name, p.Shapes, c.shape)
		}
		if len(p.Exact) != len(c.exact) {
			t.Errorf("%s: exact %v want %v", c.name, p.Exact, c.exact)
			continue
		}
		for i := range c.exact {
			if p.Exact[i] != c.exact[i] {
				t.Errorf("%s: exact[%d] %v want %v", c.name, i, p.Exact[i], c.exact[i])
			}
		}
		if p.Domain != c.domain {
			t.Errorf("%s: domain %q want %q", c.name, p.Domain, c.domain)
		}
	}
}

func Test_Classify_prefix_fuzzy_and_comma_swap(t *testing.T) {
	p, err := searchkey.Classify("Raman, Priya")
	if err != nil {
		t.Fatal(err)
	}
	var lo []string
	for _, x := range p.Prefix {
		if x.Kind == searchkey.KindName {
			lo = append(lo, x.Lo)
		}
	}
	if len(lo) != 2 || lo[0] != "raman priya" || lo[1] != "priya raman" {
		t.Fatalf("name prefixes %v", lo)
	}
	if p.Fuzzy != "raman priya" {
		t.Fatalf("fuzzy %q", p.Fuzzy)
	}
	if p2, _ := searchkey.Classify("ab"); p2.Fuzzy != "" || p2.Runes != 2 {
		t.Fatalf("two runes: fuzzy %q runes %d", p2.Fuzzy, p2.Runes)
	}
	p3, _ := searchkey.Classify("pri")
	var kinds []searchkey.Kind
	for _, x := range p3.Prefix {
		kinds = append(kinds, x.Kind)
	}
	hasWord := false
	for _, k := range kinds {
		hasWord = hasWord || k == searchkey.KindNameWord
	}
	if !hasWord {
		t.Fatalf("a one-word query prefix-matches name words: %v", kinds)
	}
	// two commas: no swap
	p4, _ := searchkey.Classify("a, b, c")
	n := 0
	for _, x := range p4.Prefix {
		if x.Kind == searchkey.KindName {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("no swap with two commas: %d", n)
	}
}

func Test_Words(t *testing.T) {
	if w := searchkey.Words("priya raman"); len(w) != 2 || w[0] != "priya" {
		t.Fatalf("%v", w)
	}
	if w := searchkey.Words("priya"); w != nil {
		t.Fatalf("one word has no word keys: %v", w)
	}
	if w := searchkey.Words("a b"); len(w) != 0 {
		t.Fatalf("one-letter words skipped: %v", w)
	}
}

func Fuzz_NormName_idempotent_and_total(f *testing.F) {
	for _, s := range []string{"Łódź", "İstanbul", "ẞ", "a.b-c", "ｆｕｌｌ", "́", "x·y"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if !utf8.ValidString(s) {
			return
		}
		a := searchkey.NormName(s)
		if !utf8.ValidString(a) {
			t.Fatalf("invalid utf8 out for %q", s)
		}
		if b := searchkey.NormName(a); b != a {
			t.Fatalf("not idempotent: %q -> %q -> %q", s, a, b)
		}
	})
}

package mailaddr

import (
	"errors"
	"strings"
	"testing"
)

// The SX-7 corpus (reports-schedules-security-review.md §4): every one of these is refused.
func TestParseRefusesTheCorpus(t *testing.T) {
	long := strings.Repeat("a", 65)
	cases := map[string]string{
		"quoted local part":       `"a@ok.example"@evil.example`,
		"quoted local simple":     `"a"@ok.example`,
		"display name":            `Alice <a@ok.example>`,
		"display name bare angle": `<a@ok.example>`,
		"comment":                 `a(comment)@ok.example`,
		"comment after":           `a@ok.example(comment)`,
		"source route":            `@relay.example:a@ok.example`,
		"ip literal v4":           `a@[192.0.2.1]`,
		"ip literal v6":           `a@[IPv6:::1]`,
		"bare ipv4 domain":        `a@192.0.2.1`,
		"two at":                  `a@b@ok.example`,
		"two at in domain":        `a@ok.example@evil.example`,
		"LF":                      "a@ok.example\n",
		"CR LF injection":         "a@ok.example\r\nRCPT TO:<x@evil.example>",
		"CR":                      "a\r@ok.example",
		"NUL":                     "a\x00@ok.example",
		"leading space":           " a@ok.example",
		"trailing space":          "a@ok.example ",
		"inner space":             "a b@ok.example",
		"tab":                     "a\t@ok.example",
		"empty":                   "",
		"no at":                   "ok.example",
		"empty local":             "@ok.example",
		"empty domain":            "a@",
		"single label domain":     "a@localhost",
		"trailing dot domain":     "a@ok.example.",
		"leading dot domain":      "a@.ok.example",
		"double dot domain":       "a@ok..example",
		"leading dot local":       ".a@ok.example",
		"trailing dot local":      "a.@ok.example",
		"double dot local":        "a..b@ok.example",
		"non-ascii local":         "á@ok.example",
		"local too long":          long + "@ok.example",
		"hyphen label":            "a@-ok.example",
		"wildcard domain":         "a@*.ok.example",
		"percent hack":            "a%evil.example@ok.example",
		"comma list":              "a@ok.example,b@evil.example",
		"semicolon":               "a@ok.example;b@evil.example",
		"angle in domain":         "a@ok.example>",
		"colon in domain":         "a@ok.example:25",
		"slash":                   "a@ok.example/x",
		"backslash":               `a\@b@ok.example`,
		"invalid idna (xn--)":     "a@xn--.example",
		"underscore domain":       "a@ok_host.example",
		"fullwidth at":            "a＠ok.example",
		"numeric tld":             "a@ok.123",
		"unicode space in domain": "a@ok .example",
		"domain too long":         "a@" + strings.Repeat("a.", 130) + "example",
		"label too long":          "a@" + strings.Repeat("a", 64) + ".example",
		"huge input":              strings.Repeat("a", 4000) + "@ok.example",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			a, err := Parse(in)
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("Parse(%q) = %q, %v; want ErrInvalid", in, a.String(), err)
			}
			if !a.IsZero() || a.String() != "" {
				t.Fatalf("a refusal must return the zero Address, got %+v", a)
			}
			if strings.Contains(err.Error(), "evil") {
				t.Fatalf("the error carries input: %v", err)
			}
		})
	}
}

func TestParseCanonicalForm(t *testing.T) {
	cases := []struct{ in, want, domain string }{
		{"Alice@OK.Example", "Alice@ok.example", "ok.example"},
		{"a.b+tag@ok.example", "a.b+tag@ok.example", "ok.example"},
		{"o'brien@ok.example", "o'brien@ok.example", "ok.example"},
		{"a@sub.ok.example", "a@sub.ok.example", "sub.ok.example"},
		{"a@münchen.example", "a@xn--mnchen-3ya.example", "xn--mnchen-3ya.example"},
		{"a@MÜNCHEN.example", "a@xn--mnchen-3ya.example", "xn--mnchen-3ya.example"},
		{"a@xn--mnchen-3ya.example", "a@xn--mnchen-3ya.example", "xn--mnchen-3ya.example"},
	}
	for _, c := range cases {
		a, err := Parse(c.in)
		if err != nil {
			t.Fatalf("Parse(%q): %v", c.in, err)
		}
		if a.String() != c.want || a.Domain() != c.domain {
			t.Errorf("Parse(%q) = %q (domain %q); want %q (%q)", c.in, a.String(), a.Domain(), c.want, c.domain)
		}
		// Idempotent: the canonical string parses to itself, so classify-then-send cannot drift.
		b, err := Parse(a.String())
		if err != nil || b != a {
			t.Errorf("canonical %q does not re-parse to itself: %v %v", a.String(), b, err)
		}
	}
}

// A Unicode lookalike of an ASCII domain is a different domain after ToASCII.
func TestLookalikeDomainIsDifferent(t *testing.T) {
	ascii, err := Parse("a@ok.example")
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range []string{"a@оk.example" /* Cyrillic о */, "a@ok.exаmple" /* Cyrillic а */} {
		a, err := Parse(in)
		if err != nil {
			continue // refused outright is also safe
		}
		if a.Domain() == ascii.Domain() {
			t.Errorf("%q folded to %q", in, a.Domain())
		}
		if !strings.HasPrefix(a.Domain(), "xn--") && !strings.Contains(a.Domain(), ".xn--") {
			t.Errorf("%q = %q is not in punycode", in, a.Domain())
		}
	}
}

func TestNormalizeDomain(t *testing.T) {
	good := map[string]string{"OK.Example": "ok.example", "münchen.example": "xn--mnchen-3ya.example"}
	for in, want := range good {
		got, err := NormalizeDomain(in)
		if err != nil || got != want {
			t.Errorf("NormalizeDomain(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "*.ok.example", ".ok.example", "ok.example.", "a@ok.example", "localhost", "1.2.3.4", "[1.2.3.4]", "ok.example\n", "ok example"} {
		if _, err := NormalizeDomain(bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("NormalizeDomain(%q) = %v; want ErrInvalid", bad, err)
		}
	}
}

func FuzzParse(f *testing.F) {
	for _, s := range []string{"a@ok.example", `"a"@b.example`, "a@[1.2.3.4]", "A@B.C\r\n", "á@münchen.example"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		a, err := Parse(s)
		if err != nil {
			return
		}
		c := a.String()
		if strings.ContainsAny(c, " \r\n\x00<>\"(),;:[]\\") || strings.Count(c, "@") != 1 {
			t.Fatalf("accepted %q → unsafe canonical %q", s, c)
		}
		b, err := Parse(c)
		if err != nil || b.String() != c {
			t.Fatalf("canonical %q not stable: %q %v", c, b.String(), err)
		}
	})
}

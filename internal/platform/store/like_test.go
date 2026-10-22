package store

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// likeMatch is a test-local LIKE evaluator for `col LIKE $1 ESCAPE '\'`: % any run, _ any one character,
// `\` makes the next character literal. It works on runes, as PostgreSQL does for UTF-8 text.
func likeMatch(pattern, text string) bool {
	return likeRunes([]rune(pattern), []rune(text))
}

func likeRunes(p, s []rune) bool {
	for len(p) > 0 {
		switch p[0] {
		case '%':
			for len(p) > 0 && p[0] == '%' {
				p = p[1:]
			}
			if len(p) == 0 {
				return true
			}
			for i := 0; i <= len(s); i++ {
				if likeRunes(p, s[i:]) {
					return true
				}
			}
			return false
		case '_':
			if len(s) == 0 {
				return false
			}
			p, s = p[1:], s[1:]
		default:
			c := p[0]
			if c == '\\' && len(p) > 1 {
				c, p = p[1], p[1:]
			}
			if len(s) == 0 || s[0] != c {
				return false
			}
			p, s = p[1:], s[1:]
		}
	}
	return len(s) == 0
}

func TestLikePatternRendering(t *testing.T) {
	cases := []struct{ in, contains, prefix string }{
		{"%", `%\%%`, `\%%`},
		{"_", `%\_%`, `\_%`},
		{`\`, `%\\%`, `\\%`},
		{"", "%%", "%"},
		{"a%b_c\\", `%a\%b\_c\\%`, `a\%b\_c\\%`},
		{"é'; --", "%é'; --%", "é'; --%"},
	}
	for _, c := range cases {
		got, err := LikePattern{}.Contains(c.in)
		if err != nil || got.pattern != c.contains {
			t.Errorf("Contains(%q) = %q, %v; want %q", c.in, got.pattern, err, c.contains)
		}
		got, err = LikePattern{}.Prefix(c.in)
		if err != nil || got.pattern != c.prefix {
			t.Errorf("Prefix(%q) = %q, %v; want %q", c.in, got.pattern, err, c.prefix)
		}
		if v, err := got.Value(); err != nil || v != got.pattern {
			t.Errorf("Value = %v, %v", v, err)
		}
	}
}

func TestLikePatternRefusals(t *testing.T) {
	for name, in := range map[string]string{"nul": "a\x00b", "bad utf8": "\xff\xfe", "truncated": "ok\xc3"} {
		for _, build := range []func(string) (LikePattern, error){LikePattern{}.Contains, LikePattern{}.Prefix} {
			p, err := build(in)
			if err == nil || p != (LikePattern{}) {
				t.Fatalf("%s: got %v, %v; want refusal", name, p, err)
			}
			if (name == "nul") != (err == ErrNulInText) || strings.Contains(err.Error(), in) {
				t.Errorf("%s: error %q", name, err)
			}
		}
	}
}

func TestLikeMatcherModel(t *testing.T) {
	if !likeMatch(`%\%%`, "50%") || likeMatch(`%\%%`, "50") || likeMatch(`%\_%`, "ab") || !likeMatch(`%\\%`, `a\b`) {
		t.Fatal("test-local LIKE evaluator is wrong")
	}
}

// fuzzLike is the property: Contains(s) matches exactly the strings containing s literally; Prefix(s)
// those starting with it. Refused text is exactly NUL or invalid UTF-8.
func fuzzLike(t *testing.T, s string) {
	t.Helper()
	c, cerr := LikePattern{}.Contains(s)
	p, perr := LikePattern{}.Prefix(s)
	if refused := strings.IndexByte(s, 0) >= 0 || !utf8.ValidString(s); refused != (cerr != nil) || refused != (perr != nil) {
		t.Fatalf("Contains(%q) err=%v Prefix err=%v", s, cerr, perr)
	}
	if cerr != nil {
		return
	}
	probes := []string{"", s, "x" + s, s + "x", "x" + s + "y", strings.ToUpper(s), strings.ReplaceAll(s, "%", "a"),
		strings.ReplaceAll(s, "_", "a"), strings.ReplaceAll(s, `\`, ""), "%" + s, "_" + s, s + s}
	if len(s) > 0 {
		probes = append(probes, s[1:], s[:len(s)-1])
	}
	for _, text := range probes {
		if !utf8.ValidString(text) {
			continue
		}
		if got, want := likeMatch(c.pattern, text), strings.Contains(text, s); got != want {
			t.Fatalf("Contains(%q) pattern %q on %q: got %v want %v", s, c.pattern, text, got, want)
		}
		if got, want := likeMatch(p.pattern, text), strings.HasPrefix(text, s); got != want {
			t.Fatalf("Prefix(%q) pattern %q on %q: got %v want %v", s, p.pattern, text, got, want)
		}
	}
}

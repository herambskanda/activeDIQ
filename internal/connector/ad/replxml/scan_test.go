package replxml

import (
	"strings"
	"testing"
)

func TestScanTags(t *testing.T) {
	attrs := func(n int) string {
		var sb strings.Builder
		for i := 0; i < n; i++ {
			sb.WriteString(` a` + string(rune('a'+i%26)) + string(rune('a'+i/26)) + `="1"`)
		}
		return sb.String()
	}
	cases := []struct {
		name string
		doc  string
		want Code // "" = not refused by the scan
	}{
		{"16 attributes pass", `<r` + attrs(16) + `/>`, ""},
		{"17 attributes", `<r` + attrs(17) + `/>`, CodeTooManyAttrs},
		{"equals in a quoted value is not an attribute", `<r a="x=y=z=1=2=3=4=5=6=7=8=9=10=11=12=13=14=15=16=17"/>`, ""},
		{"gt in a quoted value does not end the tag", `<r a=">" b="1"` + attrs(14) + `/>`, ""},
		{"attributes in a comment are not counted", `<!-- <r` + attrs(40) + `> --><r/>`, ""},
		{"attributes in CDATA are not counted", `<r><![CDATA[<x` + attrs(40) + `>]]></r>`, ""},
		{"equals in text is not an attribute", `<r>CN=a,DC=b,DC=c,CN=a,DC=b,DC=c,CN=a,DC=b,DC=c,CN=a,DC=b,DC=c,CN=a,DC=b,DC=c</r>`, ""},
		{"depth before budget", strings.Repeat("<a>", 9), CodeTooDeep},
		{"unterminated tag is left to the decoder", `<r` + attrs(5), ""},
		{"unterminated tag still charges its attributes", `<r` + attrs(40), CodeTooManyAttrs},
		{"lt in a quoted value is left to the decoder", `<r a="<"` + attrs(5) + `/>`, ""},
		{"quote parity broken by an unquoted value still charges", `<r` + attrs(20) + ` x=d"` + attrs(40) + `/>`, CodeTooManyAttrs},
	}
	for _, c := range cases {
		e := scanTags([]byte(c.doc), defaultLimits)
		switch {
		case c.want == "" && e != nil:
			t.Errorf("%s: refused with %s", c.name, e.Code)
		case c.want != "" && (e == nil || e.Code != c.want):
			t.Errorf("%s: got %v, want %s", c.name, e, c.want)
		}
	}
}

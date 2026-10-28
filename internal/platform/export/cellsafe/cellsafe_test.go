package cellsafe

import (
	"slices"
	"testing"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

func TestTableMatchesNFKC(t *testing.T) {
	var gen []rune
	for r := rune(0); r <= utf8.MaxRune; r++ {
		if r >= 0xD800 && r <= 0xDFFF {
			continue
		}
		n := norm.NFKC.String(string(r))
		if n == "" {
			continue
		}
		switch f, _ := utf8.DecodeRuneInString(n); f {
		case '=', '+', '-', '@', 0x2212:
			gen = append(gen, r)
		}
	}
	if !slices.Equal(gen, FormulaLeadTable) {
		t.Fatalf("FormulaLeadTable differs from NFKC generator:\n got  %U\n want %U", FormulaLeadTable, gen)
	}
}

// The corpus of §12.2 (CS-01 … CS-22).
var corpus = []struct {
	id, in string
	want   Class
}{
	{"CS-01", "=1+1", FormulaLead}, {"CS-02", "+1+1", FormulaLead}, {"CS-03", "-1+1", FormulaLead},
	{"CS-04", "@SUM(1,1)", FormulaLead}, {"CS-05", "\t=1+1", FormulaLead},
	{"CS-06a", "\r=1+1", FormulaLead}, {"CS-06b", "\n=1+1", FormulaLead},
	{"CS-06c", "\rabc", FormulaLead}, {"CS-06d", "\tabc", FormulaLead}, {"CS-06e", "\nabc", FormulaLead},
	{"CS-07", "＝1+1", FormulaLead},
	{"CS-08a", "＋1+1", FormulaLead}, {"CS-08b", "－1+1", FormulaLead}, {"CS-08c", "＠SUM(1,1)", FormulaLead},
	{"CS-09a", "﹦1+1", FormulaLead}, {"CS-09b", "﹢1", FormulaLead}, {"CS-09c", "﹣1", FormulaLead}, {"CS-09d", "﹫A1", FormulaLead},
	{"CS-10a", "⁼1", FormulaLead}, {"CS-10b", "₌1", FormulaLead}, {"CS-10c", "⁺1", FormulaLead},
	{"CS-10d", "₊1", FormulaLead}, {"CS-10e", "⁻1", FormulaLead}, {"CS-10f", "₋1", FormulaLead},
	{"CS-11", "−1+1", FormulaLead},
	{"CS-12a", " =1+1", FormulaLead}, {"CS-12b", "\u00a0=1+1", FormulaLead}, {"CS-12c", "\u3000=1+1", FormulaLead},
	{"CS-13a", "\u200b=1+1", FormulaLead}, {"CS-13b", "\ufeff=1+1", FormulaLead}, {"CS-13c", "\u202e=1+1", FormulaLead},
	{"CS-13d", "\u00ad=1+1", FormulaLead}, {"CS-13e", "\u2060=1+1", FormulaLead},
	{"CS-14a", "\x01=1+1", FormulaLead}, {"CS-14b", "\x1f+1", FormulaLead},
	{"CS-15", "=", FormulaLead},
	{"CS-16a", "⩵1", FormulaLead}, {"CS-16b", "﬩1", FormulaLead},
	{"CS-17", "x=1+1", Plain}, {"CS-18", "'=1+1", Plain}, {"CS-19", "１２３", Plain}, {"CS-20", "", Plain},
	{"CS-21a", "|calc", Plain}, {"CS-21b", "%1", Plain}, {"CS-22", "🙂=1", Plain},
	{"ctrl-only", "\x01abc", Plain}, {"spaces-only", "   ", Plain}, {"bad-utf8", "\xff=1", Plain},
}

func TestCorpus(t *testing.T) {
	for _, c := range corpus {
		if got := Classify(c.in); got != c.want {
			t.Errorf("%s: Classify(%q) = %d, want %d", c.id, c.in, got, c.want)
		}
	}
}

func FuzzClassifyNeverPanics(f *testing.F) {
	for _, c := range corpus {
		f.Add(c.in)
	}
	f.Fuzz(func(t *testing.T, s string) { _ = Classify(s) })
}

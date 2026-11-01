package cellsafe

import (
	"slices"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/skenzeriq/activediq/internal/platform/corpus"
	"github.com/skenzeriq/activediq/internal/platform/corpus/corpustest"
)

func TestTableMatchesNFKC(t *testing.T) {
	if norm.Version != tableUnicodeVersion {
		t.Fatalf("norm.Version = %s, table.go pins tableUnicodeVersion = %s: re-verify the table, then update the const, the table.go comment and safe-primitives §12.2 together",
			norm.Version, tableUnicodeVersion)
	}
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

// TestCorpus runs CS-01 to CS-22 (testdata/safe-primitives/cellsafe.jsonl, safe-primitives §12.2,
// FF-SP4): 42 inputs, 35 hostile.
func TestCorpus(t *testing.T) {
	names := map[Class]string{Plain: "Plain", FormulaLead: "FormulaLead"}
	corpustest.Run(t, "go/cellsafe", "cellsafe", func(r corpus.Record) (corpus.Result, error) {
		if r.Call != "Classify" {
			return corpus.Result{}, corpustest.Skip("unknown call " + r.Call)
		}
		v, err := r.Arg("value")
		if err != nil {
			return corpus.Result{}, err
		}
		return corpustest.Render(names[Classify(v.Text())]), nil
	})
}

// Cases beyond the §12.2 table: a lone CR, TAB or LF lead (rule 1 needs no following lead), a
// control-only or space-only cell, and invalid UTF-8 before a lead.
func TestClassifyEdges(t *testing.T) {
	for _, c := range []struct {
		name, in string
		want     Class
	}{
		{"cr-then-text", "\rabc", FormulaLead}, {"tab-then-text", "\tabc", FormulaLead}, {"lf-then-text", "\nabc", FormulaLead},
		{"ctrl-only", "\x01abc", Plain}, {"spaces-only", "   ", Plain}, {"bad-utf8", "\xff=1", Plain},
	} {
		if got := Classify(c.in); got != c.want {
			t.Errorf("%s: Classify(%q) = %d, want %d", c.name, c.in, got, c.want)
		}
	}
}

// FuzzClassify checks the noFormulaLead property against an independent oracle: when Classify
// says Plain, the value, with its leading White_Space / Cc / Cf scalars skipped, does not NFKC-
// normalise to something that starts with a formula operator, and it does not start with TAB, CR
// or LF. (The oracle normalises a copy; Classify never normalises the value, R4.)
func FuzzClassify(f *testing.F) {
	corpustest.Seed(f, "cellsafe")
	f.Fuzz(func(t *testing.T, in []byte) {
		s := string(in)
		if Classify(s) == FormulaLead {
			return
		}
		if s != "" && (s[0] == '\t' || s[0] == '\r' || s[0] == '\n') {
			t.Fatalf("Classify(%q) = Plain for a TAB/CR/LF lead", s)
		}
		rest := strings.TrimLeftFunc(s, func(r rune) bool {
			return r != utf8.RuneError && (unicode.IsSpace(r) || unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r))
		})
		if rest == "" || !utf8.ValidString(rest[:min(len(rest), utf8.UTFMax)]) {
			return
		}
		first, _ := utf8.DecodeRuneInString(rest)
		n, _ := utf8.DecodeRuneInString(norm.NFKC.String(string(first)))
		switch n {
		case '=', '+', '-', '@', 0x2212:
			t.Fatalf("Classify(%q) = Plain but %U normalises to a formula lead %q", s, first, n)
		}
	})
}

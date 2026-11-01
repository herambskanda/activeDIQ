package addc

import (
	"testing"
	"unicode/utf16"

	"github.com/skenzeriq/activediq/internal/platform/agentpolicy"
)

func u(s string) []uint16 { return utf16.Encode([]rune(s)) }

func rules() agentpolicy.PasswordRules {
	return agentpolicy.PasswordRules{MinLength: 8, MaxLength: 32, MinClasses: 3,
		ClassesRequired: []agentpolicy.Class{agentpolicy.ClassDigit}, BannedTerms: []string{"Winter", "ПАРОЛЬ"},
		RejectSAMInPassword: true, RejectDisplayNameParts: true}
}

func TestEvaluate(t *testing.T) {
	e := Compile(rules())
	acct := Account{SAMAccountName: "jsmith", DisplayName: "Jane Q. Smith-Jones"}
	cases := []struct {
		name string
		pw   string
		want Verdict
	}{
		{"ok", "Tr0ub4dor&3x", VerdictAccept},
		{"short", "Ab1!", VerdictTooShort},
		{"long", "Aa1!Aa1!Aa1!Aa1!Aa1!Aa1!Aa1!Aa1!Aa1!", VerdictTooLong},
		{"no digit", "Abcdefgh!ijk", VerdictMissingClass},
		{"two classes", "abcdefgh1234", VerdictTooFewClasses},
		{"banned folded", "xxWINTERxx9Z!", VerdictBannedTerm},
		{"banned cyrillic", "x1!пароль.zz", VerdictBannedTerm},
		{"sam", "x1!JSMITHzzzz", VerdictContainsAccountName},
		{"display part", "q9!JoNeSzzzzz", VerdictContainsDisplayNamePart},
		{"short display part ignored", "q9!Q.zzzzzzz", VerdictAccept},
		{"fullwidth NFKC", "x1!Ｗｉｎｔｅｒzz", VerdictBannedTerm},
	}
	for _, c := range cases {
		if got := e.Evaluate(u(c.pw), acct); got != c.want {
			t.Errorf("%s: got %d want %d", c.name, got, c.want)
		}
	}
}

func TestUnpairedSurrogateIsMalformedNotPanic(t *testing.T) {
	e := Compile(rules())
	if got := e.Evaluate([]uint16{0xD800, 'a', '1', 'A', '!', 'x', 'y', 'z', 'w'}, Account{}); got != VerdictMalformed {
		t.Fatalf("got %d", got)
	}
	_ = e.Evaluate(nil, Account{})
}

func TestVerdictCarriesNoPassword(t *testing.T) {
	// The type is a uint8: it cannot hold any part of the candidate.
	var _ uint8 = uint8(VerdictAccept)
}

// F1/F2: arbitrary input and arbitrary banned terms never panic and terminate quickly.
func FuzzEvaluate(f *testing.F) {
	f.Add([]byte("Tr0ub4dor&3x"), "Winter")
	f.Add([]byte{0xff, 0xfe, 0xd8, 0x00}, "")
	f.Fuzz(func(t *testing.T, raw []byte, banned string) {
		pw := make([]uint16, 0, len(raw)/2)
		for i := 0; i+1 < len(raw); i += 2 {
			pw = append(pw, uint16(raw[i])|uint16(raw[i+1])<<8)
		}
		r := rules()
		r.BannedTerms = []string{banned}
		_ = Compile(r).Evaluate(pw, Account{SAMAccountName: banned, DisplayName: banned})
	})
}

func BenchmarkEvaluateWorstCase(b *testing.B) {
	r := rules()
	for i := 0; i < 20000; i++ {
		r.BannedTerms = append(r.BannedTerms, "term"+string(rune('a'+i%26))+"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")
	}
	e := Compile(r)
	pw := u("Aa1!Aa1!Aa1!Aa1!Aa1!Aa1!Aa1!")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.Evaluate(pw, Account{})
	}
}

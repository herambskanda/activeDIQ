package corpustest

import "testing"

// Seed adds every input of the unit's corpus (hostile and benign) to a fuzz target as a []byte
// seed. Every parser and encoder has one target that starts here (FF-SP5); the gate checks that the
// target exists and that its body calls Seed. The target's function takes []byte:
//
//	func FuzzRoundTrip(f *testing.F) {
//		corpustest.Seed(f, "ldapfilter")
//		f.Fuzz(func(t *testing.T, in []byte) { … parse(render(x)) == x … })
//	}
func Seed(f *testing.F, unit string) {
	f.Helper()
	file := Load(f, unit)
	n := 0
	for _, r := range file.Records {
		for _, in := range r.Inputs() {
			f.Add(in)
			n++
		}
	}
	if n == 0 {
		f.Fatalf("corpus unit %s has no inputs to seed from", unit)
	}
}

// NoUnescapedSpecial fails when data holds any byte of specials. The caller passes the data
// portion of the output with the primitive's own structural characters removed, and the characters
// its output language reserves, so an implementation cannot pass by escaping nothing.
func NoUnescapedSpecial(t testing.TB, data string, specials string) {
	t.Helper()
	for i := 0; i < len(data); i++ {
		for j := 0; j < len(specials); j++ {
			if data[i] == specials[j] {
				t.Fatalf("rendered data %q holds the unescaped special %q at byte %d", data, specials[j], i)
			}
		}
	}
}

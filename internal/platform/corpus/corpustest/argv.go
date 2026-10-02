package corpustest

import (
	"fmt"
	"math/rand"
	"os"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/skenzeriq/activediq/internal/platform/corpus"
)

// MinArgvRequests is the floor on the random requests one FF-SP8 run drives.
const MinArgvRequests = 100

// Elem is one element of a manifest's argv: a constant, a typed value slot, or a joined
// constant-flag-plus-value element.
type Elem struct {
	kind  elemKind
	Const string                   // the constant text, for a constant; the flag for a joined element
	Sep   string                   // joined: the separator
	Name  string                   // slot name, for messages
	Check func(value string) error // slot and joined: the type's own validity check (may be nil)
}

type elemKind int

const (
	constElem elemKind = iota
	slotElem
	joinedElem
)

// C is a constant argv element, spelled in the manifest.
func C(s string) Elem { return Elem{kind: constElem, Const: s} }

// Slot is an element holding one typed value (GUID, port, enum token, inventory host, managed path).
// The universal rules apply on top of check: no option-looking start, no control characters.
func Slot(name string, check func(string) error) Elem {
	return Elem{kind: slotElem, Name: name, Check: check}
}

// Joined is the element flag+sep+value built from a constant flag and separator and a typed value.
func Joined(flag, sep, name string, check func(string) error) Elem {
	return Elem{kind: joinedElem, Const: flag, Sep: sep, Name: name, Check: check}
}

// CheckArgv compares one observed argv with the manifest template: the same length, every constant
// byte-for-byte, every value slot a clean typed value. A request therefore cannot add, drop or
// reshape an argv element, which is what FF-SP8 asserts.
func CheckArgv(tpl []Elem, argv []string) error {
	if len(argv) != len(tpl) {
		return fmt.Errorf("argv has %d elements, the manifest has %d: %q", len(argv), len(tpl), argv)
	}
	for i, e := range tpl {
		got := argv[i]
		switch e.kind {
		case constElem:
			if got != e.Const {
				return fmt.Errorf("argv[%d] = %q, the manifest's constant is %q", i, got, e.Const)
			}
		case slotElem:
			if err := checkValue(e, got); err != nil {
				return fmt.Errorf("argv[%d] (%s): %w", i, e.Name, err)
			}
		case joinedElem:
			rest, ok := strings.CutPrefix(got, e.Const+e.Sep)
			if !ok {
				return fmt.Errorf("argv[%d] = %q, want the constant prefix %q", i, got, e.Const+e.Sep)
			}
			if e.Sep != "" && strings.Contains(rest, e.Sep) {
				return fmt.Errorf("argv[%d] (%s): the value %q holds the separator %q", i, e.Name, rest, e.Sep)
			}
			if strings.ContainsAny(rest, " \t\"") {
				return fmt.Errorf("argv[%d] (%s): the value %q holds whitespace or a double quote", i, e.Name, rest)
			}
			if err := checkValue(e, rest); err != nil {
				return fmt.Errorf("argv[%d] (%s): %w", i, e.Name, err)
			}
		}
	}
	return nil
}

func checkValue(e Elem, v string) error {
	if v == "" {
		return fmt.Errorf("empty value")
	}
	if !utf8.ValidString(v) {
		return fmt.Errorf("value %q is not valid UTF-8", v)
	}
	r, _ := utf8.DecodeRuneInString(v)
	if r == '-' || r == '/' || (r >= 0x2013 && r <= 0x2015) {
		return fmt.Errorf("value %q starts like an option", v)
	}
	for _, c := range v {
		if c < 0x20 || c == 0x7f {
			return fmt.Errorf("value %q holds a control character", v)
		}
	}
	if e.Check != nil {
		if err := e.Check(v); err != nil {
			return err
		}
	}
	return nil
}

// ArgvSpec drives one FF-SP8 run.
type ArgvSpec struct {
	Impl     string                          // the implementation name in the gate's manifest
	Requests int                             // random requests to drive; 0 means 500
	Seed     int64                           // 0 means 1; the run is deterministic for a seed
	Gen      func(rng *rand.Rand) any        // a random request, hostile values included (see HostileStrings)
	Observe  func(req any) ([]string, error) // runs the request through the real code and returns the argv the child would get
	Template func(req any) []Elem            // the manifest's argv for that request's operation
}

// ConstantArgv is the FF-SP8 test: for random requests the observed argv equals the manifest's
// constant argv, with only typed value slots varying. Failures name the request index and seed.
func ConstantArgv(t *testing.T, s ArgvSpec) {
	t.Helper()
	n := s.Requests
	if n == 0 {
		n = 500
	}
	if n < MinArgvRequests {
		t.Fatalf("FF-SP8 drives at least %d random requests, not %d", MinArgvRequests, n)
	}
	seed := s.Seed
	if seed == 0 {
		seed = 1
	}
	rng := rand.New(rand.NewSource(seed))
	rep := corpus.ArgvReport{Impl: s.Impl}
	for i := 0; i < n; i++ {
		req := s.Gen(rng)
		argv, err := s.Observe(req)
		rep.Requests++
		if err != nil {
			continue // a refused request starts no process: nothing to compare
		}
		if err := CheckArgv(s.Template(req), argv); err != nil {
			msg := fmt.Sprintf("request %d (seed %d): %v", i, seed, err)
			rep.Mismatches = append(rep.Mismatches, msg)
			if len(rep.Mismatches) <= 10 {
				t.Errorf("%s", msg)
			}
		}
	}
	if dir := os.Getenv(corpus.ReportDirEnv); dir != "" {
		if err := corpus.WriteReport(corpus.ReportPath(dir, "argv", s.Impl, "argv"), rep); err != nil {
			t.Fatalf("writing the argv report: %v", err)
		}
	}
}

// HostileStrings returns every hostile input of the given units: the pool a request generator
// draws values from, so FF-SP8 runs with the corpus's own attacks rather than friendly text.
func HostileStrings(t testing.TB, units ...string) []string {
	t.Helper()
	var out []string
	for _, u := range units {
		for _, r := range Load(t, u).Records {
			if !r.IsHostile() {
				continue
			}
			for _, in := range r.Inputs() {
				out = append(out, string(in))
			}
		}
	}
	return out
}

// Mutate returns s with a few random byte-level edits (insert, delete, flip, duplicate).
func Mutate(rng *rand.Rand, s string) string {
	b := []byte(s)
	for k := rng.Intn(3) + 1; k > 0; k-- {
		switch {
		case len(b) == 0 || rng.Intn(4) == 0:
			i := rng.Intn(len(b) + 1)
			b = append(b[:i], append([]byte{byte(rng.Intn(256))}, b[i:]...)...)
		case rng.Intn(3) == 0:
			i := rng.Intn(len(b))
			b = append(b[:i], b[i+1:]...)
		case rng.Intn(2) == 0:
			b[rng.Intn(len(b))] ^= 1 << uint(rng.Intn(8))
		default:
			b = append(b, b...)
		}
	}
	return string(b)
}

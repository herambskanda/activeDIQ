package authn

// AN-8 throttle tests (T-0497, from T-0359; threat model 7.6 rule 2 a-g, TM-F-ABUSE).
//
// The five tests below pin WHAT the spec requires of the break-glass password step, through the an8Target
// seam: they say nothing about how a handler is built. Two targets satisfy the seam:
//
//   - realAN8Target (an8_real_test.go) is the real handler of T-0200. Until T-0200 lands it reports
//     "not built" and the tests skip with a loud XFAIL line naming T-0200. T-0200 must not merge until it
//     fills that one function in and the tests pass against it. A skip here is never a pass.
//   - refAN8 (an8_ref_test.go) is a labelled reference MODEL of the spec, not product code. The meta
//     tests run the five assertions against it, and against deliberately broken mutants, to prove the
//     assertions accept a correct implementation and bite on each violation.

import (
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"
)

// an8Resp is everything a caller can observe of one AN-8 answer.
type an8Resp struct {
	Status  int
	Body    string
	Headers map[string][]string // canonical names; Content-Length included
}

// an8Seed is the account set every target is built with.
type an8Seed struct {
	Known    string // active local account
	Password string // its right password
	NonLocal string // exists, not a local account
	Disabled string // local but disabled
}

// an8Target is the seam. All time is the target's own fixed clock (Advance); nothing sleeps.
type an8Target interface {
	// Do submits one AN-8 request from source address ip.
	Do(name, password, ip string) an8Resp
	// Advance moves the target's clock.
	Advance(d time.Duration)
	// Keys is every throttle key the shared store holds right now.
	Keys() []string
	// Pending is the number of pending sign-ins created.
	Pending() int
	// FillTable makes the key table full with names unrelated to the seed.
	FillTable()
}

const (
	an8Wrong       = "not-the-password"
	an8BurstFails  = 5                // rule 3: delay starts after 5 failures
	an8DelayWindow = 15 * time.Minute // rule 3 ceiling: past it every delay has passed
)

var an8Seeds = an8Seed{Known: "bg-admin", Password: "correct horse battery staple", NonLocal: "corp-user", Disabled: "bg-old"}

// newTarget builds the target for a test: the real handler when it is built, else the XFAIL skip.
func newRealTarget(t *testing.T) an8Target {
	t.Helper()
	tg, ok := realAN8Target(t, an8Seeds)
	if !ok {
		t.Skipf("XFAIL T-0200: the AN-8 handler is still a 501 stub, so this spec test cannot run against it; " +
			"T-0200 must wire realAN8Target (an8_real_test.go) and this test must pass before it merges. " +
			"The assertions are proven by TestAN8AssertionsAgainstReference.")
	}
	return tg
}

// ---- the five assertions, each a function of a target so the meta tests can reuse them -------------

func an8ThrottledKnownEqualsUnknown(t an8T, tg an8Target) {
	t.Helper()
	const unknown = "no-such-account"
	drive := func(name string) {
		for i := 0; i < an8BurstFails+3; i++ { // past burst 5
			tg.Do(name, an8Wrong, "198.51.100.1")
		}
	}
	drive(an8Seeds.Known)
	drive(unknown)

	// In the delay window: a wrong and the RIGHT password for the known name, against the unknown name.
	k := tg.Do(an8Seeds.Known, an8Wrong, "198.51.100.2")
	u := tg.Do(unknown, an8Wrong, "198.51.100.2")
	kRight := tg.Do(an8Seeds.Known, an8Seeds.Password, "198.51.100.2")
	assertSameAnswer(t, "throttled known vs unknown (wrong password)", k, u)
	assertSameAnswer(t, "throttled known (right password) vs unknown", kRight, u)
	if u.Status != 401 {
		t.Errorf("throttled answer status = %d, want the uniform 401", u.Status)
	}

	// Past the rule-3 window, the wrong-password answers are still the same for both names.
	tg.Advance(an8DelayWindow + time.Second)
	assertSameAnswer(t, "after the window, known vs unknown wrong password",
		tg.Do(an8Seeds.Known, an8Wrong, "198.51.100.3"), tg.Do(unknown, an8Wrong, "198.51.100.3"))
}

func an8NeverAnswersPerAccount429(t an8T, tg an8Target) {
	t.Helper()
	// 100 requests for one name over 10 source IPs: 10 each, far under the per-IP auth burst of 30.
	for _, name := range []string{an8Seeds.Known, "no-such-account"} {
		for i := 0; i < 100; i++ {
			ip := fmt.Sprintf("203.0.113.%d", 1+i%10)
			r := tg.Do(name, an8Wrong, ip)
			if r.Status == 429 {
				t.Fatalf("request %d for %q from %s answered 429: a per-account 429 is an enumeration oracle (rule 2)", i+1, name, ip)
			}
			if r.Status != 401 {
				t.Fatalf("request %d for %q answered %d, want the uniform 401", i+1, name, r.Status)
			}
			if _, ok := r.Headers["Retry-After"]; ok {
				t.Fatalf("request %d for %q carries Retry-After: AN-8 gives none (rule 2c)", i+1, name)
			}
		}
	}
}

func an8ThrottledCorrectPasswordRefused(t an8T, tg an8Target) {
	t.Helper()
	for i := 0; i < an8BurstFails; i++ {
		tg.Do(an8Seeds.Known, an8Wrong, "198.51.100.9")
	}
	before := tg.Pending()
	r := tg.Do(an8Seeds.Known, an8Seeds.Password, "198.51.100.9")
	if r.Status != 401 {
		t.Fatalf("right password while throttled answered %d, want the uniform 401 (rule 2b: not evaluated)", r.Status)
	}
	if got := tg.Pending(); got != before {
		t.Fatalf("pending sign-ins %d -> %d: a throttled attempt must create none", before, got)
	}
	if _, ok := r.Headers["Set-Cookie"]; ok {
		t.Fatalf("throttled answer sets a cookie: %v", r.Headers["Set-Cookie"])
	}
	// Throttled, never locked (rule 3): once the delay has passed the right password works.
	tg.Advance(an8DelayWindow + time.Second)
	if r := tg.Do(an8Seeds.Known, an8Seeds.Password, "198.51.100.9"); r.Status != 204 || tg.Pending() != before+1 {
		t.Fatalf("after the delay the right password answered %d with %d pending: the account must never be locked", r.Status, tg.Pending())
	}
}

func an8ThrottleKeyIgnoresExistence(t an8T, tg an8Target) {
	t.Helper()
	names := []string{an8Seeds.Known, an8Seeds.NonLocal, an8Seeds.Disabled, "no-such-account"}
	for _, n := range names {
		before := len(tg.Keys())
		tg.Do(n, an8Wrong, "198.51.100.20")
		if got := len(tg.Keys()) - before; got != 1 {
			t.Errorf("one failed attempt for %q created %d keys, want exactly 1 whether or not the account exists, is local or is disabled (rule 2a)", n, got)
		}
	}
	// Spelling variants reach the same key (trim, NFC, case-fold).
	base := len(tg.Keys())
	for _, v := range []string{"  " + an8Seeds.Known + " ", strings.ToUpper(an8Seeds.Known)} {
		tg.Do(v, an8Wrong, "198.51.100.21")
	}
	if got := len(tg.Keys()); got != base {
		t.Errorf("trim/case variants of %q created %d new keys, want 0", an8Seeds.Known, got-base)
	}
	nfc, nfd := "café-admin", "café-admin"
	tg.Do(nfc, an8Wrong, "198.51.100.22")
	n1 := len(tg.Keys())
	tg.Do(nfd, an8Wrong, "198.51.100.22")
	if len(tg.Keys()) != n1 {
		t.Errorf("NFC and NFD spellings of one name reached different keys: a variant could get a fresh bucket (rule 2a)")
	}
	// The store holds a hash, never the name.
	keys := tg.Keys()
	sort.Strings(keys)
	for _, k := range keys {
		for _, n := range append(names, nfc) {
			if strings.Contains(strings.ToLower(k), strings.ToLower(n)) {
				t.Errorf("store key %q contains the submitted name %q: it must hold only the HMAC (rule 2a)", k, n)
			}
		}
	}
}

func an8TableFullIsNameIndependent(t an8T, tg an8Target) {
	t.Helper()
	tg.FillTable()
	newKnown := tg.Do(an8Seeds.Known, an8Wrong, "198.51.100.30") // a new key for a real account
	newUnknown := tg.Do("never-seen-before", an8Wrong, "198.51.100.30")
	assertSameAnswer(t, "table full: new existing vs new unknown name", newKnown, newUnknown)
	if newKnown.Status != 401 {
		t.Errorf("table full answered %d, want the uniform 401 (the cap must not be observable per name)", newKnown.Status)
	}
}

func assertSameAnswer(t an8T, what string, a, b an8Resp) {
	t.Helper()
	if a.Status != b.Status {
		t.Errorf("%s: status %d != %d", what, a.Status, b.Status)
	}
	if a.Body != b.Body {
		t.Errorf("%s: body differs:\n  %q\n  %q", what, a.Body, b.Body)
	}
	if fmt.Sprint(sortedHeaders(a.Headers)) != fmt.Sprint(sortedHeaders(b.Headers)) {
		t.Errorf("%s: headers differ:\n  %v\n  %v", what, sortedHeaders(a.Headers), sortedHeaders(b.Headers))
	}
	for _, r := range []an8Resp{a, b} {
		if _, ok := r.Headers["Retry-After"]; ok {
			t.Errorf("%s: Retry-After present (AN-8 gives none, rule 2c)", what)
		}
	}
}

func sortedHeaders(h map[string][]string) []string {
	var out []string
	for k, v := range h {
		out = append(out, k+": "+strings.Join(v, ","))
	}
	sort.Strings(out)
	return out
}

// ---- the five named tests, against the real handler -------------------------------------------------

func TestAN8ThrottledKnownEqualsUnknown(t *testing.T) {
	an8ThrottledKnownEqualsUnknown(t, newRealTarget(t))
}
func TestAN8NeverAnswersPerAccount429(t *testing.T) {
	an8NeverAnswersPerAccount429(t, newRealTarget(t))
}
func TestAN8ThrottledCorrectPasswordRefused(t *testing.T) {
	an8ThrottledCorrectPasswordRefused(t, newRealTarget(t))
}
func TestAN8ThrottleKeyIgnoresExistence(t *testing.T) {
	an8ThrottleKeyIgnoresExistence(t, newRealTarget(t))
}
func TestAN8TableFullIsNameIndependent(t *testing.T) {
	an8TableFullIsNameIndependent(t, newRealTarget(t))
}

// an8T is the part of *testing.T the assertions use, so the meta tests can run them against a mutant and
// observe the failure instead of failing themselves.
type an8T interface {
	Helper()
	Errorf(format string, args ...any)
	Fatalf(format string, args ...any)
}

// an8Recorder records failures; Fatalf unwinds like testing.T does.
type an8Recorder struct{ failures []string }

type an8Stop struct{}

func (r *an8Recorder) Helper() {}
func (r *an8Recorder) Errorf(f string, a ...any) {
	r.failures = append(r.failures, fmt.Sprintf(f, a...))
}
func (r *an8Recorder) Fatalf(f string, a ...any) { r.Errorf(f, a...); panic(an8Stop{}) }

// runCaptured runs fn and reports whether it recorded a failure.
func runCaptured(fn func(an8T)) (failures []string) {
	r := &an8Recorder{}
	func() {
		defer func() {
			if v := recover(); v != nil {
				if _, ok := v.(an8Stop); !ok {
					panic(v)
				}
			}
		}()
		fn(r)
	}()
	return r.failures
}

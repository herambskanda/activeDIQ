package authn

// refAN8 is a REFERENCE MODEL of threat model 7.6 rule 2 a-g, written only to prove the TestAN8*
// assertions. It is test code, not product code, and it is not the handler: it never stands in for the
// real target (an8_real_test.go). Each flag in an8Mutation breaks one rule so the meta test can show the
// assertions bite.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/text/unicode/norm"
)

type an8Mutation struct {
	PerAccount429     bool // answers 429 for a name that was tried a lot
	SkipUnknownKey    bool // no throttle key for names that are not real accounts (the oracle)
	EvalWhenLimited   bool // checks the password while throttled
	NoNormalise       bool // key is the raw submitted name
	RawNameKey        bool // key is the name itself, not an HMAC
	RetryAfter        bool // adds Retry-After when throttled
	DistinctThrottled bool // throttled body differs for existing accounts
	FullTable429      bool // a full table answers differently for new real accounts
}

type refKeyState struct {
	fails int
	until time.Time
}

type refAN8 struct {
	m       an8Mutation
	seed    an8Seed
	now     time.Time
	keyHMAC []byte
	table   map[string]*refKeyState
	cap     int
	perIP   map[string]int
	pending int
}

const refTableCap = 50

func newRefAN8(seed an8Seed, m an8Mutation) *refAN8 {
	return &refAN8{m: m, seed: seed, now: time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC),
		keyHMAC: []byte("test-server-key"), table: map[string]*refKeyState{}, cap: refTableCap, perIP: map[string]int{}}
}

func (r *refAN8) norm(name string) string {
	if r.m.NoNormalise {
		return name
	}
	return strings.ToLower(norm.NFC.String(strings.TrimSpace(name)))
}

func (r *refAN8) key(name string) string {
	n := r.norm(name)
	if r.m.RawNameKey {
		return "t1:" + n
	}
	h := hmac.New(sha256.New, r.keyHMAC)
	h.Write([]byte("t1\x00" + n))
	return hex.EncodeToString(h.Sum(nil))
}

func (r *refAN8) isReal(name string) bool {
	n := r.norm(name)
	return n == r.norm(r.seed.Known) || n == r.norm(r.seed.NonLocal) || n == r.norm(r.seed.Disabled)
}

func (r *refAN8) fail() an8Resp {
	body := `{"type":"/problems/sign-in-failed","title":"Sign-in failed","status":401}`
	return an8Resp{Status: 401, Body: body, Headers: map[string][]string{
		"Content-Type": {"application/problem+json"}, "Content-Length": {strconv.Itoa(len(body))}}}
}

func (r *refAN8) Do(name, password, ip string) an8Resp {
	r.perIP[ip]++
	if r.perIP[ip] > 30 { // source-IP 429 only, decided before the name is known
		return an8Resp{Status: 429, Body: `{"status":429}`, Headers: map[string][]string{"Retry-After": {"60"}}}
	}
	k := r.key(name)
	real := r.isReal(name)
	st := r.table[k]
	if st == nil {
		if r.m.SkipUnknownKey && !real {
			return r.fail() // dummy hash would run here; no state is kept
		}
		if len(r.table) >= r.cap {
			k = "overflow"
			if st = r.table[k]; st == nil {
				st = &refKeyState{}
				r.table[k] = st
			}
			if r.m.FullTable429 && real {
				resp := r.fail()
				resp.Headers["X-Overflow"] = []string{"1"}
				return resp
			}
		} else {
			st = &refKeyState{}
			r.table[k] = st
		}
	}
	throttled := st.fails >= an8BurstFails && r.now.Before(st.until)
	if throttled {
		st.fails++ // rule 2f: counts as a failure, ceiling is the 15 minute cap
		st.until = r.now.Add(r.delay(st.fails))
		if r.m.PerAccount429 {
			return an8Resp{Status: 429, Body: `{"status":429}`, Headers: map[string][]string{}}
		}
		if r.m.EvalWhenLimited && r.checkPassword(name, password) {
			r.pending++
			return an8Resp{Status: 204, Headers: map[string][]string{"Set-Cookie": {"__Host-adiq_pending=x"}}}
		}
		resp := r.fail()
		if r.m.RetryAfter {
			resp.Headers["Retry-After"] = []string{"1"}
		}
		if r.m.DistinctThrottled && real {
			resp.Body += " "
			resp.Headers["Content-Length"] = []string{strconv.Itoa(len(resp.Body))}
		}
		return resp
	}
	if r.checkPassword(name, password) {
		st.fails = 0
		r.pending++
		return an8Resp{Status: 204, Headers: map[string][]string{"Set-Cookie": {"__Host-adiq_pending=x"}}}
	}
	st.fails++
	if st.fails >= an8BurstFails {
		st.until = r.now.Add(r.delay(st.fails))
	}
	return r.fail()
}

// checkPassword is the local-active-account check; other names cost a dummy verification and fail.
func (r *refAN8) checkPassword(name, password string) bool {
	return r.norm(name) == r.norm(r.seed.Known) && password == r.seed.Password
}

// delay is 1 s doubling after the fifth failure, capped at 15 minutes.
func (r *refAN8) delay(fails int) time.Duration {
	d := time.Second
	for i := an8BurstFails; i < fails && d < an8DelayWindow; i++ {
		d *= 2
	}
	if d > an8DelayWindow {
		d = an8DelayWindow
	}
	return d
}

func (r *refAN8) Advance(d time.Duration) { r.now = r.now.Add(d) }
func (r *refAN8) Pending() int            { return r.pending }
func (r *refAN8) Keys() []string {
	out := make([]string, 0, len(r.table))
	for k := range r.table {
		out = append(out, k)
	}
	return out
}
func (r *refAN8) FillTable() {
	for i := 0; len(r.table) < r.cap-1; i++ {
		r.table[r.key("filler-"+strconv.Itoa(i))] = &refKeyState{}
	}
	r.table["overflow-reserved"] = &refKeyState{}
}

// ---- meta tests ------------------------------------------------------------------------------------

type an8Assertion struct {
	name string
	run  func(an8T, an8Target)
}

var an8Assertions = []an8Assertion{
	{"ThrottledKnownEqualsUnknown", an8ThrottledKnownEqualsUnknown},
	{"NeverAnswersPerAccount429", an8NeverAnswersPerAccount429},
	{"ThrottledCorrectPasswordRefused", an8ThrottledCorrectPasswordRefused},
	{"ThrottleKeyIgnoresExistence", an8ThrottleKeyIgnoresExistence},
	{"TableFullIsNameIndependent", an8TableFullIsNameIndependent},
}

// The five assertions accept a correct implementation of the spec.
func TestAN8AssertionsAgainstReference(t *testing.T) {
	for _, a := range an8Assertions {
		t.Run(a.name, func(t *testing.T) { a.run(t, newRefAN8(an8Seeds, an8Mutation{})) })
	}
}

// Each violation of rule 2 makes the assertion that guards it fail: the tests bite.
func TestAN8AssertionsBiteOnMutants(t *testing.T) {
	cases := []struct {
		mutant string
		m      an8Mutation
		caught string // assertion that must fail
	}{
		{"per-account 429", an8Mutation{PerAccount429: true}, "NeverAnswersPerAccount429"},
		{"per-account 429 (known != unknown)", an8Mutation{PerAccount429: true}, "ThrottledKnownEqualsUnknown"},
		{"no key for unknown names", an8Mutation{SkipUnknownKey: true}, "ThrottleKeyIgnoresExistence"},
		{"password evaluated while throttled", an8Mutation{EvalWhenLimited: true}, "ThrottledCorrectPasswordRefused"},
		{"no normalisation", an8Mutation{NoNormalise: true}, "ThrottleKeyIgnoresExistence"},
		{"key is the raw name", an8Mutation{RawNameKey: true}, "ThrottleKeyIgnoresExistence"},
		{"Retry-After on throttle", an8Mutation{RetryAfter: true}, "ThrottledKnownEqualsUnknown"},
		{"throttled body differs for real accounts", an8Mutation{DistinctThrottled: true}, "ThrottledKnownEqualsUnknown"},
		{"full table observable per name", an8Mutation{FullTable429: true}, "TableFullIsNameIndependent"},
	}
	for _, c := range cases {
		a := pick(c.caught)
		t.Run(c.mutant+"/"+c.caught, func(t *testing.T) {
			failures := runCaptured(func(rt an8T) { a.run(rt, newRefAN8(an8Seeds, c.m)) })
			if len(failures) == 0 {
				t.Fatalf("mutant %q passed %s: the assertion does not guard the rule", c.mutant, c.caught)
			}
			t.Logf("caught: %s", failures[0])
		})
	}
}

func pick(name string) an8Assertion {
	for _, a := range an8Assertions {
		if a.name == name {
			return a
		}
	}
	panic("unknown assertion " + name)
}

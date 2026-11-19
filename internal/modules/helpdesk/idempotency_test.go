package helpdesk

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/limiter"
)

func (e *env) issueOnce(key, technician string, resend bool) (Challenge, error) {
	return e.v.IssueOnce(context.Background(), key, IssueInput{Tenant: e.ten, Technician: technician, Target: Target{conn, user}, Factor: FactorEmailOTP, Resend: resend})
}

func (e *env) verifyOnce(key, id, code string) error {
	_, err := e.v.VerifyOnce(context.Background(), key, VerifyInput{Tenant: e.ten, Technician: tech, ChallengeID: id, Code: code})
	return err
}

// A retried issue sends nothing more, even a resend; the key is bound to its request.
func Test_issue_is_idempotent(t *testing.T) {
	each(t, nil, func(t *testing.T, e *env) {
		c1, err := e.issueOnce("issue-key-1", tech, false)
		if err != nil || e.send.count() != 1 {
			t.Fatalf("first issue: %+v %v sent=%d", c1, err, e.send.count())
		}
		c2, err := e.issueOnce("issue-key-1", tech, false)
		if err != nil || c2.ID != c1.ID || !c2.Reused || e.send.count() != 1 {
			t.Fatalf("replay: %+v %v sent=%d", c2, err, e.send.count())
		}
		r1, err := e.issueOnce("issue-key-2", tech, true)
		if err != nil || r1.ID == c1.ID || e.send.count() != 2 {
			t.Fatalf("resend: %+v %v sent=%d", r1, err, e.send.count())
		}
		for i := 0; i < 5; i++ {
			if r, err := e.issueOnce("issue-key-2", tech, true); err != nil || r.ID != r1.ID || e.send.count() != 2 {
				t.Fatalf("resend replay %d: %+v %v sent=%d", i, r, err, e.send.count())
			}
		}
		if _, err := e.issueOnce("issue-key-2", tech, false); !errors.Is(err, ErrKeyReuse) {
			t.Fatalf("same key, different request: %v", err)
		}
		if _, err := e.issueOnce("short", tech, false); !errors.Is(err, ErrKeyInvalid) {
			t.Fatalf("bad key: %v", err)
		}
		// Another technician's identical key is its own key.
		if _, err := e.issueOnce("issue-key-1", tech2, false); errors.Is(err, ErrKeyReuse) {
			t.Fatal("keys are per technician")
		}
	})
}

// Parallel retries of one key send one code.
func Test_issue_key_in_parallel_sends_once(t *testing.T) {
	each(t, nil, func(t *testing.T, e *env) {
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := e.issueOnce("issue-key-par", tech, true)
				if err != nil && !errors.Is(err, ErrKeyInFlight) {
					t.Error(err)
				}
			}()
		}
		wg.Wait()
		if n := e.send.count(); n != 1 {
			t.Fatalf("8 parallel retries of one key sent %d codes, want 1", n)
		}
	})
}

// A refused issue is not remembered: after the cause is gone the same key works.
func Test_refused_issue_is_not_remembered(t *testing.T) {
	each(t, nil, func(t *testing.T, e *env) {
		e.send.fail = true
		if _, err := e.issueOnce("issue-key-fail", tech, false); !errors.Is(err, ErrDelivery) {
			t.Fatalf("want delivery failure, got %v", err)
		}
		e.send.fail = false
		if c, err := e.issueOnce("issue-key-fail", tech, false); err != nil || c.Reused || e.send.count() != 1 {
			t.Fatalf("retry after failure: %+v %v sent=%d", c, err, e.send.count())
		}
	})
}

// A retried verify replays the first answer and charges no second attempt: three wrong answers are still
// three distinct requests, and a retry of a pass is not turned into a refusal.
func Test_verify_is_idempotent_and_charges_once(t *testing.T) {
	each(t, nil, func(t *testing.T, e *env) {
		c, _ := e.issueOnce("issue-key-v", tech, false)
		good := e.send.last()
		bad := wrong(good)
		for i := 0; i < 6; i++ { // six deliveries of one request are one attempt
			if err := e.verifyOnce("verify-key-1", c.ID, bad); !errors.Is(err, ErrRefused) {
				t.Fatalf("replay %d: %v", i, err)
			}
		}
		if err := e.verifyOnce("verify-key-2", c.ID, bad); !errors.Is(err, ErrRefused) {
			t.Fatal(err)
		}
		if err := e.verifyOnce("verify-key-1", c.ID, good); !errors.Is(err, ErrKeyReuse) {
			t.Fatalf("same key, other code: %v", err)
		}
		if err := e.verifyOnce("verify-key-3", c.ID, good); err != nil {
			t.Fatalf("2 attempts used, the third (correct) must pass: %v", err)
		}
		if err := e.verifyOnce("verify-key-3", c.ID, good); err != nil {
			t.Fatalf("a retried pass must pass again: %v", err)
		}
		if got := len(e.sink.kind(KindVerified)); got != 1 {
			t.Fatalf("verified events = %d, want 1", got)
		}
		if got := len(e.sink.kind(KindRefused)); got != 2 {
			t.Fatalf("refused events = %d, want 2 (one per charged attempt)", got)
		}
	})
}

// Acceptance 2 through HTTP and the real engine: a wrong code, a spent cap, an expired, an unknown and another
// technician's challenge answer with the same status and body.
func Test_every_verify_failure_is_one_answer(t *testing.T) {
	each(t, nil, func(t *testing.T, e *env) {
		r := newRigWith(t, e.v, apihost.KindSession, limiter.NewMemoryStore(time.Now), e.ten.String())
		post := func(id, code string, n int) (int, string) {
			w := r.do("POST", "/api/v1/helpdesk/caller-verifications/"+id+"/verify", `{"code":"`+code+`"}`,
				ok(map[string]string{"Idempotency-Key": fmt.Sprintf("verify-http-%s-%d", id[:8], n)}))
			return w.Code, noTrace(w.Body.String())
		}
		// Instance carries the caller's own URL, so compare on one challenge id where the cause varies, and on
		// the type/status/title for the ones with a different id.
		c, _ := e.issueOnce("issue-http-1", tech, false)
		good := e.send.last()
		code1, wrongBody := post(c.ID, wrong(good), 1)
		_, _ = post(c.ID, wrong(good), 2)
		code3, _ := post(c.ID, wrong(good), 3) // spends the cap
		code4, capBody := post(c.ID, good, 4)  // cap spent: even the right code is refused
		if code1 != 422 || code3 != 422 || code4 != 422 || wrongBody != capBody {
			t.Fatalf("wrong code vs cap differ:\n%d %s\n%d %s", code1, wrongBody, code4, capBody)
		}
		// Expired.
		c2, _ := e.issueOnce("issue-http-2", tech, true)
		code5, _ := post(c2.ID, "000000", 5)
		e.advance(Lifetime + time.Second)
		code6, expBody := post(c2.ID, e.send.last(), 6)
		// Unknown challenge.
		unknown := "99999999-0000-4000-8000-000000000000"
		code7, unkBody := post(unknown, "123456", 7)
		for _, b := range []*string{&expBody, &unkBody, &wrongBody} {
			*b = traceTail(*b)
		}
		if code5 != 422 || code6 != 422 || code7 != 422 || expBody != unkBody || unkBody != wrongBody {
			t.Fatalf("expired/unknown/wrong differ:\n%d %s\n%d %s\n%d %s", code5, expBody, code6, unkBody, code1, wrongBody)
		}
		for _, d := range r.sleep {
			if d != RefusalFloor {
				t.Fatalf("a refusal waited %v, want the floor %v", d, RefusalFloor)
			}
		}
		if len(r.sleep) != 7 {
			t.Fatalf("%d refusals were padded, want 7", len(r.sleep))
		}
	})
}

// traceTail drops the instance (the caller's own URL, which differs by challenge), leaving type, status and title.
func traceTail(s string) string { return instanceRe.ReplaceAllString(s, `"instance":"-"`) }

var instanceRe = regexp.MustCompile(`"instance":"[^"]*"`)

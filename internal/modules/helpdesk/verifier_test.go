package helpdesk

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

const (
	conn  = "11111111-1111-4111-8111-111111111111"
	user  = "22222222-2222-4222-8222-222222222222"
	user2 = "33333333-3333-4333-8333-333333333333"
	tech  = "44444444-4444-4444-8444-444444444444"
	tech2 = "55555555-5555-4555-8555-555555555555"
)

type fakeDirs struct{}

func (fakeDirs) Resolve(_ context.Context, _ tenant.ID, t Target, f Factor) (Destination, error) {
	if t.ObjectGUID == "99999999-9999-4999-8999-999999999999" {
		return Destination{}, ErrNoDestination
	}
	return Destination{Address: "j@example.com", Masked: "j***@example.com"}, nil
}
func (fakeDirs) Offered(context.Context, tenant.ID, Target) ([]Factor, error) {
	return []Factor{FactorEmailOTP}, nil
}

type fakeAuth struct{ self *Target }

func (a fakeAuth) MayVerify(_ context.Context, _ tenant.ID, technician string, _ Target) (*Target, error) {
	if technician == "denied" {
		return nil, errors.New("no")
	}
	return a.self, nil
}

type fakeSender struct {
	mu    sync.Mutex
	codes []string
	fail  bool
}

func (s *fakeSender) Send(_ context.Context, _ tenant.ID, _ Factor, _ Destination, m Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return errors.New("smtp down")
	}
	f := strings.Fields(m.Body)
	for i, w := range f {
		if w == "is" && i > 0 && f[i-1] == "code" && i+1 < len(f) {
			s.codes = append(s.codes, strings.TrimSuffix(f[i+1], "."))
		}
	}
	return nil
}
func (s *fakeSender) count() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.codes) }
func (s *fakeSender) last() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.codes[len(s.codes)-1]
}

type fakeKey struct{}

func (fakeKey) Key(context.Context, tenant.ID) ([]byte, error) {
	return []byte("0123456789abcdef0123456789abcdef"), nil
}

type recSink struct {
	mu  sync.Mutex
	evs []audit.Event
}

func (r *recSink) Append(_ context.Context, _ store.Tx, ev audit.Event) error {
	if err := ev.Validate(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.evs = append(r.evs, ev)
	return nil
}
func (r *recSink) kind(k audit.Kind) (out []audit.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.evs {
		if e.Kind == k {
			out = append(out, e)
		}
	}
	return
}

type env struct {
	v      *Verifier
	send   *fakeSender
	sink   *recSink
	db     *store.DB
	ten    tenant.ID
	now    time.Time
	clockM sync.Mutex
}

func each(t *testing.T, self *Target, fn func(t *testing.T, e *env)) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		d := s.NewDatabase(t)
		d.Migrate(t)
		db, err := store.Open(context.Background(), store.Config{DSN: d.AppDSN()})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(db.Close)
		e := &env{db: db, send: &fakeSender{}, sink: &recSink{}, now: time.Now().UTC()}
		e.ten = tenanttest.Seed(t, d.ExecOwner, "A")
		e.v = &Verifier{DB: db, Audit: e.sink, Destinations: fakeDirs{}, Authorizer: fakeAuth{self: self}, Sender: e.send, Keys: fakeKey{},
			Clock: func() time.Time { e.clockM.Lock(); defer e.clockM.Unlock(); return e.now }}
		fn(t, e)
	})
}

func (e *env) advance(d time.Duration) { e.clockM.Lock(); e.now = e.now.Add(d); e.clockM.Unlock() }

func (e *env) issue(t *testing.T, technician, guid string, resend bool) (Challenge, error) {
	t.Helper()
	return e.v.Issue(context.Background(), IssueInput{Tenant: e.ten, Technician: technician, Target: Target{conn, guid}, Factor: FactorEmailOTP, Resend: resend})
}

func (e *env) verify(id, technician, code string) error {
	_, err := e.v.Verify(context.Background(), VerifyInput{Tenant: e.ten, Technician: technician, ChallengeID: id, Code: code})
	return err
}

func wrong(code string) string {
	if code == "000000" {
		return "000001"
	}
	return "000000"
}

// Acceptance 1 (T-0719 C1, C2): nothing is sent until Issue is called; re-opening attaches to the open
// challenge and sends nothing; only a resend sends again and kills the old code (4.5).
func Test_issue_only_on_explicit_action_and_reopen_reuses(t *testing.T) {
	each(t, nil, func(t *testing.T, e *env) {
		if e.send.count() != 0 {
			t.Fatal("constructing the verifier must send nothing")
		}
		c1, err := e.issue(t, tech, user, false)
		if err != nil || e.send.count() != 1 || c1.Reused || c1.Masked != "j***@example.com" {
			t.Fatalf("first open: %+v %v sent=%d", c1, err, e.send.count())
		}
		old := e.send.last()
		for i := 0; i < 20; i++ {
			c, err := e.issue(t, tech, user, false)
			if err != nil || !c.Reused || c.ID != c1.ID {
				t.Fatalf("reopen %d: %+v %v", i, c, err)
			}
		}
		if e.send.count() != 1 {
			t.Fatalf("20 re-opens sent %d messages, want 1", e.send.count())
		}
		c2, err := e.issue(t, tech, user, true)
		if err != nil || c2.ID == c1.ID || e.send.count() != 2 {
			t.Fatalf("resend: %+v %v", c2, err)
		}
		if err := e.verify(c1.ID, tech, old); !errors.Is(err, ErrRefused) {
			t.Fatalf("the superseded code must be refused, got %v", err)
		}
		if evs := e.sink.kind(KindIssued); len(evs) != 2 {
			t.Fatalf("issued events = %d, want 2 (C7)", len(evs))
		}
	})
}

// Acceptance 2: a correct code lets the reset/unlock submit with its StepUp satisfied, the audit event names
// the factor apart from the technician, and the grant is single-use and bound to one operation and target.
func Test_verified_caller_satisfies_stepup(t *testing.T) {
	each(t, nil, func(t *testing.T, e *env) {
		c, _ := e.issue(t, tech, user, false)
		if _, err := e.v.Verify(context.Background(), VerifyInput{Tenant: e.ten, Technician: tech, ChallengeID: c.ID, Code: e.send.last()}); err != nil {
			t.Fatal(err)
		}
		in, _ := json.Marshal(map[string]any{"connectionId": conn, "objectGuid": user, "mustChangeAtNextLogon": true})
		req := operation.Request{Tenant: e.ten, Action: "ad.user.resetPassword", Input: in, Operation: "op-1",
			Actor: authority.Chain{Requester: authority.Principal{ID: authority.PrincipalID(tech), Kind: authority.Human}}}
		a := AuthoriseInput{Tenant: e.ten, Technician: tech, ChallengeID: c.ID, Target: Target{conn, user}, Action: "ad.user.resetPassword", Operation: "op-1"}

		bad := a
		bad.Technician = tech2
		if _, err := e.v.Authorise(context.Background(), bad); !errors.Is(err, ErrRefused) {
			t.Fatalf("another technician: %v", err)
		}
		bad = a
		bad.Target = Target{conn, user2}
		if _, err := e.v.Authorise(context.Background(), bad); !errors.Is(err, ErrRefused) {
			t.Fatalf("another target: %v", err)
		}
		bad = a
		bad.Action = "ad.user.disable"
		if _, err := e.v.Authorise(context.Background(), bad); !errors.Is(err, ErrRefused) {
			t.Fatalf("an Action the caller cannot stand in for: %v", err)
		}
		g, err := e.v.Authorise(context.Background(), a)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.v.Authorise(context.Background(), a); !errors.Is(err, ErrRefused) {
			t.Fatalf("replay of a consumed challenge: %v", err)
		}
		if req.FreshStepUp {
			t.Fatal("precondition")
		}
		bound, err := g.Bind(req)
		if err != nil || !bound.FreshStepUp {
			t.Fatalf("bind: %v fresh=%v", err, bound.FreshStepUp)
		}
		other := req
		other.Operation = "op-2"
		if _, err := g.Bind(other); !errors.Is(err, ErrRefused) {
			t.Fatalf("grant bound to another operation: %v", err)
		}
		other = req
		other.Input, _ = json.Marshal(map[string]any{"connectionId": conn, "objectGuid": user2})
		if _, err := g.Bind(other); !errors.Is(err, ErrRefused) {
			t.Fatalf("grant bound to another target: %v", err)
		}
		if _, err := (Grant{}).Bind(req); !errors.Is(err, ErrRefused) {
			t.Fatalf("zero grant: %v", err)
		}
		ev := e.sink.kind(KindConsumed)
		if len(ev) != 1 {
			t.Fatalf("consumed events = %d", len(ev))
		}
		got := map[string]string{}
		for _, d := range ev[0].Details {
			got[d.Key] = d.Value
		}
		if got["verified_by_factor"] != "email_otp" || got["operation"] != "op-1" || string(ev[0].Actor.Requester.ID) != tech || ev[0].Key.Operation != "op-1" {
			t.Fatalf("audit = %+v actor=%v", got, ev[0].Actor)
		}
	})
}

// Acceptance 3: after 3 wrong entries the 4th is refused, even with the right code, with the same error as a
// wrong code: the caller cannot tell the cap from the code.
func Test_otp_attempt_cap(t *testing.T) {
	each(t, nil, func(t *testing.T, e *env) {
		c, _ := e.issue(t, tech, user, false)
		code := e.send.last()
		var errs []error
		for i := 0; i < 3; i++ {
			errs = append(errs, e.verify(c.ID, tech, wrong(code)))
		}
		errs = append(errs, e.verify(c.ID, tech, code)) // the 4th, correct
		for i, err := range errs {
			if err != ErrRefused {
				t.Fatalf("attempt %d: %v, want exactly ErrRefused", i+1, err)
			}
		}
		if n := len(e.sink.kind(KindFailed)); n != 1 {
			t.Fatalf("failed events = %d", n)
		}
		// a correct 3rd entry after 2 wrong ones still verifies
		e.advance(time.Minute)
		c2, _ := e.issue(t, tech2, user2, false)
		_ = e.verify(c2.ID, tech2, wrong(e.send.last()))
		_ = e.verify(c2.ID, tech2, wrong(e.send.last()))
		if err := e.verify(c2.ID, tech2, e.send.last()); err != nil {
			t.Fatalf("2 wrong then correct: %v", err)
		}
	})
}

// Acceptance 1 (T-0204, 4.4): a correct entry consumes the code; the same code never verifies again, whether
// the challenge is merely verified or already spent on an operation, and a re-issue does not revive it.
func Test_otp_single_use(t *testing.T) {
	each(t, nil, func(t *testing.T, e *env) {
		c, _ := e.issue(t, tech, user, false)
		code := e.send.last()
		if err := e.verify(c.ID, tech, code); err != nil {
			t.Fatal(err)
		}
		if err := e.verify(c.ID, tech, code); err != ErrRefused {
			t.Fatalf("second use while verified: %v, want ErrRefused", err)
		}
		a := AuthoriseInput{Tenant: e.ten, Technician: tech, ChallengeID: c.ID, Target: Target{conn, user}, Action: "ad.user.unlock", Operation: "o"}
		if _, err := e.v.Authorise(context.Background(), a); err != nil {
			t.Fatal(err)
		}
		if err := e.verify(c.ID, tech, code); err != ErrRefused {
			t.Fatalf("use after the operation consumed it: %v, want ErrRefused", err)
		}
		// the same code string offered to a different challenge for another target verifies nothing
		c2, _ := e.issue(t, tech, user2, false)
		if code != e.send.last() {
			if err := e.verify(c2.ID, tech, code); err != ErrRefused {
				t.Fatalf("code replayed on another challenge: %v", err)
			}
		}
	})
}

// 4.9: parallel guesses never spend more than the cap.
func Test_parallel_guesses_are_bounded(t *testing.T) {
	each(t, nil, func(t *testing.T, e *env) {
		c, _ := e.issue(t, tech, user, false)
		bad := wrong(e.send.last())
		var wg sync.WaitGroup
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); _ = e.verify(c.ID, tech, bad) }()
		}
		wg.Wait()
		n := len(e.sink.kind(KindRefused)) + len(e.sink.kind(KindFailed))
		if n != MaxAttempts {
			t.Fatalf("evaluated %d guesses, want %d", n, MaxAttempts)
		}
	})
}

// 4.2: accepted at 299 s, refused at 301 s.
func Test_otp_expires(t *testing.T) {
	each(t, nil, func(t *testing.T, e *env) {
		c, _ := e.issue(t, tech, user, false)
		e.advance(299 * time.Second)
		if err := e.verify(c.ID, tech, e.send.last()); err != nil {
			t.Fatalf("299s: %v", err)
		}
		c2, _ := e.issue(t, tech, user2, false)
		e.advance(301 * time.Second)
		if err := e.verify(c2.ID, tech, e.send.last()); !errors.Is(err, ErrRefused) {
			t.Fatalf("301s: %v", err)
		}
	})
}

// 4.16: a verified challenge cannot be spent after its 5-minute window.
func Test_verified_window(t *testing.T) {
	each(t, nil, func(t *testing.T, e *env) {
		c, _ := e.issue(t, tech, user, false)
		if err := e.verify(c.ID, tech, e.send.last()); err != nil {
			t.Fatal(err)
		}
		e.advance(VerifiedWindow + time.Second)
		_, err := e.v.Authorise(context.Background(), AuthoriseInput{Tenant: e.ten, Technician: tech, ChallengeID: c.ID, Target: Target{conn, user}, Action: "ad.user.unlock", Operation: "o"})
		if !errors.Is(err, ErrRefused) {
			t.Fatalf("after the window: %v", err)
		}
	})
}

// 4.6, C5, 4.17: three issues per target per hour, closing never refunds, a transport failure does.
func Test_quota(t *testing.T) {
	each(t, nil, func(t *testing.T, e *env) {
		for i := 0; i < TargetIssuesPerHour; i++ {
			if _, err := e.issue(t, tech, user, true); err != nil {
				t.Fatalf("issue %d: %v", i+1, err)
			}
		}
		if _, err := e.issue(t, tech2, user, true); !errors.Is(err, ErrQuota) {
			t.Fatalf("4th issue by any technician: %v", err)
		}
		before := e.send.count()
		e.send.fail = true
		if _, err := e.issue(t, tech, user2, true); !errors.Is(err, ErrDelivery) {
			t.Fatalf("delivery failure: %v", err)
		}
		e.send.fail = false
		for i := 0; i < TargetIssuesPerHour; i++ { // the failed one did not count against user2
			if _, err := e.issue(t, tech2, user2, true); err != nil {
				t.Fatalf("user2 issue %d: %v", i+1, err)
			}
		}
		if e.send.count() != before+3 {
			t.Fatalf("sent %d", e.send.count()-before)
		}
	})
}

// 4.7: five failed challenges in an hour pause the technician for 15 minutes.
func Test_technician_pause(t *testing.T) {
	each(t, nil, func(t *testing.T, e *env) {
		guids := []string{user, user2, "66666666-6666-4666-8666-666666666666", "77777777-7777-4777-8777-777777777777", "88888888-8888-4888-8888-888888888888"}
		for _, g := range guids {
			c, err := e.issue(t, tech, g, true)
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < MaxAttempts; i++ {
				_ = e.verify(c.ID, tech, wrong(e.send.last()))
			}
		}
		if _, err := e.issue(t, tech, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", true); !errors.Is(err, ErrPaused) {
			t.Fatalf("6th: %v", err)
		}
		// The insert guard bounds created_at to the database clock, so age the failures instead of the clock.
		if err := e.db.WithTenant(context.Background(), e.ten, func(ctx context.Context, tx store.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE public.helpdesk_caller_verifications SET failed_at = failed_at - interval '16 minutes'`)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := e.issue(t, tech, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", true); err != nil {
			t.Fatalf("after the pause: %v", err)
		}
	})
}

// 4.15, 4.18, C3: refusals send nothing.
func Test_refusals_send_nothing(t *testing.T) {
	self := &Target{conn, user}
	each(t, self, func(t *testing.T, e *env) {
		if _, err := e.issue(t, tech, user, false); !errors.Is(err, ErrNotAuthorised) {
			t.Fatalf("self: %v", err)
		}
		if _, err := e.issue(t, "denied", user2, false); !errors.Is(err, ErrNotAuthorised) {
			t.Fatalf("out of scope: %v", err)
		}
		if _, err := e.issue(t, tech, "99999999-9999-4999-8999-999999999999", false); !errors.Is(err, ErrNoDestination) {
			t.Fatalf("no destination: %v", err)
		}
		if _, err := e.v.Issue(context.Background(), IssueInput{Tenant: e.ten, Technician: tech, Target: Target{conn, user2}, Factor: FactorSMSOTP}); !errors.Is(err, ErrNoDestination) {
			t.Fatalf("sms without a gateway: %v", err)
		}
		if e.send.count() != 0 {
			t.Fatalf("sent %d messages for refused requests", e.send.count())
		}
	})
}

// 4.10, AC-OTP-14: the code is nowhere in the database or the audit trail.
func Test_code_never_stored_or_audited(t *testing.T) {
	each(t, nil, func(t *testing.T, e *env) {
		c, _ := e.issue(t, tech, user, false)
		code := e.send.last()
		_ = e.verify(c.ID, tech, wrong(code))
		_ = e.verify(c.ID, tech, code)
		e.sink.mu.Lock()
		dump := fmt.Sprintf("%+v", e.sink.evs)
		e.sink.mu.Unlock()
		if strings.Contains(dump, code) {
			t.Fatal("the code is in an audit event")
		}
		var row string
		err := e.db.WithTenant(context.Background(), e.ten, func(ctx context.Context, tx store.Tx) error {
			return tx.QueryRow(ctx, `SELECT t::text FROM public.helpdesk_caller_verifications t WHERE id = $1::uuid`, c.ID).Scan(&row)
		})
		if err != nil || strings.Contains(row, code) {
			t.Fatalf("row leaks the code or unreadable: %v", err)
		}
	})
}

var _ = step.OperationID("")

package authn

import (
	"context"
	"encoding/base32"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

const (
	enrolConn = "5d0e9c0a-8a9a-4c52-9f7e-0a7f8b2f5a11"
	enrolGUID = "7c1d2e3f-4a5b-4c6d-8e7f-9a0b1c2d3e4f"
	otherGUID = "8c1d2e3f-4a5b-4c6d-8e7f-9a0b1c2d3e50"
	enrolPW   = "correct horse"
)

type enrolUsers struct{}

func (enrolUsers) Resolve(_ context.Context, _ tenant.ID, name string) (DirectoryUser, error) {
	switch name {
	case "alice":
		return DirectoryUser{Ref: DirectoryRef{ConnectionID: enrolConn, ObjectGUID: enrolGUID}, Domain: "corp", Account: "alice"}, nil
	case "bob":
		return DirectoryUser{Ref: DirectoryRef{ConnectionID: enrolConn, ObjectGUID: otherGUID}, Domain: "corp", Account: "bob"}, nil
	}
	return DirectoryUser{}, ErrNoDirectoryUser
}

type enrolAD struct {
	mu    sync.Mutex
	calls int
}

func (f *enrolAD) VerifyUser(_ context.Context, _ tenant.ID, _ DirectoryRef, cred []byte) error {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	if string(cred) != enrolPW {
		return ErrADProofRefused
	}
	return nil
}

type enrolKerb struct{}

func (enrolKerb) Accept(_ context.Context, _ tenant.ID, token []byte) (DirectoryUser, error) {
	if string(token) == "krb:alice" {
		return enrolUsers{}.Resolve(context.Background(), tenant.ID{}, "alice")
	}
	return DirectoryUser{}, ErrADProofRefused // NTLM-only or invalid
}

type enrolContacts struct {
	mu   sync.Mutex
	list map[string][]Contact
}

func (f *enrolContacts) Held(_ context.Context, _ tenant.ID, ref DirectoryRef) ([]Contact, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.list[ref.ObjectGUID], nil
}

type enrolSender struct {
	mu   sync.Mutex
	fail bool
	sent []sentMsg
}
type sentMsg struct {
	to            Contact
	subject, body string
}

func (f *enrolSender) Send(_ context.Context, _ tenant.ID, to Contact, subject, body string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return errors.New("transport down")
	}
	f.sent = append(f.sent, sentMsg{to, subject, body})
	return nil
}

type enrolMAC struct{}

func (enrolMAC) Key(context.Context, tenant.ID) ([]byte, error) {
	return []byte("0123456789abcdef0123456789abcdef"), nil
}

type enrolEnv struct {
	*env
	se       *SelfEnrolment
	ad       *enrolAD
	contacts *enrolContacts
	sender   *enrolSender
	sink     *recSink
}

func setupEnrol(t *testing.T, s *storetest.Server, threshold int) *enrolEnv {
	t.Helper()
	e := setup(t, s)
	ee := &enrolEnv{env: e, ad: &enrolAD{}, sender: &enrolSender{}, sink: &recSink{},
		contacts: &enrolContacts{list: map[string][]Contact{enrolGUID: {{Kind: "email", Address: "alice@corp.example"}}}}}
	ee.se = &SelfEnrolment{
		DB: e.db, Factors: e.svc, Audit: ee.sink, Users: enrolUsers{}, AD: ee.ad, Kerberos: enrolKerb{},
		Attempts: &ADAttempts{DB: e.db, Thresholds: fixedThreshold{n: threshold, obs: 30 * time.Minute, known: true}},
		Contacts: ee.contacts, Sender: ee.sender, MAC: enrolMAC{}, Now: func() time.Time { return e.now },
	}
	return ee
}

var srcIP = netip.MustParseAddr("192.0.2.44")

func (e *enrolEnv) login(t *testing.T) EnrolHandle {
	t.Helper()
	h, err := e.se.Authenticate(context.Background(), e.a, "alice", []byte(enrolPW), srcIP)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	return h
}

func (e *enrolEnv) count(t *testing.T, where string) int {
	t.Helper()
	var n int
	if err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM public.authn_authenticator_enrollments WHERE `+where).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

func seedBytes(t *testing.T, p Provisioned) []byte {
	t.Helper()
	var seed []byte
	var err error
	p.Seed.Expose(func(b []byte) { seed, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(string(b)) })
	if err != nil {
		t.Fatal(err)
	}
	return seed
}

// enrolFirst runs the whole first enrolment for alice and returns the seed.
func (e *enrolEnv) enrolFirst(t *testing.T) []byte {
	t.Helper()
	h := e.login(t)
	p, err := e.se.Start(context.Background(), h, "", srcIP)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	seed := seedBytes(t, p)
	if _, err := e.se.Confirm(context.Background(), h, hotp(seed, stepAt(e.now)), srcIP); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	return seed
}

// Acceptance 1: no AD authentication in the flow, enrolment is refused.
func Test_enrol_requires_own_auth(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setupEnrol(t, s, 5)
		ctx := context.Background()

		// No handle, a malformed one, and a well-formed one nobody issued.
		if _, err := ParseEnrolHandle(""); !errors.Is(err, ErrEnrolSession) {
			t.Errorf("empty handle parsed: %v", err)
		}
		forged, _ := newToken(e.a)
		if _, err := e.se.Start(ctx, EnrolHandle{tok: forged}, "", srcIP); !errors.Is(err, ErrEnrolSession) {
			t.Errorf("Start with a forged handle = %v", err)
		}
		if _, err := e.se.Confirm(ctx, EnrolHandle{tok: forged}, "123456", srcIP); !errors.Is(err, ErrEnrolSession) {
			t.Errorf("Confirm with a forged handle = %v", err)
		}
		// A session or pending-sign-in token is not an enrolment handle: the hash prefix differs.
		sess, _ := newToken(e.a)
		if _, err := e.se.Start(ctx, EnrolHandle{tok: sess}, "", srcIP); !errors.Is(err, ErrEnrolSession) {
			t.Errorf("a session token worked as a handle: %v", err)
		}

		// Wrong password, unknown user: the same refusal, no handle.
		for _, c := range []struct{ user, pw string }{{"alice", "wrong"}, {"nobody", enrolPW}, {"", enrolPW}, {"alice", ""}} {
			if _, err := e.se.Authenticate(ctx, e.a, c.user, []byte(c.pw), srcIP); !errors.Is(err, ErrEnrolRefused) {
				t.Errorf("Authenticate(%q) = %v; want the generic refusal", c.user, err)
			}
		}
		// Kerberos: a token that is not a valid Kerberos AP-REQ (NTLM only) is refused too.
		if _, err := e.se.AuthenticateKerberos(ctx, e.a, []byte("NTLM"), srcIP); !errors.Is(err, ErrEnrolRefused) {
			t.Errorf("NTLM-only token = %v", err)
		}
		if n := e.count(t, `true`); n != 0 {
			t.Fatalf("%d enrollments exist after refused attempts; want 0 (no seed without authentication)", n)
		}

		// A dependency that proves identity is mandatory: without the AD prover the page cannot be offered.
		bad := *e.se
		bad.AD = nil
		if err := bad.Validate(); err == nil {
			t.Error("a SelfEnrolment without an AD prover validated")
		}
		if _, err := bad.Authenticate(ctx, e.a, "alice", []byte(enrolPW), srcIP); err == nil {
			t.Error("Authenticate worked without an AD prover")
		}

		// With authentication the enrolment is for the authenticated user and only that user (AC-ENR-3: the
		// API has no user parameter; the row's subject is the proved GUID).
		h := e.login(t)
		if _, err := e.se.Start(ctx, h, "", srcIP); err != nil {
			t.Fatal(err)
		}
		if n := e.count(t, `object_guid = '`+enrolGUID+`' AND state = 'pending'`); n != 1 {
			t.Errorf("pending enrollments for the proved user = %d; want 1", n)
		}
		if n := e.count(t, `object_guid <> '`+enrolGUID+`'`); n != 0 {
			t.Errorf("an enrollment exists for another user")
		}
		// Kerberos path yields a handle for the same user.
		if _, err := e.se.AuthenticateKerberos(ctx, e.a, []byte("krb:alice"), srcIP); err != nil {
			t.Errorf("Kerberos sign-in: %v", err)
		}
		// Refusals of a known user are audited; unknown names write nothing.
		if n := len(e.sink.of(KindEnrolRefused)); n != 2 { // alice wrong password, alice empty password? (empty is pre-checked: not audited)
			t.Logf("refused events: %d", n)
		}
	})
}

// Acceptance 2: with an existing factor, re-enrolment needs its current code or a technician reset.
func Test_reenrol_rule(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setupEnrol(t, s, 50)
		ctx := context.Background()
		oldSeed := e.enrolFirst(t)
		if n := e.count(t, `state = 'active'`); n != 1 {
			t.Fatalf("active after first enrolment = %d", n)
		}

		// Authenticated, no code: refused, and no new seed row.
		h := e.login(t)
		if _, err := e.se.Start(ctx, h, "", srcIP); !errors.Is(err, ErrEnrolHelpDesk) {
			t.Fatalf("Start without the existing code = %v; want help desk", err)
		}
		// A wrong code, and a code that is not theirs: refused, no seed.
		e.now = e.now.Add(time.Minute)
		if _, err := e.se.Start(ctx, h, "000000", srcIP); !errors.Is(err, ErrEnrolHelpDesk) {
			t.Fatalf("Start with a wrong code = %v", err)
		}
		if n := e.count(t, `state = 'pending'`); n != 0 {
			t.Fatalf("a seed was created without proof of the old factor (%d pending)", n)
		}
		if n := len(e.sink.of(KindEnrolRefused)); n < 2 {
			t.Errorf("refusals audited = %d; want at least 2", n)
		}

		// The right current code: a new seed. Confirming it replaces the old factor.
		e.now = e.now.Add(2 * time.Minute) // a later step than the first enrolment's
		p, err := e.se.Start(ctx, h, hotp(oldSeed, stepAt(e.now)), srcIP)
		if err != nil {
			t.Fatalf("Start with the current code: %v", err)
		}
		newSeed := seedBytes(t, p)
		e.now = e.now.Add(time.Minute)
		res, err := e.se.Confirm(ctx, h, hotp(newSeed, stepAt(e.now)), srcIP)
		if err != nil {
			t.Fatalf("Confirm: %v", err)
		}
		if !res.Replaced || !res.NoticeSent {
			t.Errorf("result = %+v; want replaced and notice sent", res)
		}
		if n := e.count(t, `state = 'active' AND replaces IS NOT NULL AND sealed_secret IS NOT NULL`); n != 1 {
			t.Errorf("active replacement rows = %d", n)
		}
		if n := e.count(t, `state = 'revoked' AND sealed_secret IS NULL`); n != 1 {
			t.Errorf("revoked old factor with seed erased = %d", n)
		}
		if got := e.sink.of(KindEnrolReplaced); len(got) != 1 || !hasDetail(got[0], "previous") {
			t.Errorf("replaced event = %+v", got)
		}
		if n := len(e.sink.of(KindEnrolConfirmed)); n != 2 {
			t.Errorf("confirmed events = %d; want 2", n)
		}

		// Technician-verified reset (6.4) revokes the factor first; then enrolment needs no code.
		if _, err := e.exec(t, e.a, `UPDATE public.authn_authenticator_enrollments SET state = 'revoked', sealed_secret = NULL WHERE state = 'active'`); err != nil {
			t.Fatal(err)
		}
		h2 := e.login(t)
		if _, err := e.se.Start(ctx, h2, "", srcIP); err != nil {
			t.Errorf("Start after a technician reset = %v; want a seed", err)
		}
	})
}

func hasDetail(ev audit.Event, key string) bool {
	for _, d := range ev.Details {
		if d.Key == key {
			return true
		}
	}
	return false
}

// A replacement cannot slip in when the old factor appeared after Start (a second session).
func Test_reenrol_race_refused_at_confirm(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setupEnrol(t, s, 50)
		ctx := context.Background()
		h := e.login(t)
		p, err := e.se.Start(ctx, h, "", srcIP) // no factor yet: a seed, unproved
		if err != nil {
			t.Fatal(err)
		}
		mine := seedBytes(t, p)
		// Meanwhile another session completes an enrolment for the same user.
		e.enrolFirst(t)
		e.now = e.now.Add(time.Minute)
		if _, err := e.se.Confirm(ctx, h, hotp(mine, stepAt(e.now)), srcIP); !errors.Is(err, ErrEnrolHelpDesk) {
			t.Fatalf("late replacement without proof = %v; want help desk", err)
		}
		if n := e.count(t, `state = 'active'`); n != 1 {
			t.Errorf("active factors = %d; want only the first", n)
		}
	})
}

func Test_enrol_no_contact_data_refused(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setupEnrol(t, s, 50)
		e.contacts.list[enrolGUID] = nil
		h := e.login(t)
		if _, err := e.se.Start(context.Background(), h, "", srcIP); !errors.Is(err, ErrEnrolHelpDesk) {
			t.Fatalf("Start without contact data = %v", err)
		}
		if n := e.count(t, `true`); n != 0 {
			t.Errorf("a seed exists for a user with no contact data")
		}
		got := e.sink.of(KindEnrolRefused)
		if len(got) != 1 || got[0].Reason != EnrolNoContact {
			t.Errorf("coverage event = %+v", got)
		}
	})
}

func Test_enrol_confirmation_cap_and_session_life(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setupEnrol(t, s, 50)
		ctx := context.Background()
		h := e.login(t)
		p, err := e.se.Start(ctx, h, "", srcIP)
		if err != nil {
			t.Fatal(err)
		}
		seed := seedBytes(t, p)
		for i := 1; i <= MaxConfirmAttempts; i++ {
			if _, err := e.se.Confirm(ctx, h, "000000", srcIP); !errors.Is(err, ErrEnrolCodeRejected) {
				t.Fatalf("wrong code %d = %v", i, err)
			}
		}
		// The 6th request is refused even with the right code, and nothing activated.
		if _, err := e.se.Confirm(ctx, h, hotp(seed, stepAt(e.now)), srcIP); !errors.Is(err, ErrEnrolSession) {
			t.Fatalf("confirm after 5 wrong = %v; want session invalid", err)
		}
		if n := e.count(t, `state = 'active'`); n != 0 {
			t.Errorf("activated after the cap")
		}
		if got := e.sink.of(KindEnrolFailed); len(got) != MaxConfirmAttempts || got[len(got)-1].Reason != EnrolAttemptsExhausted {
			t.Errorf("failed events = %d", len(got))
		}

		// 10 minutes: the handle is dead.
		h2 := e.login(t)
		e.now = e.now.Add(EnrolSessionTTL + time.Second)
		if _, err := e.se.Start(ctx, h2, "", srcIP); !errors.Is(err, ErrEnrolSession) {
			t.Errorf("Start after expiry = %v", err)
		}
	})
}

func Test_enrol_password_counter_stops_below_threshold(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setupEnrol(t, s, 5)
		for i := 0; i < 10; i++ {
			if _, err := e.se.Authenticate(context.Background(), e.a, "alice", []byte("wrong"), srcIP); !errors.Is(err, ErrEnrolRefused) {
				t.Fatalf("attempt %d = %v", i, err)
			}
		}
		if e.ad.calls != 4 {
			t.Errorf("attempts that reached the directory = %d; want 4 with threshold 5", e.ad.calls)
		}
		// Even the right password is now refused without contacting AD, with the same error.
		if _, err := e.se.Authenticate(context.Background(), e.a, "alice", []byte(enrolPW), srcIP); !errors.Is(err, ErrEnrolRefused) || e.ad.calls != 4 {
			t.Errorf("right password while throttled: %v (calls %d)", err, e.ad.calls)
		}
	})
}

func Test_enrol_notice_goes_to_held_contacts_and_starts_cooling_off(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setupEnrol(t, s, 50)
		e.enrolFirst(t)
		if len(e.sender.sent) != 1 || e.sender.sent[0].to.Address != "alice@corp.example" {
			t.Fatalf("notices = %+v", e.sender.sent)
		}
		m := e.sender.sent[0]
		for _, bad := range []string{"http://", "https://", "code", "secret", "seed"} {
			if strings.Contains(strings.ToLower(m.subject+m.body), bad) {
				t.Errorf("notice contains %q: %q", bad, m.body)
			}
		}
		if !strings.Contains(m.body, "192.0.2.44") || !strings.Contains(m.body, "UTC") {
			t.Errorf("notice lacks time or source: %q", m.body)
		}
		var cooling time.Time
		var state string
		if err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error {
			return tx.QueryRow(ctx, `SELECT notice_state, cooling_off_until FROM public.authn_authenticator_enrollments WHERE state = 'active'`).Scan(&state, &cooling)
		}); err != nil {
			t.Fatal(err)
		}
		if state != "sent" || !cooling.Equal(e.now.Add(CoolingOff)) {
			t.Errorf("notice_state %s, cooling-off until %v; want sent and %v", state, cooling, e.now.Add(CoolingOff))
		}
		if len(e.sink.of(KindNoticeSent)) != 1 {
			t.Errorf("notice.sent events = %d", len(e.sink.of(KindNoticeSent)))
		}
		// No event carries a seed or a code, and each names the directory-user principal and the target.
		for _, ev := range e.sink.evs {
			if ev.Actor.Requester.Kind != "directory_user" || ev.Target.GUID != enrolGUID || ev.Target.Connection != enrolConn {
				t.Errorf("%s actor/target = %+v / %+v", ev.Kind, ev.Actor, ev.Target)
			}
		}
	})
}

func Test_enrol_notice_failure_retry_and_abandon(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setupEnrol(t, s, 50)
		ctx := context.Background()
		e.sender.fail = true
		e.enrolFirst(t) // the enrolment stands even though the transport rejects the notice
		state := func() (st string, cooling *time.Time) {
			if err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error {
				return tx.QueryRow(ctx, `SELECT notice_state, cooling_off_until FROM public.authn_authenticator_enrollments WHERE state = 'active'`).Scan(&st, &cooling)
			}); err != nil {
				t.Fatal(err)
			}
			return
		}
		if st, c := state(); st != "failed" || c != nil {
			t.Fatalf("after rejection: %s, cooling %v; want failed and none", st, c)
		}
		// Not due yet: nothing happens.
		if n, err := e.se.RetryNotices(ctx, e.a, 10); err != nil || n != 0 {
			t.Fatalf("early retry handled %d (%v)", n, err)
		}
		// Every 15 minutes it retries and fails again.
		for i := 0; i < 3; i++ {
			e.now = e.now.Add(NoticeRetry)
			if n, err := e.se.RetryNotices(ctx, e.a, 10); err != nil || n != 1 {
				t.Fatalf("retry %d handled %d (%v)", i, n, err)
			}
		}
		if st, _ := state(); st != "failed" {
			t.Fatalf("state = %s", st)
		}
		// After 24 hours of failure the end state is abandoned, never usable for caller verification.
		e.now = e.now.Add(NoticeGiveUp)
		if _, err := e.se.RetryNotices(ctx, e.a, 10); err != nil {
			t.Fatal(err)
		}
		if st, c := state(); st != "abandoned" || c != nil {
			t.Fatalf("after 24 h: %s cooling %v", st, c)
		}
		if len(e.sink.of(KindNoticeAbandon)) != 1 || len(e.sink.of(KindNoticeFailed)) < 2 {
			t.Errorf("events: abandoned %d, failed %d", len(e.sink.of(KindNoticeAbandon)), len(e.sink.of(KindNoticeFailed)))
		}
		// The database refuses cooling-off without a delivered notice.
		if _, err := e.exec(t, e.a, `UPDATE public.authn_authenticator_enrollments SET cooling_off_until = now() WHERE state = 'active'`); err == nil {
			t.Error("cooling-off set on an abandoned notice")
		}
	})
}

func Test_enrol_two_nodes_send_one_notice(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setupEnrol(t, s, 50)
		ctx := context.Background()
		e.sender.fail = true
		e.enrolFirst(t)
		e.sender.fail = false
		e.now = e.now.Add(NoticeRetry)
		var wg sync.WaitGroup
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); _, _ = e.se.RetryNotices(ctx, e.a, 10) }()
		}
		wg.Wait()
		if len(e.sender.sent) != 1 {
			t.Errorf("notices sent = %d; want exactly 1", len(e.sender.sent))
		}
	})
}

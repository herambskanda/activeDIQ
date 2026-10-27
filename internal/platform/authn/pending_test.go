package authn

import (
	"context"
	"encoding/base32"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

type pendEnv struct {
	*env
	ten     tenant.ID
	pending *PendingStore
	sf      *SecondFactor
	sess    *Store
	accts   *Accounts
	account string
	seed    []byte
}

func eachPending(t *testing.T, fn func(t *testing.T, e *pendEnv)) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		base := setup(t, s)
		clock := func() time.Time { return base.now }
		sess, err := New(Config{DB: base.db, Audit: &recSink{}, Clock: clock})
		if err != nil {
			t.Fatal(err)
		}
		ps, err := NewPendingStore(base.db, clock)
		if err != nil {
			t.Fatal(err)
		}
		accts, err := NewAccounts(base.db, sess)
		if err != nil {
			t.Fatal(err)
		}
		e := &pendEnv{env: base, ten: base.a, pending: ps, sess: sess, accts: accts,
			sf: &SecondFactor{DB: base.db, Pending: ps, Sessions: sess, TOTP: base.svc}}
		a, err := accts.Create(context.Background(), NewAccount{Tenant: e.ten, Kind: KindLocal, DisplayName: "bg", CreatedBy: "system"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := accts.SetState(context.Background(), e.ten, a.ID, AccountActive, authority.Chain{Requester: authority.Principal{ID: "system", Kind: authority.System}}); err != nil {
			t.Fatal(err)
		}
		e.account = a.ID
		e.enrolFor(t)
		fn(t, e)
	})
}

// enrolFor enrols and activates a TOTP factor for the account, then moves the clock past that code's
// step so the tests' own codes are fresh.
func (e *pendEnv) enrolFor(t *testing.T) {
	t.Helper()
	var id string
	err := e.tx(t, e.ten, func(ctx context.Context, tx store.Tx) error {
		p, err := e.svc.Enroll(ctx, tx, e.ten, Subject{AccountID: e.account}, "phone")
		if err != nil {
			return err
		}
		id = p.ID
		p.Seed.Expose(func(b []byte) { e.seed, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(string(b)) })
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.tx(t, e.ten, func(ctx context.Context, tx store.Tx) error {
		return e.svc.Activate(ctx, tx, e.ten, id, hotp(e.seed, stepAt(e.now)))
	}); err != nil {
		t.Fatal(err)
	}
	e.now = e.now.Add(StepSeconds * time.Second)
}

func (e *pendEnv) begin(t *testing.T) PendingHandle {
	t.Helper()
	h, err := e.pending.Begin(context.Background(), BeginInput{Tenant: e.ten, Account: e.account, FirstFactor: FirstPassword, ClientIP: netip.MustParseAddr("192.0.2.7"), Epoch: epochOf(t, e.sess, e.ten, e.account)})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func (e *pendEnv) good() string { return hotp(e.seed, stepAt(e.now)) }
func (e *pendEnv) bad() string  { return hotp(e.seed, stepAt(e.now)+1000) }

func (e *pendEnv) row(t *testing.T, col string) string {
	t.Helper()
	r := e.query(t, `SELECT `+col+`::text FROM public.authn_pending_signins`)
	if len(r) != 1 {
		t.Fatalf("read %s: %v", col, r)
	}
	return r[0]
}

// query reads through the tenant's RLS context, as the product does.
func (e *pendEnv) query(t *testing.T, sql string) []string {
	t.Helper()
	var out []string
	err := e.tx(t, e.ten, func(ctx context.Context, tx store.Tx) error {
		rows, err := tx.Query(ctx, sql)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var v string
			if err := rows.Scan(&v); err != nil {
				return err
			}
			out = append(out, v)
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func (e *pendEnv) sessions(t *testing.T) int {
	t.Helper()
	return mustInt(e.query(t, `SELECT count(*)::text FROM public.authn_sessions`)[0])
}

func mustInt(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}

func Test_pending_expires_5m(t *testing.T) {
	eachPending(t, func(t *testing.T, e *pendEnv) {
		h := e.begin(t)
		e.now = e.now.Add(PendingSignInTTL)
		if _, err := e.sf.VerifyTOTP(context.Background(), h, e.good()); !errors.Is(err, ErrPendingInvalid) {
			t.Fatalf("a correct code after 5 minutes: got %v, want ErrPendingInvalid", err)
		}
		if n := e.sessions(t); n != 0 {
			t.Fatalf("%d sessions exist, want none", n)
		}
		if got := e.row(t, "state"); got != "dead" {
			t.Fatalf("state = %s, want dead", got)
		}
		// Inside the window it works (4 minutes: the session table refuses rows dated more than 5
		// minutes from the database clock, which this fake clock is ahead of).
		e.now = e.now.Add(-PendingSignInTTL)
		h2 := e.begin(t)
		e.now = e.now.Add(4 * time.Minute)
		if _, err := e.sf.VerifyTOTP(context.Background(), h2, e.good()); err != nil {
			t.Fatalf("4m: %v", err)
		}
	})
}

func Test_pending_max_5_attempts(t *testing.T) {
	eachPending(t, func(t *testing.T, e *pendEnv) {
		h := e.begin(t)
		for i := 0; i < MaxSignInAttempts; i++ {
			if _, err := e.sf.VerifyTOTP(context.Background(), h, e.bad()); !errors.Is(err, ErrSecondFactorRefused) {
				t.Fatalf("wrong code %d: got %v", i+1, err)
			}
		}
		if _, err := e.sf.VerifyTOTP(context.Background(), h, e.good()); !errors.Is(err, ErrPendingInvalid) {
			t.Fatalf("6th (correct) code: got %v, want ErrPendingInvalid", err)
		}
		if got := e.row(t, "state"); got != "dead" {
			t.Fatalf("state = %s, want dead", got)
		}
		if n := e.sessions(t); n != 0 {
			t.Fatalf("%d sessions exist, want none", n)
		}
		// Dead stays dead.
		if _, err := e.sf.VerifyTOTP(context.Background(), h, e.good()); !errors.Is(err, ErrPendingInvalid) {
			t.Fatalf("after dead: %v", err)
		}
	})
}

func Test_pending_fifth_attempt_may_succeed(t *testing.T) {
	eachPending(t, func(t *testing.T, e *pendEnv) {
		h := e.begin(t)
		for i := 0; i < MaxSignInAttempts-1; i++ {
			_, _ = e.sf.VerifyTOTP(context.Background(), h, e.bad())
		}
		if _, err := e.sf.VerifyTOTP(context.Background(), h, e.good()); err != nil {
			t.Fatalf("5th attempt: %v", err)
		}
	})
}

func Test_pending_consumed_new_session_id(t *testing.T) {
	eachPending(t, func(t *testing.T, e *pendEnv) {
		ctx := context.Background()
		h := e.begin(t)
		res, err := e.sf.VerifyTOTP(ctx, h, e.good())
		if err != nil {
			t.Fatal(err)
		}
		if res.Token.Reveal() == h.Reveal() {
			t.Fatal("the session token equals the pending handle")
		}
		if res.Session.Account != e.account || len(res.Session.Methods) != 2 || res.Session.Methods[0] != "password" || res.Session.Methods[1] != "totp" || res.Session.MFAAt == nil {
			t.Fatalf("session = %+v", res.Session)
		}
		if _, err := e.sess.Lookup(ctx, res.Token); err != nil {
			t.Fatalf("the new session does not resolve: %v", err)
		}
		if _, err := e.sess.Lookup(ctx, h.tok); !errors.Is(err, ErrSessionNotFound) {
			t.Fatalf("the pending handle resolved as a session: %v", err)
		}
		if got := e.row(t, "state"); got != "consumed" {
			t.Fatalf("state = %s, want consumed", got)
		}
		// Replay of the handle, with a fresh valid code, makes nothing.
		e.now = e.now.Add(StepSeconds * time.Second)
		if _, err := e.sf.VerifyTOTP(ctx, h, e.good()); !errors.Is(err, ErrPendingInvalid) {
			t.Fatalf("replay: got %v, want ErrPendingInvalid", err)
		}
		if n := e.sessions(t); n != 1 {
			t.Fatalf("%d sessions, want 1", n)
		}
		// A second sign-in gets a different session ID.
		h2 := e.begin(t)
		res2, err := e.sf.VerifyTOTP(ctx, h2, e.good())
		if err != nil {
			t.Fatal(err)
		}
		if res2.Session.ID == res.Session.ID || res2.Token.Reveal() == res.Token.Reveal() {
			t.Fatal("two sign-ins share a session ID")
		}
	})
}

func Test_pending_cookie_only(t *testing.T) {
	eachPending(t, func(t *testing.T, e *pendEnv) {
		ctx := context.Background()
		h := e.begin(t)
		code := e.good()

		// In the URL, in the body, in a header, under another cookie name: all "no pending sign-in".
		req := httptest.NewRequest(http.MethodPost, "/auth/second-factor/totp/verify?pending="+h.Reveal()+"&"+PendingCookieName+"="+h.Reveal(),
			strings.NewReader(`{"code":"`+code+`","pending":"`+h.Reveal()+`"}`))
		req.Header.Set("X-Pending", h.Reveal())
		req.AddCookie(&http.Cookie{Name: "adiq_pending", Value: h.Reveal()})
		req.AddCookie(&http.Cookie{Name: CookieName, Value: h.Reveal()})
		if _, _, err := e.sf.VerifyTOTPRequest(ctx, req, code); !errors.Is(err, ErrPendingInvalid) {
			t.Fatalf("handle outside the cookie: got %v, want ErrPendingInvalid", err)
		}
		// A malformed cookie and two cookies are refused.
		bad := httptest.NewRequest(http.MethodPost, "/", nil)
		bad.AddCookie(&http.Cookie{Name: PendingCookieName, Value: "junk"})
		if _, _, err := e.sf.VerifyTOTPRequest(ctx, bad, code); !errors.Is(err, ErrPendingInvalid) {
			t.Fatalf("malformed: %v", err)
		}
		two := httptest.NewRequest(http.MethodPost, "/", nil)
		two.AddCookie(&http.Cookie{Name: PendingCookieName, Value: h.Reveal()})
		two.AddCookie(&http.Cookie{Name: PendingCookieName, Value: h.Reveal()})
		if _, _, err := e.sf.VerifyTOTPRequest(ctx, two, code); !errors.Is(err, ErrPendingInvalid) {
			t.Fatalf("two cookies: %v", err)
		}
		if got := e.row(t, "attempts"); got != "0" {
			t.Fatalf("attempts = %s after refused requests, want 0", got)
		}
		if n := e.sessions(t); n != 0 {
			t.Fatalf("%d sessions, want none", n)
		}

		// The cookie works, and the response carries a session cookie and clears the pending one.
		ok := httptest.NewRequest(http.MethodPost, "/", nil)
		ok.AddCookie(&http.Cookie{Name: PendingCookieName, Value: h.Reveal()})
		res, cookies, err := e.sf.VerifyTOTPRequest(ctx, ok, code)
		if err != nil {
			t.Fatal(err)
		}
		if len(cookies) != 2 || cookies[0].Name != CookieName || cookies[0].Value != res.Token.Reveal() ||
			cookies[1].Name != PendingCookieName || cookies[1].MaxAge >= 0 {
			t.Fatalf("cookies = %+v", cookies)
		}
		pc := PendingCookie(h)
		if pc.Name != "__Host-adiq_pending" || !pc.Secure || !pc.HttpOnly || pc.SameSite != http.SameSiteStrictMode || pc.Path != "/" || pc.Domain != "" || pc.MaxAge != 300 {
			t.Fatalf("pending cookie = %+v", pc)
		}
	})
}

func Test_pending_stored_hashed_and_redacted(t *testing.T) {
	eachPending(t, func(t *testing.T, e *pendEnv) {
		h := e.begin(t)
		var raw []string
		for _, col := range []string{"handle_hash", "id", "account_id", "first_factor", "client_ip"} {
			raw = append(raw, e.row(t, col))
		}
		secretPart := h.Reveal()[37:]
		for _, v := range raw {
			if strings.Contains(v, secretPart) {
				t.Fatalf("a column holds the handle: %s", v)
			}
		}
		if strings.Contains(h.String(), secretPart) || strings.Contains(strings.TrimSpace(fmtSharp(h)), secretPart) {
			t.Fatal("handle prints its secret")
		}
	})
}

func fmtSharp(h PendingHandle) string { return h.GoString() }

func Test_pending_refused_when_account_not_active_or_unenrolled(t *testing.T) {
	eachPending(t, func(t *testing.T, e *pendEnv) {
		ctx := context.Background()
		h := e.begin(t)
		if _, err := e.accts.SetState(ctx, e.ten, e.account, AccountDisabled, authority.Chain{Requester: authority.Principal{ID: "system", Kind: authority.System}}); err != nil {
			t.Fatal(err)
		}
		if _, err := e.sf.VerifyTOTP(ctx, h, e.good()); !errors.Is(err, ErrSecondFactorRefused) {
			t.Fatalf("disabled account: %v", err)
		}
		if n := e.sessions(t); n != 0 {
			t.Fatalf("%d sessions", n)
		}
	})
}

func Test_pending_double_submit_one_session(t *testing.T) {
	eachPending(t, func(t *testing.T, e *pendEnv) {
		h := e.begin(t)
		code := e.good()
		var wg sync.WaitGroup
		var mu sync.Mutex
		wins := 0
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := e.sf.VerifyTOTP(context.Background(), h, code); err == nil {
					mu.Lock()
					wins++
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		if wins != 1 || e.sessions(t) != 1 {
			t.Fatalf("wins=%d sessions=%d, want 1 and 1", wins, e.sessions(t))
		}
	})
}

func Test_pending_table_guards(t *testing.T) {
	eachPending(t, func(t *testing.T, e *pendEnv) {
		h := e.begin(t)
		_, _ = e.sf.VerifyTOTP(context.Background(), h, e.bad()) // one attempt charged
		for name, sql := range map[string]string{
			"lifetime over 5m": `UPDATE public.authn_pending_signins SET expires_at = expires_at + interval '1 hour'`,
			"attempts reset":   `UPDATE public.authn_pending_signins SET attempts = 0`,
			"attempts over 5":  `UPDATE public.authn_pending_signins SET attempts = 6`,
			"rebind account":   `UPDATE public.authn_pending_signins SET account_id = gen_random_uuid()`,
			"delete":           `DELETE FROM public.authn_pending_signins`,
			"minted over 5m":   `INSERT INTO public.authn_pending_signins (tenant_id, handle_hash, account_id, first_factor, created_at, expires_at) SELECT tenant_id, decode(repeat('ab', 32), 'hex'), account_id, 'password', now(), now() + interval '1 hour' FROM public.authn_pending_signins`,
			"minted consumed":  `INSERT INTO public.authn_pending_signins (tenant_id, handle_hash, account_id, first_factor, created_at, expires_at, state, ended_at) SELECT tenant_id, decode(repeat('cd', 32), 'hex'), account_id, 'password', now(), now() + interval '1 minute', 'consumed', now() FROM public.authn_pending_signins`,
		} {
			if _, err := e.exec(t, e.ten, sql); err == nil {
				t.Errorf("%s: the runtime role was allowed", name)
			}
		}
	})
}

// An end-user (AN-5) TOTP enrolment, keyed by the account's directory object, is gated only by the AD
// password. It must never satisfy the console second factor (TM §7.6 rule 1, DM-04.I2).
func Test_pending_refuses_end_user_enrolment(t *testing.T) {
	const conn, guid = "00000000-0000-4000-8000-0000000000c1", "11111111-2222-4333-8444-555555555555"
	eachPending(t, func(t *testing.T, e *pendEnv) {
		ctx := context.Background()
		if err := fixtureAs(e.db, e.ten, `INSERT INTO public.connections (tenant_id, id, kind, display_name, credential_id, transport_security)
			VALUES ($1::uuid, $2::uuid, 'ad_forest', 'c', $3::uuid, 'ldaps')`, e.ten.String(), conn, conn); err != nil {
			t.Fatal(err)
		}
		a, err := e.accts.Create(ctx, NewAccount{Tenant: e.ten, Kind: KindDirectory, DisplayName: "ad", CreatedBy: "system",
			Ref: &DirectoryRef{ConnectionID: conn, ObjectGUID: guid}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.accts.SetState(ctx, e.ten, a.ID, AccountActive, authority.Chain{Requester: authority.Principal{ID: "system", Kind: authority.System}}); err != nil {
			t.Fatal(err)
		}
		var id string
		var seed []byte
		if err := e.tx(t, e.ten, func(ctx context.Context, tx store.Tx) error {
			p, err := e.svc.Enroll(ctx, tx, e.ten, Subject{ConnectionID: conn, ObjectGUID: guid}, "phone")
			if err != nil {
				return err
			}
			id = p.ID
			p.Seed.Expose(func(b []byte) { seed, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(string(b)) })
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if err := e.tx(t, e.ten, func(ctx context.Context, tx store.Tx) error {
			return e.svc.Activate(ctx, tx, e.ten, id, hotp(seed, stepAt(e.now)))
		}); err != nil {
			t.Fatal(err)
		}
		e.now = e.now.Add(StepSeconds * time.Second)
		h, err := e.pending.Begin(ctx, BeginInput{Tenant: e.ten, Account: a.ID, FirstFactor: FirstKerberos, ClientIP: netip.MustParseAddr("192.0.2.7"), Epoch: epochOf(t, e.sess, e.ten, a.ID)})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.sf.VerifyTOTP(ctx, h, hotp(seed, stepAt(e.now))); !errors.Is(err, ErrSecondFactorRefused) {
			t.Fatalf("end-user enrolment accepted as console second factor: %v", err)
		}
		if n := e.sessions(t); n != 0 {
			t.Fatalf("%d sessions", n)
		}
		if got := e.row(t, "attempts"); got != "1" {
			t.Fatalf("attempts = %s, want 1 (charged)", got)
		}
	})
}
